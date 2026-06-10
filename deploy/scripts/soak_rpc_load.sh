#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Soak Test: RPC Load Testing — Production‑Grade
# =============================================================================
#
# Sends sustained RPC load and measures latency, error rates, and throughput.
#
# Usage:
#   ./soak_rpc_load.sh [OPTIONS]
#
# Options:
#   --duration DURATION   Test duration (e.g. 4h, 30m, 3600s) (default: 4h)
#   --rps RPS             Target requests per second (default: 100)
#   --url URL             RPC endpoint URL (default: http://127.0.0.1:9000)
#   --output-dir DIR      Directory for logs and results (default: /tmp/iona_soak)
#   --json                Output final summary as JSON (for CI/CD)
#   --verbose             Enable detailed output
#   --help                Show this help
#
# Environment variables (fallback):
#   IONA_SOAK_DURATION, IONA_SOAK_RPS, IONA_SOAK_URL, IONA_SOAK_OUTPUT_DIR

# ── Configuration ────────────────────────────────────────────────────────────
DURATION="${IONA_SOAK_DURATION:-4h}"
RPS="${IONA_SOAK_RPS:-100}"
RPC_URL="${IONA_SOAK_URL:-http://127.0.0.1:9000}"
OUTPUT_DIR="${IONA_SOAK_OUTPUT_DIR:-/tmp/iona_soak}"
VERBOSE="${IONA_VERBOSE:-0}"
JSON_OUTPUT=0
START_TIME=$(date +%s)

# ── Colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

# ── Logging ─────────────────────────────────────────────────────────────────
LOG_FILE=""; RESULTS_FILE=""
log_init() {
    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="${OUTPUT_DIR}/soak_rpc_load_$(date +%Y%m%d-%H%M%S).log"
    RESULTS_FILE="${OUTPUT_DIR}/soak_rpc_results.csv"
    exec 3>&1 4>&2
    exec 1> >(tee -a "$LOG_FILE") 2>&1
}

log_info()    { echo -e "${GREEN}[INFO]${NC}  $(date -u +%H:%M:%S) $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $(date -u +%H:%M:%S) $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $(date -u +%H:%M:%S) $*" >&2; }
log_verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $(date -u +%H:%M:%S) $*"; }
die()         { log_error "$*"; exit 1; }

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration)   DURATION="$2"; shift 2 ;;
        --rps)        RPS="$2"; shift 2 ;;
        --url)        RPC_URL="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --json)       JSON_OUTPUT=1; shift ;;
        --verbose)    VERBOSE=1; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Pre-flight checks ──────────────────────────────────────────────────────
log_init
if ! command -v curl &>/dev/null; then die "curl is required but not installed"; fi
if ! command -v python3 &>/dev/null; then die "python3 is required but not installed"; fi
if ! command -v awk &>/dev/null; then die "awk is required but not installed"; fi

# Validate RPC URL
if ! curl -sf --max-time 5 "${RPC_URL}/health" >/dev/null 2>&1; then
    log_warn "RPC health endpoint not reachable at ${RPC_URL}/health — continuing anyway"
fi

# Parse duration
duration_to_seconds() {
    local d="$1"
    case "$d" in
        *h) echo $(( ${d%h} * 3600 )) ;;
        *m) echo $(( ${d%m} * 60 )) ;;
        *s) echo "${d%s}" ;;
        *)   echo "$d" ;;
    esac
}
DURATION_S=$(duration_to_seconds "$DURATION")
if [[ ! "$DURATION_S" =~ ^[0-9]+$ ]] || [[ "$DURATION_S" -lt 10 ]]; then
    die "Invalid duration: $DURATION (minimum 10s)"
fi
if [[ ! "$RPS" =~ ^[0-9]+$ ]] || [[ "$RPS" -lt 1 ]]; then
    die "Invalid RPS: $RPS (minimum 1)"
fi

log_info "=== IONA Soak Test: RPC Load ==="
log_info "Duration: $DURATION (${DURATION_S}s)"
log_info "Target RPS: $RPS"
log_info "RPC URL: $RPC_URL"
log_info "Output dir: $OUTPUT_DIR"
echo ""

# ── Helpers ─────────────────────────────────────────────────────────────────
HEALTH_REQ="$RPC_URL/health"
STATUS_REQ="$RPC_URL/status"
BLOCK_NUM_REQ='{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Initialize results CSV
echo "timestamp,endpoint,status,latency_ms" > "$RESULTS_FILE"

# ── Statistics ──────────────────────────────────────────────────────────────
TOTAL=0; ERRORS=0; STATUS_200=0; STATUS_429=0; STATUS_OTHER=0
BATCH=10
BATCH_SLEEP=$(awk "BEGIN{printf \"%.3f\", $BATCH / $RPS}")
END_TIME=$(( $(date +%s) + DURATION_S ))
NEXT_REPORT=$(( TOTAL + 1000 ))

# ── Cleanup ─────────────────────────────────────────────────────────────────
cleanup() {
    log_info "Test interrupted. Partial results saved to $RESULTS_FILE"
}
trap cleanup EXIT

# ── Main loop ───────────────────────────────────────────────────────────────
while [[ $(date +%s) -lt $END_TIME ]]; do
    for i in $(seq 1 $BATCH); do
        R=$((RANDOM % 3))
        case $R in
            0)
                ENDPOINT="/health"
                RESULT=$(curl -sf -o /dev/null -w "%{http_code},%{time_total}" "$HEALTH_REQ" 2>/dev/null || echo "000,0")
                ;;
            1)
                ENDPOINT="/status"
                RESULT=$(curl -sf -o /dev/null -w "%{http_code},%{time_total}" "$STATUS_REQ" 2>/dev/null || echo "000,0")
                ;;
            2)
                ENDPOINT="/jsonrpc"
                RESULT=$(curl -sf -o /dev/null -w "%{http_code},%{time_total}" \
                    -X POST "$RPC_URL" \
                    -H "Content-Type: application/json" \
                    -d "$BLOCK_NUM_REQ" 2>/dev/null || echo "000,0")
                ;;
        esac

        STATUS=$(echo "$RESULT" | cut -d, -f1)
        LATENCY=$(echo "$RESULT" | cut -d, -f2)
        LATENCY_MS=$(awk "BEGIN{printf \"%.1f\", $LATENCY * 1000}")

        echo "$(date +%s),$ENDPOINT,$STATUS,$LATENCY_MS" >> "$RESULTS_FILE"

        TOTAL=$((TOTAL + 1))
        case "$STATUS" in
            200) STATUS_200=$((STATUS_200 + 1)) ;;
            429) STATUS_429=$((STATUS_429 + 1)) ;;
            000) ERRORS=$((ERRORS + 1)) ;;
            *)   STATUS_OTHER=$((STATUS_OTHER + 1)) ;;
        esac
    done

    sleep "$BATCH_SLEEP"

    # Progress reporting every 1000 requests
    if [[ $TOTAL -ge $NEXT_REPORT ]]; then
        SUCCESS_RATE=$(awk "BEGIN{printf \"%.1f\", ($STATUS_200 / $TOTAL) * 100}")
        log_info "Progress: total=$TOTAL ok=$STATUS_200 rate_limited=$STATUS_429 errors=$ERRORS (${SUCCESS_RATE}% success)"
        NEXT_REPORT=$(( TOTAL + 1000 ))
    fi
done

# ── Compute latency percentiles ────────────────────────────────────────────
compute_percentiles() {
    local file="$1"
    local lines p50_idx p95_idx p99_idx p50 p95 p99
    lines=$(tail -n +2 "$file" | wc -l)
    if [[ $lines -eq 0 ]]; then
        echo "0 0 0"
        return
    fi
    p50_idx=$(( lines / 2 ))
    p95_idx=$(( lines * 95 / 100 ))
    p99_idx=$(( lines * 99 / 100 ))

    local sorted
    sorted=$(tail -n +2 "$file" | cut -d, -f4 | sort -n)
    p50=$(echo "$sorted" | sed -n "${p50_idx}p")
    p95=$(echo "$sorted" | sed -n "${p95_idx}p")
    p99=$(echo "$sorted" | sed -n "${p99_idx}p")
    echo "${p50:-0} ${p95:-0} ${p99:-0}"
}

# ── Summary ─────────────────────────────────────────────────────────────────
DURATION_ACTUAL=$(($(date +%s) - START_TIME))

echo ""
log_info "=== Results ==="
log_info "Total requests:  $TOTAL"
log_info "200 OK:          $STATUS_200"
log_info "429 Rate Limited: $STATUS_429"
log_info "Errors:          $ERRORS"
log_info "Other:           $STATUS_OTHER"

if [[ "$TOTAL" -gt 0 ]]; then
    SUCCESS_RATE=$(awk "BEGIN{printf \"%.2f\", ($STATUS_200 / $TOTAL) * 100}")
    ERROR_RATE=$(awk "BEGIN{printf \"%.2f\", ($ERRORS / $TOTAL) * 100}")
    log_info "Success rate:    ${SUCCESS_RATE}%"
    log_info "Error rate:      ${ERROR_RATE}%"

    read -r P50 P95 P99 <<< "$(compute_percentiles "$RESULTS_FILE")"
    log_info "Latency p50:     ${P50}ms"
    log_info "Latency p95:     ${P95}ms"
    log_info "Latency p99:     ${P99}ms"
    log_info "Throughput:      $(awk "BEGIN{printf \"%.1f\", $TOTAL / $DURATION_ACTUAL}") req/s"
fi

echo ""
if [[ "$ERRORS" -gt "$((TOTAL / 20))" ]]; then
    log_error "RESULT: FAIL (error rate > 5%)"
    STATUS="FAIL"
else
    log_info "RESULT: PASS"
    STATUS="PASS"
fi

# ── JSON output ─────────────────────────────────────────────────────────────
if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    jq -n \
        --arg status "$STATUS" \
        --argjson total "$TOTAL" \
        --argjson ok "$STATUS_200" \
        --argjson rate_limited "$STATUS_429" \
        --argjson errors "$ERRORS" \
        --argjson duration "$DURATION_ACTUAL" \
        --arg success_rate "${SUCCESS_RATE:-0}" \
        --arg p50 "${P50:-0}" \
        --arg p95 "${P95:-0}" \
        --arg p99 "${P99:-0}" \
        --arg log_file "$LOG_FILE" \
        --arg results_file "$RESULTS_FILE" \
        --arg timestamp "$(date -Iseconds)" \
        '{
            status: $status,
            total_requests: $total,
            ok: $ok,
            rate_limited: $rate_limited,
            errors: $errors,
            duration_s: $duration,
            success_rate_pct: $success_rate,
            latency_p50_ms: $p50,
            latency_p95_ms: $p95,
            latency_p99_ms: $p99,
            log_file: $log_file,
            results_file: $results_file,
            timestamp: $timestamp
        }'
fi

[[ "$STATUS" == "PASS" ]] && exit 0 || exit 1
