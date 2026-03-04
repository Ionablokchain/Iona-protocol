#!/usr/bin/env bash
# IONA Soak Test: RPC Load Testing
# Usage: ./deploy/scripts/soak_rpc_load.sh [--duration DURATION] [--rps RPS]
#
# Sends sustained RPC load and measures latency, error rates, and throughput.

set -euo pipefail

DURATION="4h"
RPS=100
RPC_URL="http://127.0.0.1:9000"
LOG_FILE="/tmp/iona_soak/soak_rpc_load.log"
RESULTS_FILE="/tmp/iona_soak/soak_rpc_results.csv"

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration) DURATION="$2"; shift 2 ;;
        --rps) RPS="$2"; shift 2 ;;
        --url) RPC_URL="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

mkdir -p /tmp/iona_soak

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE"; }

duration_to_seconds() {
    local d="$1"
    case "$d" in
        *h) echo $(( ${d%h} * 3600 )) ;;
        *m) echo $(( ${d%m} * 60 )) ;;
        *) echo "$d" ;;
    esac
}

DURATION_S=$(duration_to_seconds "$DURATION")
END_TIME=$(( $(date +%s) + DURATION_S ))

log "=== IONA Soak Test: RPC Load ==="
log "Duration: $DURATION ($DURATION_S seconds)"
log "Target RPS: $RPS"
log "RPC URL: $RPC_URL"

echo "timestamp,endpoint,status,latency_ms" > "$RESULTS_FILE"

HEALTH_REQ="$RPC_URL/health"
STATUS_REQ="$RPC_URL/status"
BLOCK_NUM_REQ='{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

TOTAL=0
ERRORS=0
STATUS_200=0
STATUS_429=0
STATUS_OTHER=0

BATCH=10
BATCH_SLEEP=$(awk "BEGIN{printf \"%.3f\", $BATCH / $RPS}")

while [ $(date +%s) -lt $END_TIME ]; do
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
            *) STATUS_OTHER=$((STATUS_OTHER + 1)) ;;
        esac
    done

    sleep "$BATCH_SLEEP"

    if [ $((TOTAL % 1000)) -eq 0 ]; then
        log "Progress: total=$TOTAL ok=$STATUS_200 rate_limited=$STATUS_429 errors=$ERRORS"
    fi
done

log ""
log "=== Results ==="
log "Total requests: $TOTAL"
log "200 OK: $STATUS_200"
log "429 Rate Limited: $STATUS_429"
log "Errors: $ERRORS"
log "Other: $STATUS_OTHER"

if [ "$TOTAL" -gt 0 ]; then
    SUCCESS_RATE=$(awk "BEGIN{printf \"%.1f\", ($STATUS_200 / $TOTAL) * 100}")
    ERROR_RATE=$(awk "BEGIN{printf \"%.1f\", ($ERRORS / $TOTAL) * 100}")
    log "Success rate: ${SUCCESS_RATE}%"
    log "Error rate: ${ERROR_RATE}%"

    if command -v sort &>/dev/null; then
        LATENCIES=$(tail -n +2 "$RESULTS_FILE" | cut -d, -f4 | sort -n)
        COUNT=$(echo "$LATENCIES" | wc -l)
        P50_IDX=$(( COUNT / 2 ))
        P99_IDX=$(( COUNT * 99 / 100 ))
        P50=$(echo "$LATENCIES" | sed -n "${P50_IDX}p")
        P99=$(echo "$LATENCIES" | sed -n "${P99_IDX}p")
        log "Latency p50: ${P50}ms"
        log "Latency p99: ${P99}ms"
    fi
fi

log ""
if [ "$ERRORS" -gt "$((TOTAL / 20))" ]; then
    log "RESULT: FAIL (error rate > 5%)"
    exit 1
else
    log "RESULT: PASS"
    exit 0
fi
