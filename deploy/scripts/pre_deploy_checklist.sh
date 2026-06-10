#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Pre‑Deploy Checklist — Production‑Grade
# =============================================================================
#
# Validates that all components required for a production deployment are
# present, correctly configured, and free of common mistakes.
#
# Usage:
#   ./pre_deploy_checklist.sh [OPTIONS]
#
# Options:
#   --binary PATH        Path to iona‑node binary (default: /usr/local/bin/iona‑node)
#   --configs DIR        Directory containing node configs (default: ../configs)
#   --systemd DIR        Directory containing systemd units (default: ../systemd)
#   --data-root DIR      Expected data root (default: /var/lib/iona)
#   --skip-disk-check    Skip disk space verification
#   --skip-checksums     Skip SHA256 integrity checks
#   --json               Output result as JSON (for CI/CD)
#   --verbose            Enable detailed output
#   --help               Show this help
#
# Environment variables (fallback):
#   IONA_BINARY, IONA_CONFIGS_DIR, IONA_SYSTEMD_DIR, IONA_DATA_ROOT,
#   IONA_SKIP_DISK_CHECK, IONA_SKIP_CHECKSUMS, IONA_VERBOSE

# ── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${IONA_BINARY:-/usr/local/bin/iona-node}"
CONFIG_DIR="${IONA_CONFIGS_DIR:-$SCRIPT_DIR/../configs}"
SYSTEMD_DIR="${IONA_SYSTEMD_DIR:-$SCRIPT_DIR/../systemd}"
DATA_ROOT="${IONA_DATA_ROOT:-/var/lib/iona}"
SKIP_DISK_CHECK="${IONA_SKIP_DISK_CHECK:-0}"
SKIP_CHECKSUMS="${IONA_SKIP_CHECKSUMS:-0}"
VERBOSE="${IONA_VERBOSE:-0}"
JSON_OUTPUT=0
ERRORS=0
WARNINGS=0

# Colours (safe for non‑TTY)
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARNINGS=$((WARNINGS+1)); }
log_verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "  ${CYAN}[DEBUG]${NC} $1"; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)          BINARY="$2"; shift 2 ;;
        --configs)         CONFIG_DIR="$2"; shift 2 ;;
        --systemd)         SYSTEMD_DIR="$2"; shift 2 ;;
        --data-root)       DATA_ROOT="$2"; shift 2 ;;
        --skip-disk-check) SKIP_DISK_CHECK=1; shift ;;
        --skip-checksums)  SKIP_CHECKSUMS=1; shift ;;
        --json)            JSON_OUTPUT=1; shift ;;
        --verbose)         VERBOSE=1; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Header ──────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  IONA Pre‑Deploy Checklist                                      ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Binary ─────────────────────────────────────────────────────────────
echo "[1/8] Binary"
if [[ -f "$BINARY" ]]; then
    if [[ -x "$BINARY" ]]; then
        pass "Binary exists and is executable: $BINARY"
    else
        fail "Binary exists but is NOT executable: $BINARY"
    fi
    if file "$BINARY" | grep -q "ELF"; then
        pass "Binary is a valid ELF"
    else
        warn "Binary may not be a valid ELF"
    fi
    # Version check
    BIN_VER=$("$BINARY" --version 2>/dev/null | head -1 || echo "unknown")
    pass "Version: $BIN_VER"
else
    fail "Binary not found: $BINARY"
fi

# ── 2. Config files ──────────────────────────────────────────────────────
echo ""
echo "[2/8] Config files"
for node in val1 val2 val3 val4 rpc; do
    cfg="$CONFIG_DIR/${node}.toml"
    if [[ -f "$cfg" ]]; then
        if command -v toml-test &>/dev/null; then
            if toml-test "$cfg" 2>/dev/null; then
                pass "$node.toml parses OK"
            else
                fail "$node.toml has parse errors"
            fi
        elif python3 -c "import tomllib" 2>/dev/null; then
            if python3 -c "import tomllib; tomllib.load(open('$cfg','rb'))" 2>/dev/null; then
                pass "$node.toml parses OK"
            else
                fail "$node.toml has parse errors"
            fi
        else
            # Basic validation
            if grep -q '^\[' "$cfg" && grep -q '=' "$cfg"; then
                pass "$node.toml exists (basic check)"
            else
                fail "$node.toml appears malformed"
            fi
        fi
    else
        fail "$node.toml not found at $cfg"
    fi
done

# ── 3. Genesis ────────────────────────────────────────────────────────────
echo ""
echo "[3/8] Genesis"
GENESIS="$CONFIG_DIR/genesis.json"
if [[ -f "$GENESIS" ]]; then
    pass "genesis.json exists"
    if command -v jq &>/dev/null; then
        VAL_COUNT=$(jq '.validators | length' "$GENESIS" 2>/dev/null || echo "0")
        CHAIN_ID=$(jq -r '.chain_id' "$GENESIS" 2>/dev/null || echo "missing")
    else
        VAL_COUNT=$(python3 -c "import json; g=json.load(open('$GENESIS')); print(len(g.get('validators',[])))" 2>/dev/null || echo "0")
        CHAIN_ID=$(python3 -c "import json; g=json.load(open('$GENESIS')); print(g.get('chain_id','missing'))" 2>/dev/null || echo "missing")
    fi
    if [[ "$VAL_COUNT" -ge 1 ]]; then
        pass "Genesis has $VAL_COUNT validator(s)"
    else
        fail "Genesis has no validators"
    fi
    if [[ "$CHAIN_ID" != "missing" ]]; then
        pass "chain_id = $CHAIN_ID"
    else
        fail "chain_id missing from genesis"
    fi
else
    fail "genesis.json not found at $GENESIS"
fi

# ── 4. No self‑bootstrap ─────────────────────────────────────────────────
echo ""
echo "[4/8] No self‑bootstrap"
declare -A NODE_PORTS=(
    [val1]=30333 [val2]=30334 [val3]=30335 [val4]=30336 [rpc]=30337
)
for node in val1 val2 val3 val4 rpc; do
    cfg="$CONFIG_DIR/${node}.toml"
    if [[ -f "$cfg" ]]; then
        own_port="${NODE_PORTS[$node]}"
        if grep -q "tcp/${own_port}" "$cfg" 2>/dev/null; then
            peer_lines=$(grep "peers" "$cfg" | grep -c "tcp/${own_port}" 2>/dev/null || echo "0")
            if [[ "$peer_lines" -gt 0 ]]; then
                fail "$node has itself in peers list (port $own_port)"
            else
                pass "$node does not self‑bootstrap"
            fi
        else
            pass "$node does not self‑bootstrap"
        fi
    fi
done

# ── 5. Systemd units ─────────────────────────────────────────────────────
echo ""
echo "[5/8] Systemd unit files"
for node in val1 val2 val3 val4 rpc; do
    unit="$SYSTEMD_DIR/iona-${node}.service"
    if [[ -f "$unit" ]]; then
        pass "iona-${node}.service exists"
    else
        fail "iona-${node}.service not found"
    fi
done

# ── 6. Scripts ────────────────────────────────────────────────────────────
echo ""
echo "[6/8] Scripts"
REQUIRED_SCRIPTS=("startup_order.sh" "dev_reset.sh" "build_release.sh" "atomic_deploy.sh" "healthcheck.sh")
for script in "${REQUIRED_SCRIPTS[@]}"; do
    s="${SCRIPT_DIR}/${script}"
    if [[ -f "$s" ]]; then
        if [[ -x "$s" ]]; then
            pass "$script exists and is executable"
        else
            warn "$script exists but is NOT executable"
        fi
    else
        fail "$script not found"
    fi
done

# ── 7. Disk space / permissions ──────────────────────────────────────────
echo ""
echo "[7/8] System checks"
if id iona &>/dev/null 2>&1; then
    pass "iona system user exists"
else
    warn "iona system user does not exist"
fi

for node in val1 val2 val3 val4 rpc; do
    d="$DATA_ROOT/$node"
    if [[ -d "$d" ]]; then
        pass "Data dir exists: $d"
    else
        warn "Data dir missing: $d"
    fi
done

if [[ "$SKIP_DISK_CHECK" -eq 0 ]]; then
    AVAIL_KB=$(df "$DATA_ROOT" 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    AVAIL_GB=$((AVAIL_KB / 1024 / 1024))
    if [[ "$AVAIL_GB" -lt 10 ]]; then
        fail "Low disk space on $DATA_ROOT: ${AVAIL_GB}GB available (need ≥10GB)"
    else
        pass "Disk space: ${AVAIL_GB}GB available on $DATA_ROOT"
    fi
fi

# ── 8. Checksums (optional) ──────────────────────────────────────────────
echo ""
echo "[8/8] SHA256 checksums"
if [[ "$SKIP_CHECKSUMS" -eq 0 ]]; then
    if [[ -f "$BINARY" ]]; then
        SHA_BIN=$(sha256sum "$BINARY" | awk '{print $1}')
        pass "Binary SHA256: $SHA_BIN"
    fi
else
    pass "Checksums skipped (--skip-checksums)"
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
if [[ "$ERRORS" -eq 0 ]]; then
    echo "║  RESULT: ALL CHECKS PASSED                                      ║"
    if [[ "$WARNINGS" -gt 0 ]]; then
        echo "║  ($WARNINGS warnings — review above)                            ║"
    fi
    echo "╚══════════════════════════════════════════════════════════════════╝"
    STATUS="PASS"
else
    echo "║  RESULT: $ERRORS FAILURES, $WARNINGS warnings                    ║"
    echo "║  Fix errors before deploying!                                   ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    STATUS="FAIL"
fi

if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    jq -n \
        --arg status "$STATUS" \
        --argjson errors "$ERRORS" \
        --argjson warnings "$WARNINGS" \
        --arg binary "$BINARY" \
        --arg timestamp "$(date -Iseconds)" \
        '{status: $status, errors: $errors, warnings: $warnings, binary: $binary, timestamp: $timestamp}'
fi

[[ "$ERRORS" -eq 0 ]] && exit 0 || exit 1
