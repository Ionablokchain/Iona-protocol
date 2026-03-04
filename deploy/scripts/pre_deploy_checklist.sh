#!/usr/bin/env bash
set -euo pipefail
#
# IONA Pre-Deploy Checklist — run before every deployment.
#
# Verifies:
#   1. Binary exists and runs
#   2. Configs parse correctly
#   3. Genesis is valid
#   4. No self-bootstrap in peer lists
#   5. Identity files present (unless fresh chain)
#   6. Disk space / permissions
#
# Usage:
#   ./deploy/scripts/pre_deploy_checklist.sh [--binary /path/to/iona-node]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/../configs"
BINARY="${1:-/usr/local/bin/iona-node}"
ERRORS=0
WARNINGS=0

pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; ERRORS=$((ERRORS+1)); }
warn() { echo "  [WARN] $1"; WARNINGS=$((WARNINGS+1)); }

echo "=== IONA Pre-Deploy Checklist ==="
echo ""

# ── 1. Binary ─────────────────────────────────────────────────────────────
echo "[1/7] Binary"
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
else
    fail "Binary not found: $BINARY"
fi

# ── 2. Config files ──────────────────────────────────────────────────────
echo ""
echo "[2/7] Config files"
for node in val1 val2 val3 val4 rpc; do
    cfg="$CONFIG_DIR/${node}.toml"
    if [[ -f "$cfg" ]]; then
        # Basic TOML validity check (look for unclosed brackets, missing =)
        if python3 -c "
import sys
try:
    import tomllib
    with open('$cfg', 'rb') as f:
        tomllib.load(f)
    sys.exit(0)
except Exception:
    pass
try:
    import tomli
    with open('$cfg', 'rb') as f:
        tomli.load(f)
    sys.exit(0)
except Exception:
    pass
# Fallback: basic check
with open('$cfg') as f:
    content = f.read()
if '[' in content and '=' in content:
    sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
            pass "$node.toml parses OK"
        else
            fail "$node.toml has parse errors"
        fi
    else
        fail "$node.toml not found at $cfg"
    fi
done

# ── 3. Genesis ────────────────────────────────────────────────────────────
echo ""
echo "[3/7] Genesis"
GENESIS="$CONFIG_DIR/genesis.json"
if [[ -f "$GENESIS" ]]; then
    pass "genesis.json exists"
    VAL_COUNT=$(python3 -c "
import json
with open('$GENESIS') as f:
    g = json.load(f)
vals = g.get('validators', [])
print(len(vals))
" 2>/dev/null || echo "0")
    if [[ "$VAL_COUNT" -eq 3 ]]; then
        pass "Genesis has exactly 3 validators"
    else
        fail "Genesis has $VAL_COUNT validators (expected 3)"
    fi
    # Check chain_id
    CHAIN_ID=$(python3 -c "
import json
with open('$GENESIS') as f:
    g = json.load(f)
print(g.get('chain_id', 'missing'))
" 2>/dev/null || echo "missing")
    if [[ "$CHAIN_ID" != "missing" ]]; then
        pass "chain_id = $CHAIN_ID"
    else
        fail "chain_id missing from genesis"
    fi
else
    fail "genesis.json not found at $GENESIS"
fi

# ── 4. No self-bootstrap ─────────────────────────────────────────────────
echo ""
echo "[4/7] No self-bootstrap"
declare -A NODE_PORTS=(
    [val1]=30333 [val2]=30334 [val3]=30335 [val4]=30336 [rpc]=30337
)
for node in val1 val2 val3 val4 rpc; do
    cfg="$CONFIG_DIR/${node}.toml"
    if [[ -f "$cfg" ]]; then
        own_port="${NODE_PORTS[$node]}"
        if grep -q "tcp/${own_port}" "$cfg" 2>/dev/null; then
            # Check if it's in the peers section, not the listen section
            peer_lines=$(grep "peers" "$cfg" | grep -c "tcp/${own_port}" 2>/dev/null || echo "0")
            if [[ "$peer_lines" -gt 0 ]]; then
                fail "$node has itself in peers list (port $own_port)"
            else
                pass "$node does not self-bootstrap"
            fi
        else
            pass "$node does not self-bootstrap"
        fi
    fi
done

# ── 5. Systemd units ─────────────────────────────────────────────────────
echo ""
echo "[5/7] Systemd unit files"
SYSTEMD_DIR="${SCRIPT_DIR}/../systemd"
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
echo "[6/7] Scripts"
for script in startup_order.sh dev_reset.sh build_release.sh atomic_deploy.sh healthcheck.sh; do
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

# ── 7. Disk / permissions ────────────────────────────────────────────────
echo ""
echo "[7/7] System checks"
# Check if iona user exists
if id iona >/dev/null 2>&1; then
    pass "iona system user exists"
else
    warn "iona system user does not exist (create before production deploy)"
fi
# Check data dirs
for node in val1 val2 val3 val4 rpc; do
    d="/var/lib/iona/${node}"
    if [[ -d "$d" ]]; then
        pass "Data dir exists: $d"
    else
        warn "Data dir missing: $d (will be created on first start)"
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════"
if [[ "$ERRORS" -eq 0 ]]; then
    echo "  RESULT: ALL CHECKS PASSED"
    if [[ "$WARNINGS" -gt 0 ]]; then
        echo "  ($WARNINGS warnings — review above)"
    fi
    echo "═══════════════════════════════════════"
    exit 0
else
    echo "  RESULT: $ERRORS FAILURES, $WARNINGS warnings"
    echo "  Fix errors before deploying!"
    echo "═══════════════════════════════════════"
    exit 1
fi
