#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# IONA Security Gate — local all-in-one script
#
# Mirrors the CI pipeline in .github/workflows/security.yml exactly.
# Run this before pushing a PR to catch security regressions locally.
#
# Usage:
#   ./scripts/security_check.sh                    # run all checks
#   ./scripts/security_check.sh --fast             # skip fuzz replay (saves ~1 min)
#   ./scripts/security_check.sh --fix              # auto-apply clippy fixes where possible
#   ./scripts/security_check.sh --skip-audit       # skip cargo audit
#   ./scripts/security_check.sh --skip-deny        # skip cargo deny
#   ./scripts/security_check.sh --skip-fuzz        # skip fuzz corpus replay
#   ./scripts/security_check.sh --skip-clippy      # skip clippy
#   ./scripts/security_check.sh --list             # list available checks
#   ./scripts/security_check.sh --json             # output results in JSON (for CI)
#   ./scripts/security_check.sh --help             # show this help
#
# Exit code: 0 = all passed, 1 = one or more checks failed.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

# ── Defaults ──────────────────────────────────────────────────────────────────
FAST_MODE=false
FIX_MODE=false
SKIP_AUDIT=false
SKIP_DENY=false
SKIP_FUZZ=false
SKIP_CLIPPY=false
JSON_OUTPUT=false
LIST_CHECKS=false

FAILED=()
START_TIME=$(date +%s)

# ── Helper functions ─────────────────────────────────────────────────────────
pass()  { echo -e "${GREEN}  ✓ PASS${RESET}  $*"; }
fail()  { echo -e "${RED}  ✗ FAIL${RESET}  $*"; FAILED+=("$*"); }
info()  { echo -e "${CYAN}  ℹ${RESET}      $*"; }
warn()  { echo -e "${YELLOW}  ⚠${RESET}      $*" >&2; }
head_() { echo -e "\n${BOLD}${YELLOW}══ $* ══${RESET}"; }

command_exists() {
    command -v "$1" &>/dev/null
}

install_cargo_tool() {
    local tool="$1"
    if ! command_exists "$tool"; then
        info "$tool not found — installing..."
        cargo install "$tool" --locked --quiet
    fi
}

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fast)          FAST_MODE=true; shift ;;
        --fix)           FIX_MODE=true; shift ;;
        --skip-audit)    SKIP_AUDIT=true; shift ;;
        --skip-deny)     SKIP_DENY=true; shift ;;
        --skip-fuzz)     SKIP_FUZZ=true; shift ;;
        --skip-clippy)   SKIP_CLIPPY=true; shift ;;
        --list)          LIST_CHECKS=true; shift ;;
        --json)          JSON_OUTPUT=true; shift ;;
        --help|-h)       sed -n '/^# Usage:/,/^# ═══/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)               warn "Unknown option: $1"; shift ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ── List checks ──────────────────────────────────────────────────────────────
if $LIST_CHECKS; then
    echo "Available security checks:"
    echo "  1. cargo audit (supply-chain vulnerabilities)"
    echo "  2. cargo deny (licenses, bans, sources)"
    echo "  3. Locked build (--locked)"
    echo "  4. Unsafe code audit (crypto/ + consensus/)"
    echo "  5. Unwrap audit (rpc/ + net/)"
    echo "  6. Clippy (deny warnings)"
    echo "  7. Security test suites"
    echo "  8. Fuzz corpus replay"
    echo ""
    echo "Options: --fast (skip fuzz), --fix (auto-fix clippy), --skip-*"
    exit 0
fi

# ── JSON output header ───────────────────────────────────────────────────────
if $JSON_OUTPUT; then
    echo '{'
    echo '  "timestamp": "'$(date -Iseconds)'",'
    echo '  "repository": "'$REPO_ROOT'",'
    echo '  "checks": ['
fi

# ── Helper for JSON reporting ────────────────────────────────────────────────
json_result() {
    local name="$1"
    local status="$2"
    local detail="$3"
    if $JSON_OUTPUT; then
        echo '    {'
        echo '      "name": "'$name'",'
        echo '      "status": "'$status'",'
        echo '      "detail": "'$detail'"'
        echo '    },'
    fi
}

# ── 1. Supply-chain: cargo audit ─────────────────────────────────────────────
if ! $SKIP_AUDIT; then
    head_ "1/8  Supply-chain: cargo audit"
    install_cargo_tool cargo-audit
    if cargo audit --deny warnings 2>&1; then
        pass "cargo audit — no known advisories"
        json_result "cargo-audit" "PASS" "No advisories found"
    else
        fail "cargo audit — RUSTSEC advisories found (blocking)"
        json_result "cargo-audit" "FAIL" "Advisories found"
    fi
else
    info "Skipping cargo audit (--skip-audit)"
fi

# ── 2. Supply-chain: cargo deny ──────────────────────────────────────────────
if ! $SKIP_DENY; then
    head_ "2/8  Supply-chain: cargo deny"
    install_cargo_tool cargo-deny
    if cargo deny check 2>&1; then
        pass "cargo deny — licenses, bans, sources OK"
        json_result "cargo-deny" "PASS" "Policy OK"
    else
        fail "cargo deny — policy violation found (blocking)"
        json_result "cargo-deny" "FAIL" "Policy violation"
    fi
else
    info "Skipping cargo deny (--skip-deny)"
fi

# ── 3. Locked build ──────────────────────────────────────────────────────────
head_ "3/8  Locked build (--locked)"
if [[ ! -f Cargo.lock ]]; then
    fail "Cargo.lock missing — must be committed for reproducible builds"
    json_result "locked-build" "FAIL" "Cargo.lock missing"
else
    if cargo build --locked --all-targets 2>&1 | tail -5; then
        pass "cargo build --locked"
        json_result "locked-build" "PASS" "Build successful"
    else
        fail "cargo build --locked — build failure"
        json_result "locked-build" "FAIL" "Build failure"
    fi
fi

# ── 4. Unsafe audit ──────────────────────────────────────────────────────────
head_ "4/8  Unsafe code audit (crypto/ + consensus/)"

check_unsafe() {
    local dir="$1"
    local count
    count=$(grep -rn --include="*.rs" "unsafe" "src/$dir/" 2>/dev/null \
            | grep -v "//.*unsafe" | wc -l || echo 0)
    if [[ "$count" -gt 0 ]]; then
        fail "src/$dir/: $count unsafe block(s) found — forbidden in security-critical code"
        json_result "unsafe-$dir" "FAIL" "$count unsafe blocks found"
        grep -rn --include="*.rs" "unsafe" "src/$dir/" | grep -v "//.*unsafe" | head -10
    else
        pass "src/$dir/ is unsafe-free"
        json_result "unsafe-$dir" "PASS" "No unsafe blocks"
    fi
}

check_unsafe crypto
check_unsafe consensus

# ── 5. Unwrap audit ──────────────────────────────────────────────────────────
head_ "5/8  Unwrap audit (rpc/ + net/)"

check_unwrap() {
    local dir="$1"
    local count
    count=$(grep -rn --include="*.rs" "\.unwrap()" "src/$dir/" 2>/dev/null \
            | grep -v "#\[cfg(test)\]" \
            | grep -v "// unwrap-ok:" | wc -l || echo 0)
    if [[ "$count" -gt 0 ]]; then
        fail "src/$dir/: $count bare .unwrap() call(s) — use .expect() or ? instead"
        json_result "unwrap-$dir" "FAIL" "$count unwrap calls found"
        grep -rn --include="*.rs" "\.unwrap()" "src/$dir/" \
            | grep -v "#\[cfg(test)\]" | grep -v "// unwrap-ok:" | head -10
    else
        pass "src/$dir/ unwrap-free"
        json_result "unwrap-$dir" "PASS" "No bare unwrap calls"
    fi
}

check_unwrap rpc
check_unwrap net

# ── 6. Clippy (deny-warnings) ────────────────────────────────────────────────
if ! $SKIP_CLIPPY; then
    head_ "6/8  Clippy (all targets, -D warnings)"
    CLIPPY_FLAGS="--locked --all-targets -- -D warnings"
    if $FIX_MODE; then
        info "Fix mode: running clippy --fix first"
        cargo clippy --fix --allow-dirty $CLIPPY_FLAGS 2>&1 || true
    fi
    if cargo clippy $CLIPPY_FLAGS 2>&1; then
        pass "clippy — no warnings"
        json_result "clippy" "PASS" "No warnings"
    else
        fail "clippy — warnings present (blocking)"
        json_result "clippy" "FAIL" "Warnings found"
    fi
else
    info "Skipping clippy (--skip-clippy)"
fi

# ── 7. Security test suites ───────────────────────────────────────────────────
head_ "7/8  Security test suites"

run_test_suite() {
    local suite="$1"
    local label="$2"
    if cargo test --locked --test "$suite" -- --nocapture 2>&1 | tail -20; then
        pass "$label"
        json_result "$suite" "PASS" "All tests passed"
    else
        fail "$label"
        json_result "$suite" "FAIL" "Test suite failed"
    fi
}

run_test_suite "consensus_adversarial"  "consensus adversarial tests"
run_test_suite "security_regression"    "security regression tests"
run_test_suite "rpc_hardening"          "RPC hardening tests"

# ── 8. Fuzz corpus replay ─────────────────────────────────────────────────────
if ! $SKIP_FUZZ && ! $FAST_MODE; then
    head_ "8/8  Fuzz corpus replay"

    if ! command_exists cargo-fuzz; then
        info "cargo-fuzz not found — installing (requires nightly)..."
        rustup toolchain install nightly --no-self-update --quiet
        cargo +nightly install cargo-fuzz --locked --quiet
    fi

    FUZZ_TARGETS=(
        consensus_msg
        tx_json
        p2p_frame_decode
        vm_bytecode
        block_header
        rpc_json
        state_transition
    )

    for target in "${FUZZ_TARGETS[@]}"; do
        CORPUS_DIR="fuzz/corpus/$target"
        mkdir -p "$CORPUS_DIR"
        SEED_COUNT=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l)

        if [[ "$SEED_COUNT" -eq 0 ]]; then
            info "$target: no corpus — skipping replay"
            pass "$target fuzz replay (no corpus)"
            json_result "fuzz-$target" "PASS" "No corpus"
        else
            info "$target: replaying $SEED_COUNT corpus entries"
            REPLAY_OUT=$(cargo +nightly fuzz run "$target" "$CORPUS_DIR" \
                         -- -runs=0 -max_len=65536 2>&1 || true)
            if echo "$REPLAY_OUT" | grep -qE "CRASH|ERROR|AddressSanitizer"; then
                fail "$target fuzz replay — CRASH detected"
                json_result "fuzz-$target" "FAIL" "Crash detected"
                echo "$REPLAY_OUT" | grep -E "CRASH|ERROR|AddressSanitizer" | head -5
            else
                pass "$target fuzz replay ($SEED_COUNT entries)"
                json_result "fuzz-$target" "PASS" "Replayed $SEED_COUNT entries"
            fi
        fi
    done
elif $FAST_MODE; then
    info "Fast mode: skipping fuzz corpus replay"
else
    info "Fuzz replay skipped (--skip-fuzz)"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BOLD}═══════════════════════════════════════════${RESET}"
if [[ ${#FAILED[@]} -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  ALL SECURITY CHECKS PASSED ✓${RESET}"
    echo -e "${BOLD}  Duration: ${DURATION}s${RESET}"
    echo -e "${BOLD}═══════════════════════════════════════════${RESET}"
    if $JSON_OUTPUT; then
        echo '  ],'
        echo '  "overall": "PASS",'
        echo '  "duration_seconds": '$DURATION
        echo '}'
    fi
    exit 0
else
    echo -e "${RED}${BOLD}  SECURITY GATE FAILED — ${#FAILED[@]} check(s) failed:${RESET}"
    for f in "${FAILED[@]}"; do
        echo -e "${RED}    • $f${RESET}"
    done
    echo -e "${BOLD}  Duration: ${DURATION}s${RESET}"
    echo -e "${BOLD}═══════════════════════════════════════════${RESET}"
    echo ""
    echo -e "Fix all failures before pushing. See ${CYAN}.github/workflows/security.yml${RESET} for details."
    if $JSON_OUTPUT; then
        echo '  ],'
        echo '  "overall": "FAIL",'
        echo '  "duration_seconds": '$DURATION
        echo '}'
    fi
    exit 1
fi
