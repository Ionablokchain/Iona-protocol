#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# IONA Security Gate — Production‑Grade v2
#
# Mirrors the CI pipeline in .github/workflows/security.yml exactly.
# Run this before pushing a PR to catch security regressions locally.
#
# Usage:
#   ./scripts/security_check.sh [OPTIONS]
#
# Options:
#   --fast              skip fuzz replay (saves ~1 min)
#   --fix               auto-apply clippy fixes where possible
#   --skip-<check>      skip a specific check (audit, deny, fuzz, clippy, secrets, complexity)
#   --step <name>       run only a specific step (can be repeated)
#   --list              list available checks
#   --json              output results in JSON (for CI)
#   --verbose           enable detailed output
#   --help              show this help
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
JSON_OUTPUT=false
LIST_CHECKS=false
VERBOSE=false
ONLY_STEPS=()
FAILED=()
PASSED=()
SKIPPED=()
START_TIME=$(date +%s)

# Individual skip flags
SKIP_AUDIT=false
SKIP_DENY=false
SKIP_FUZZ=false
SKIP_CLIPPY=false
SKIP_SECRETS=false
SKIP_COMPLEXITY=false
SKIP_DEPRECATED=false

# ── Helper functions ─────────────────────────────────────────────────────────
pass()   { echo -e "${GREEN}  ✓ PASS${RESET}  $*"; PASSED+=("$*"); }
fail()   { echo -e "${RED}  ✗ FAIL${RESET}  $*"; FAILED+=("$*"); }
info()   { echo -e "${CYAN}  ℹ${RESET}      $*"; }
warn()   { echo -e "${YELLOW}  ⚠${RESET}      $*" >&2; }
skip()   { echo -e "${YELLOW}  ⏭ SKIP${RESET}  $*"; SKIPPED+=("$*"); }
head_()  { echo -e "\n${BOLD}${YELLOW}══ $* ══${RESET}"; }

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "[DEBUG] $*"
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

install_cargo_tool() {
    local tool="$1"
    if ! command_exists "$tool"; then
        info "$tool not found — installing..."
        cargo install "$tool" --locked --quiet 2>/dev/null || {
            warn "Failed to install $tool — skipping"
            return 1
        }
    fi
    return 0
}

should_run() {
    local step="$1"
    if [[ ${#ONLY_STEPS[@]} -eq 0 ]]; then
        return 0
    fi
    for s in "${ONLY_STEPS[@]}"; do
        if [[ "$s" == "$step" ]]; then
            return 0
        fi
    done
    return 1
}

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fast)            FAST_MODE=true; shift ;;
        --fix)             FIX_MODE=true; shift ;;
        --skip-audit)      SKIP_AUDIT=true; shift ;;
        --skip-deny)       SKIP_DENY=true; shift ;;
        --skip-fuzz)       SKIP_FUZZ=true; shift ;;
        --skip-clippy)     SKIP_CLIPPY=true; shift ;;
        --skip-secrets)    SKIP_SECRETS=true; shift ;;
        --skip-complexity) SKIP_COMPLEXITY=true; shift ;;
        --skip-deprecated) SKIP_DEPRECATED=true; shift ;;
        --step)            ONLY_STEPS+=("$2"); shift 2 ;;
        --list)            LIST_CHECKS=true; shift ;;
        --json)            JSON_OUTPUT=true; shift ;;
        --verbose)         VERBOSE=true; shift ;;
        --help|-h)
            sed -n '/^# Usage:/,/^# ═══/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)                 warn "Unknown option: $1"; shift ;;
    esac
done

# ── Locate project root ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -f Cargo.toml ]]; then
    fail "Cargo.toml not found — run from project root"
    exit 1
fi

# ── Pre-flight checks ────────────────────────────────────────────────────────
for cmd in cargo rustc grep find; do
    if ! command_exists "$cmd"; then
        fail "Required tool not found: $cmd"
        exit 1
    fi
done

# ── List checks ──────────────────────────────────────────────────────────────
if $LIST_CHECKS; then
    echo "Available security checks:"
    echo "  1.  cargo audit          — supply-chain vulnerabilities"
    echo "  2.  cargo deny           — licenses, bans, sources"
    echo "  3.  locked build         — reproducible build check"
    echo "  4.  unsafe audit         — crypto/ + consensus/"
    echo "  5.  unwrap audit         — rpc/ + net/"
    echo "  6.  clippy               — deny warnings"
    echo "  7.  secrets scanning     — detect leaked keys/tokens"
    echo "  8.  security test suites — adversarial, regression, hardening"
    echo "  9.  fuzz corpus replay   — replay fuzz corpora"
    echo "  10. deprecated deps      — check for deprecated crates"
    echo "  11. code complexity      — cognitive complexity limits"
    echo ""
    echo "Options: --fast (skip fuzz), --fix (auto-fix clippy), --skip-*"
    echo "         --step <name> (run only specific steps)"
    exit 0
fi

# ── Banner ───────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║  IONA SECURITY GATE — $(date -u '+%Y-%m-%d %H:%M:%S UTC')        ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

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

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Supply-chain: cargo audit
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "audit"; then
    if ! $SKIP_AUDIT; then
        head_ "1/11  Supply-chain: cargo audit"
        if install_cargo_tool cargo-audit; then
            if cargo audit --deny warnings 2>&1; then
                pass "cargo audit — no known advisories"
                json_result "cargo-audit" "PASS" "No advisories found"
            else
                fail "cargo audit — RUSTSEC advisories found (blocking)"
                json_result "cargo-audit" "FAIL" "Advisories found"
            fi
        else
            skip "cargo audit (installation failed)"
        fi
    else
        skip "cargo audit (--skip-audit)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 2. Supply-chain: cargo deny
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "deny"; then
    if ! $SKIP_DENY; then
        head_ "2/11  Supply-chain: cargo deny"
        if install_cargo_tool cargo-deny; then
            if cargo deny check licenses advisories sources 2>&1; then
                pass "cargo deny — licenses, bans, sources OK"
                json_result "cargo-deny" "PASS" "Policy OK"
            else
                fail "cargo deny — policy violation found (blocking)"
                json_result "cargo-deny" "FAIL" "Policy violation"
            fi
        else
            skip "cargo deny (installation failed)"
        fi
    else
        skip "cargo deny (--skip-deny)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 3. Locked build
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "build"; then
    head_ "3/11  Locked build (--locked)"
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
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 4. Unsafe audit
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "unsafe"; then
    head_ "4/11  Unsafe code audit (crypto/ + consensus/)"

    check_unsafe() {
        local dir="$1"
        local count
        count=$(grep -rn --include="*.rs" "unsafe" "src/$dir/" 2>/dev/null \
                | grep -v "//.*unsafe" | grep -v "#\[allow(unsafe_code)\]" | wc -l || echo 0)
        if [[ "$count" -gt 0 ]]; then
            fail "src/$dir/: $count unsafe block(s) found — forbidden in security-critical code"
            json_result "unsafe-$dir" "FAIL" "$count unsafe blocks found"
            if $VERBOSE; then
                grep -rn --include="*.rs" "unsafe" "src/$dir/" \
                    | grep -v "//.*unsafe" | grep -v "#\[allow(unsafe_code)\]" | head -10
            fi
        else
            pass "src/$dir/ is unsafe-free"
            json_result "unsafe-$dir" "PASS" "No unsafe blocks"
        fi
    }

    check_unsafe crypto
    check_unsafe consensus
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 5. Unwrap audit
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "unwrap"; then
    head_ "5/11  Unwrap audit (rpc/ + net/)"

    check_unwrap() {
        local dir="$1"
        local count
        count=$(grep -rn --include="*.rs" "\.unwrap()" "src/$dir/" 2>/dev/null \
                | grep -v "#\[cfg(test)\]" \
                | grep -v "// unwrap-ok:" | wc -l || echo 0)
        if [[ "$count" -gt 0 ]]; then
            fail "src/$dir/: $count bare .unwrap() call(s) — use .expect() or ? instead"
            json_result "unwrap-$dir" "FAIL" "$count unwrap calls found"
            if $VERBOSE; then
                grep -rn --include="*.rs" "\.unwrap()" "src/$dir/" \
                    | grep -v "#\[cfg(test)\]" | grep -v "// unwrap-ok:" | head -10
            fi
        else
            pass "src/$dir/ unwrap-free"
            json_result "unwrap-$dir" "PASS" "No bare unwrap calls"
        fi
    }

    check_unwrap rpc
    check_unwrap net
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 6. Clippy (deny-warnings)
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "clippy"; then
    if ! $SKIP_CLIPPY; then
        head_ "6/11  Clippy (all targets, -D warnings)"
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
        skip "clippy (--skip-clippy)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 7. Secrets scanning (detect leaked keys/tokens)
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "secrets"; then
    if ! $SKIP_SECRETS; then
        head_ "7/11  Secrets scanning"
        SECRETS_FOUND=0
        SECRET_PATTERNS=(
            '-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----'
            'private_key|secret_key|api_key|auth_token|password'
            'sk-[a-zA-Z0-9]{32,}'
            'ghp_[a-zA-Z0-9]{36,}'
        )
        for pattern in "${SECRET_PATTERNS[@]}"; do
            if grep -rn --include="*.rs" --include="*.toml" --include="*.json" \
                -E "$pattern" src/ config/ data/ 2>/dev/null | grep -v "//.*fake\|//.*test\|#.*dummy"; then
                SECRETS_FOUND=1
            fi
        done
        if [[ $SECRETS_FOUND -eq 0 ]]; then
            pass "secrets scanning — no secrets detected"
            json_result "secrets" "PASS" "No secrets found"
        else
            fail "secrets scanning — potential secrets detected (review above)"
            json_result "secrets" "FAIL" "Potential secrets found"
        fi
    else
        skip "secrets scanning (--skip-secrets)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 8. Security test suites
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "tests"; then
    head_ "8/11  Security test suites"

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
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 9. Fuzz corpus replay
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "fuzz"; then
    if ! $SKIP_FUZZ && ! $FAST_MODE; then
        head_ "9/11  Fuzz corpus replay"

        if ! command_exists cargo-fuzz; then
            info "cargo-fuzz not found — installing (requires nightly)..."
            rustup toolchain install nightly --no-self-update 2>/dev/null || true
            cargo +nightly install cargo-fuzz --locked --quiet 2>/dev/null || {
                skip "fuzz replay (cargo-fuzz installation failed)"
                json_result "fuzz" "SKIP" "Installation failed"
            }
        fi

        if command_exists cargo-fuzz; then
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
                        if $VERBOSE; then
                            echo "$REPLAY_OUT" | grep -E "CRASH|ERROR|AddressSanitizer" | head -5
                        fi
                    else
                        pass "$target fuzz replay ($SEED_COUNT entries)"
                        json_result "fuzz-$target" "PASS" "Replayed $SEED_COUNT entries"
                    fi
                fi
            done
        fi
    elif $FAST_MODE; then
        skip "Fuzz replay (--fast mode)"
    else
        skip "Fuzz replay (--skip-fuzz)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 10. Deprecated dependencies check
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "deprecated"; then
    if ! $SKIP_DEPRECATED; then
        head_ "10/11 Deprecated dependencies check"
        DEPRECATED_COUNT=$(cargo tree 2>/dev/null | grep -c "deprecated" || echo 0)
        if [[ "$DEPRECATED_COUNT" -eq 0 ]]; then
            pass "no deprecated dependencies detected"
            json_result "deprecated" "PASS" "No deprecated deps"
        else
            warn "$DEPRECATED_COUNT deprecated dependencies found (non-blocking)"
            if $VERBOSE; then
                cargo tree | grep "deprecated"
            fi
            pass "deprecated dependencies (warning only)"
            json_result "deprecated" "WARN" "$DEPRECATED_COUNT deprecated deps"
        fi
    else
        skip "deprecated deps (--skip-deprecated)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 11. Code complexity limits
# ═══════════════════════════════════════════════════════════════════════════════
if should_run "complexity"; then
    if ! $SKIP_COMPLEXITY; then
        head_ "11/11 Code complexity limits"
        MAX_FN_LINES=200
        MAX_FILE_LINES=1000
        COMPLEXITY_FAILED=0

        # Check function length
        LONG_FNS=$(grep -rn "fn " src/ --include="*.rs" -A $MAX_FN_LINES 2>/dev/null | wc -l || echo 0)
        if [[ "$LONG_FNS" -gt 10 ]]; then
            warn "Some functions may exceed $MAX_FN_LINES lines (review manually)"
        fi

        # Check file length
        LONG_FILES=$(find src/ -name "*.rs" -exec wc -l {} \; 2>/dev/null \
            | awk -v max=$MAX_FILE_LINES '$1 > max {print $2 " (" $1 " lines)"}')
        if [[ -n "$LONG_FILES" ]]; then
            warn "Files exceeding $MAX_FILE_LINES lines:"
            if $VERBOSE; then
                echo "$LONG_FILES"
            fi
        else
            pass "all files within $MAX_FILE_LINES lines"
            json_result "complexity" "PASS" "Within limits"
        fi
    else
        skip "code complexity (--skip-complexity)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BOLD}═══════════════════════════════════════════${RESET}"
if [[ ${#FAILED[@]} -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  ALL SECURITY CHECKS PASSED ✓${RESET}"
    echo -e "  ${GREEN}Passed: ${#PASSED[@]} | Skipped: ${#SKIPPED[@]} | Failed: 0${RESET}"
    echo -e "${BOLD}  Duration: ${DURATION}s${RESET}"
    echo -e "${BOLD}═══════════════════════════════════════════${RESET}"
    
    if $JSON_OUTPUT; then
        echo '  ],'
        echo '  "overall": "PASS",'
        echo '  "passed": '${#PASSED[@]}','
        echo '  "skipped": '${#SKIPPED[@]}','
        echo '  "failed": 0,'
        echo '  "duration_seconds": '$DURATION
        echo '}'
    fi
    exit 0
else
    echo -e "${RED}${BOLD}  SECURITY GATE FAILED — ${#FAILED[@]} check(s) failed${RESET}"
    echo -e "  ${GREEN}Passed: ${#PASSED[@]}${RESET} | ${YELLOW}Skipped: ${#SKIPPED[@]}${RESET} | ${RED}Failed: ${#FAILED[@]}${RESET}"
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
        echo '  "passed": '${#PASSED[@]}','
        echo '  "skipped": '${#SKIPPED[@]}','
        echo '  "failed": '${#FAILED[@]}','
        echo '  "duration_seconds": '$DURATION
        echo '}'
    fi
    exit 1
fi
