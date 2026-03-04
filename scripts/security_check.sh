#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# IONA Security Gate — local all-in-one script
#
# Mirrors the CI pipeline in .github/workflows/security.yml exactly.
# Run this before pushing a PR to catch security regressions locally.
#
# Usage:
#   ./scripts/security_check.sh            # run all checks
#   ./scripts/security_check.sh --fast     # skip fuzz replay (saves ~1 min)
#   ./scripts/security_check.sh --fix      # auto-apply clippy fixes where possible
#
# Exit code: 0 = all passed, 1 = one or more checks failed.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

pass()  { echo -e "${GREEN}  ✓ PASS${RESET}  $*"; }
fail()  { echo -e "${RED}  ✗ FAIL${RESET}  $*"; FAILED+=("$*"); }
info()  { echo -e "${CYAN}  ℹ${RESET}      $*"; }
head_() { echo -e "\n${BOLD}${YELLOW}══ $* ══${RESET}"; }

FAILED=()
FAST_MODE=false
FIX_MODE=false

for arg in "$@"; do
  case "$arg" in
    --fast) FAST_MODE=true ;;
    --fix)  FIX_MODE=true  ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo -e "${BOLD}IONA Security Gate${RESET} — $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "Repository: ${REPO_ROOT}"

# ── 1. Supply-chain: cargo audit ─────────────────────────────────────────────
head_ "1/8  Supply-chain: cargo audit"

if ! command -v cargo-audit &>/dev/null; then
  info "cargo-audit not found — installing..."
  cargo install cargo-audit --locked --quiet
fi

if cargo audit --deny warnings 2>&1; then
  pass "cargo audit — no known advisories"
else
  fail "cargo audit — RUSTSEC advisories found (blocking)"
fi

# ── 2. Supply-chain: cargo deny ──────────────────────────────────────────────
head_ "2/8  Supply-chain: cargo deny"

if ! command -v cargo-deny &>/dev/null; then
  info "cargo-deny not found — installing..."
  cargo install cargo-deny --locked --quiet
fi

if cargo deny check 2>&1; then
  pass "cargo deny — licenses, bans, sources OK"
else
  fail "cargo deny — policy violation found (blocking)"
fi

# ── 3. Locked build ───────────────────────────────────────────────────────────
head_ "3/8  Locked build (--locked)"

if [ ! -f Cargo.lock ]; then
  fail "Cargo.lock missing — must be committed for reproducible builds"
else
  if cargo build --locked --all-targets 2>&1 | tail -5; then
    pass "cargo build --locked"
  else
    fail "cargo build --locked — build failure"
  fi
fi

# ── 4. Unsafe audit ───────────────────────────────────────────────────────────
head_ "4/8  Unsafe code audit (crypto/ + consensus/)"

check_unsafe() {
  local dir="$1"
  local count
  count=$(grep -rn --include="*.rs" "unsafe" "src/$dir/" 2>/dev/null \
          | grep -v "//.*unsafe" | wc -l || true)
  if [ "$count" -gt "0" ]; then
    fail "src/$dir/: $count unsafe block(s) found — forbidden in security-critical code"
    grep -rn --include="*.rs" "unsafe" "src/$dir/" | grep -v "//.*unsafe" | head -10
  else
    pass "src/$dir/ is unsafe-free"
  fi
}

check_unsafe crypto
check_unsafe consensus

# ── 5. Unwrap audit ───────────────────────────────────────────────────────────
head_ "5/8  Unwrap audit (rpc/ + net/)"

check_unwrap() {
  local dir="$1"
  local count
  count=$(grep -rn --include="*.rs" "\.unwrap()" "src/$dir/" 2>/dev/null \
          | grep -v "#\[cfg(test)\]" \
          | grep -v "// unwrap-ok:" | wc -l || true)
  if [ "$count" -gt "0" ]; then
    fail "src/$dir/: $count bare .unwrap() call(s) — use .expect() or ? instead"
    grep -rn --include="*.rs" "\.unwrap()" "src/$dir/" \
      | grep -v "#\[cfg(test)\]" | grep -v "// unwrap-ok:" | head -10
  else
    pass "src/$dir/ unwrap-free"
  fi
}

check_unwrap rpc
check_unwrap net

# ── 6. Clippy (deny-warnings) ─────────────────────────────────────────────────
head_ "6/8  Clippy (all targets, -D warnings)"

CLIPPY_FLAGS="--locked --all-targets -- -D warnings"
if $FIX_MODE; then
  info "Fix mode: running clippy --fix first"
  cargo clippy --fix --allow-dirty $CLIPPY_FLAGS 2>&1 || true
fi

if cargo clippy $CLIPPY_FLAGS 2>&1; then
  pass "clippy — no warnings"
else
  fail "clippy — warnings present (blocking)"
fi

# ── 7. Security test suites ───────────────────────────────────────────────────
head_ "7/8  Security test suites"

run_test_suite() {
  local suite="$1"
  local label="$2"
  if cargo test --locked --test "$suite" -- --nocapture 2>&1 | tail -20; then
    pass "$label"
  else
    fail "$label"
  fi
}

run_test_suite "consensus_adversarial"  "consensus adversarial tests"
run_test_suite "security_regression"    "security regression tests"
run_test_suite "rpc_hardening"          "RPC hardening tests"

# ── 8. Fuzz corpus replay ─────────────────────────────────────────────────────
head_ "8/8  Fuzz corpus replay"

if $FAST_MODE; then
  info "Fast mode: skipping fuzz corpus replay"
else
  if ! command -v cargo-fuzz &>/dev/null; then
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

    if [ "$SEED_COUNT" -eq "0" ]; then
      info "$target: no corpus — skipping replay"
      pass "$target fuzz replay (no corpus)"
    else
      info "$target: replaying $SEED_COUNT corpus entries"
      REPLAY_OUT=$(cargo +nightly fuzz run "$target" "$CORPUS_DIR" \
                   -- -runs=0 -max_len=65536 2>&1 || true)
      if echo "$REPLAY_OUT" | grep -qE "CRASH|ERROR|AddressSanitizer"; then
        fail "$target fuzz replay — CRASH detected"
        echo "$REPLAY_OUT" | grep -E "CRASH|ERROR|AddressSanitizer" | head -5
      else
        pass "$target fuzz replay ($SEED_COUNT entries)"
      fi
    fi
  done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════${RESET}"

if [ ${#FAILED[@]} -eq 0 ]; then
  echo -e "${GREEN}${BOLD}  ALL SECURITY CHECKS PASSED ✓${RESET}"
  echo -e "${BOLD}═══════════════════════════════════════════${RESET}"
  exit 0
else
  echo -e "${RED}${BOLD}  SECURITY GATE FAILED — ${#FAILED[@]} check(s) failed:${RESET}"
  for f in "${FAILED[@]}"; do
    echo -e "${RED}    • $f${RESET}"
  done
  echo -e "${BOLD}═══════════════════════════════════════════${RESET}"
  echo ""
  echo -e "Fix all failures before pushing. See ${CYAN}.github/workflows/security.yml${RESET} for details."
  exit 1
fi
