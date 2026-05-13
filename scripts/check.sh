#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
#  IONA Release Checklist — Production‑Grade
# =============================================================================
#  Run this script before every push / zip / release.
#  All critical steps must pass — if any fail, the build is NOT safe to ship.
#
#  Environment variables:
#    BIN_NAME          - name of the binary to build (default: iona-node)
#    SKIP_*            - set to 1 to skip a section (e.g., SKIP_AUDIT=1)
#    SKIP_ALL_OPTIONAL - set to 1 to skip all optional checks
#    RUSTFLAGS         - passed to cargo (default: "-D warnings")
#    VERBOSE           - set to 1 for detailed output
#    CI                - set to 1 in CI environments (disables interactive prompts)
#
#  Usage:
#    ./scripts/release_checklist.sh [--quick] [--verbose] [--json]
#      --quick   skip optional checks (audit, deny, fuzz, outdated)
#      --verbose enable detailed output
#      --json    output final summary as JSON (for CI integration)
# =============================================================================

# ── Configuration ────────────────────────────────────────────────────────────
BIN_NAME="${BIN_NAME:-iona-node}"
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"
VERBOSE="${VERBOSE:-0}"
CI="${CI:-0}"
QUICK=0
JSON_OUTPUT=0

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)   QUICK=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    --json)    JSON_OUTPUT=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Colours (safe for non‑TTY) ──────────────────────────────────────────────
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; BLUE=''; NC=''
fi

# ── Helper functions ────────────────────────────────────────────────────────
info()    { echo -e "${BLUE}[INFO]${NC}   $*"; }
pass()    { echo -e "${GREEN}[PASS]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}   $*" >&2; }
fail()    { echo -e "${RED}[FAIL]${NC}   $*" >&2; }

step() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ${BLUE}STEP: $1${NC}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo "  (verbose output follows)"
  fi
}

# Check if a command exists, returns 0 if found, else 1
cmd_exists() { command -v "$1" &>/dev/null; }

# Run a command with optional verbose output capture
run_cmd() {
  local cmd="$1"
  local msg="$2"
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo "  → $cmd"
    eval "$cmd" 2>&1
  else
    eval "$cmd" >/dev/null 2>&1
  fi
  local ret=$?
  if [[ $ret -eq 0 ]]; then
    pass "$msg"
    return 0
  else
    fail "$msg"
    return 1
  fi
}

# Run an optional check (skip if command missing or SKIP_* set)
optional_check() {
  local name="$1"
  local cmd="$2"
  local skip_var="$3"
  local required_cmd="$4"

  if [[ "${!skip_var:-0}" -eq 1 ]]; then
    warn "Skipping $name (${skip_var}=1)"
    return 0
  fi
  if [[ "$QUICK" -eq 1 ]]; then
    warn "Skipping $name (quick mode)"
    return 0
  fi
  if [[ -n "$required_cmd" ]] && ! cmd_exists "$required_cmd"; then
    warn "Skipping $name ($required_cmd not installed)"
    return 0
  fi

  if run_cmd "$cmd" "$name"; then
    return 0
  else
    return 1
  fi
}

# ── Initialise counters ──────────────────────────────────────────────────────
PASS=0
FAIL=0
FAILED_STEPS=()
START_TIME=$(date +%s)

# ── Trap for cleanup ────────────────────────────────────────────────────────
cleanup() {
  if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "────────────────────────────────────────────────────────────────────"
    warn "Release checklist incomplete. Failures recorded. See above."
  fi
}
trap cleanup EXIT

# ── A. Code formatting ──────────────────────────────────────────────────────
step "A. cargo fmt --check"
if run_cmd "cargo fmt --check" "code formatting"; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo fmt")
fi

# ── B. Lint (clippy) ───────────────────────────────────────────────────────
step "B. cargo clippy"
if run_cmd "cargo clippy --locked -- -D warnings" "clippy warnings"; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo clippy")
fi

# ── C. Tests (full suite) ───────────────────────────────────────────────────
step "C. cargo test --locked"
if run_cmd "cargo test --locked" "all tests"; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo test")
fi

# ── D. Documentation build ──────────────────────────────────────────────────
if [[ "${SKIP_DOC:-0}" -eq 1 ]]; then
  warn "Skipping documentation build (SKIP_DOC=1)"
else
  step "D. cargo doc --no-deps --document-private-items"
  if run_cmd "RUSTDOCFLAGS=\"-D warnings\" cargo doc --no-deps --document-private-items" "documentation"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo doc")
  fi
fi

# ── E. Security audit (cargo audit) ─────────────────────────────────────────
optional_check "cargo audit" \
  "cargo audit" \
  "SKIP_AUDIT" \
  "cargo-audit"
if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo audit"); fi

# ── F. License & dependency checks (cargo deny) ─────────────────────────────
optional_check "cargo deny check" \
  "cargo deny check" \
  "SKIP_DENY" \
  "cargo-deny"
if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo deny"); fi

# ── G. Fuzzing (compile only) ───────────────────────────────────────────────
optional_check "fuzz targets (compile)" \
  "cargo fuzz build --all" \
  "SKIP_FUZZ" \
  "cargo-fuzz"
if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo fuzz"); fi

# ── H. Outdated dependencies (cargo outdated) – optional, only if tool present
optional_check "cargo outdated (check for updates)" \
  "cargo outdated --exit-code 1" \
  "SKIP_OUTDATED" \
  "cargo-outdated"
# This check is informational; it does not fail the release
if [[ $? -eq 0 ]]; then
  # it passed (no outdated or tool missing) – we don't count as pass/fail
  :;
else
  warn "Some dependencies have newer versions (not a blocker)"
fi

# ── I. Release build ────────────────────────────────────────────────────────
step "H. cargo build --release --locked --bin $BIN_NAME"
if run_cmd "cargo build --release --locked --bin \"$BIN_NAME\"" "release build"; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1)); FAILED_STEPS+=("release build")
fi

# ── J. Binary sanity ────────────────────────────────────────────────────────
step "I. Binary exists and is executable"
BINARY="target/release/$BIN_NAME"
if [[ -x "$BINARY" ]]; then
  SIZE=$(du -h "$BINARY" 2>/dev/null | awk '{print $1}' || stat -c %s "$BINARY" 2>/dev/null || echo "unknown")
  SHA=$(sha256sum "$BINARY" | awk '{print $1}')
  info "Binary: $BINARY ($SIZE)"
  info "SHA256: $SHA"
  pass "binary sanity"
  PASS=$((PASS+1))
else
  fail "binary not found at $BINARY"
  FAIL=$((FAIL+1)); FAILED_STEPS+=("binary exists")
fi

# ── K. Determinism golden vectors ───────────────────────────────────────────
step "J. Determinism tests (golden vectors)"
if run_cmd "cargo test --locked determinism" "determinism golden vectors"; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1)); FAILED_STEPS+=("determinism")
fi

# ── L. Protocol version tests ───────────────────────────────────────────────
step "K. Protocol version tests"
if run_cmd "cargo test --locked test_version_for_height test_validate_block_version test_is_supported" "protocol version"; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1)); FAILED_STEPS+=("protocol version")
fi

# ── M. Working directory clean (git) ────────────────────────────────────────
if [[ -d .git ]]; then
  step "L. Check for uncommitted changes"
  if [[ -z "$(git status --porcelain)" ]]; then
    pass "working directory clean"
    PASS=$((PASS+1))
  else
    warn "Uncommitted changes detected (not a blocker for release but recommended to commit)"
    # Not counted as failure
  fi
else
  warn "Not a git repository, skipping uncommitted changes check"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "  SUMMARY: $PASS passed, $FAIL failed"
echo "  Duration: ${DURATION}s"
if [[ $FAIL -gt 0 ]]; then
  echo "  ❌ STATUS: NOT READY FOR RELEASE"
  echo "  Failed steps: ${FAILED_STEPS[*]}"
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    jq -n \
      --arg status "FAIL" \
      --arg pass "$PASS" \
      --arg fail "$FAIL" \
      --arg duration "$DURATION" \
      --argjson steps "$(printf '%s\n' "${FAILED_STEPS[@]}" | jq -R . | jq -s .)" \
      '{status: $status, passed: $pass, failed: $fail, duration: $duration, failed_steps: $steps}'
  fi
  exit 1
else
  echo "  ✅ STATUS: READY FOR RELEASE"
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    jq -n \
      --arg status "PASS" \
      --arg pass "$PASS" \
      --arg fail "$FAIL" \
      --arg duration "$DURATION" \
      '{status: $status, passed: $pass, failed: $fail, duration: $duration}'
  fi
  exit 0
fi
