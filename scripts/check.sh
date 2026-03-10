#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IONA Release Checklist                                                     ║
# ║                                                                             ║
# ║  Run this script before every push / zip / release.                         ║
# ║  All steps must pass — if any fail, the build is NOT safe to ship.          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

BIN_NAME="${BIN_NAME:-iona-node}"
PASS=0
FAIL=0

# Colors (optional)
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

step() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  STEP: $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

pass() {
  echo -e "  ${GREEN}[PASS]${NC} $1"
  PASS=$((PASS + 1))
}

fail() {
  echo -e "  ${RED}[FAIL]${NC} $1" >&2
  FAIL=$((FAIL + 1))
}

# ── A. Code formatting ──────────────────────────────────────────────────────

step "A. cargo fmt --check"
if cargo fmt --check 2>/dev/null; then
  pass "formatting"
else
  fail "formatting (run 'cargo fmt' to fix)"
fi

# ── B. Lint ──────────────────────────────────────────────────────────────────

step "B. cargo clippy"
if cargo clippy --locked -- -D warnings 2>&1; then
  pass "clippy"
else
  fail "clippy warnings/errors found"
fi

# ── C. Tests ─────────────────────────────────────────────────────────────────

step "C. cargo test --locked"
if cargo test --locked 2>&1; then
  pass "tests"
else
  fail "one or more tests failed"
fi

# ── D. Release build ────────────────────────────────────────────────────────

step "D. cargo build --release --locked --bin $BIN_NAME"
if cargo build --release --locked --bin "$BIN_NAME" 2>&1; then
  pass "release build"
else
  fail "release build failed"
fi

# ── E. Binary sanity ────────────────────────────────────────────────────────

step "E. Binary exists and is executable"
BINARY="target/release/$BIN_NAME"
if [[ -x "$BINARY" ]]; then
  SIZE=$(du -h "$BINARY" | awk '{print $1}')
  # Portable SHA256
  if command -v sha256sum >/dev/null 2>&1; then
    SHA=$(sha256sum "$BINARY" | awk '{print $1}')
  else
    SHA=$(shasum -a 256 "$BINARY" | awk '{print $1}')
  fi
  echo "  binary: $BINARY ($SIZE)"
  echo "  sha256: $SHA"
  pass "binary sanity"
else
  fail "binary not found at $BINARY"
fi

# ── F. Determinism golden vectors ────────────────────────────────────────────

step "F. Determinism tests"
# Run only tests that contain "determinism" and ensure at least one runs
OUTPUT=$(cargo test --locked determinism -- --nocapture 2>&1)
if echo "$OUTPUT" | grep -q "running 1 test"; then
  pass "determinism golden vectors"
else
  echo "$OUTPUT" # Show output for debugging
  fail "determinism tests failed or no tests found"
fi

# ── G. Protocol version check ───────────────────────────────────────────────

step "G. Protocol version check"
# Run exact test names (if they exist)
TESTS=("test_version_for_height" "test_validate_block_version" "test_is_supported")
FAILED=0
for TEST in "${TESTS[@]}"; do
  if cargo test --locked "$TEST" --exact --nocapture 2>&1; then
    echo "  [OK] $TEST"
  else
    echo "  [FAIL] $TEST"
    FAILED=$((FAILED + 1))
  fi
done
if [[ $FAILED -eq 0 ]]; then
  pass "protocol version"
else
  fail "protocol version tests failed"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "  RESULTS: $PASS passed, $FAIL failed"
if [[ $FAIL -gt 0 ]]; then
  echo "  STATUS: NOT READY FOR RELEASE"
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  exit 1
else
  echo "  STATUS: READY FOR RELEASE"
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  exit 0
fi
