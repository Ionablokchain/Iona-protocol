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

step() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  STEP: $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

pass() {
  echo "  [PASS] $1"
  PASS=$((PASS + 1))
}

fail() {
  echo "  [FAIL] $1" >&2
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
  SHA=$(sha256sum "$BINARY" | awk '{print $1}')
  echo "  binary: $BINARY ($SIZE)"
  echo "  sha256: $SHA"
  pass "binary sanity"
else
  fail "binary not found at $BINARY"
fi

# ── F. Determinism golden vectors ────────────────────────────────────────────

step "F. Determinism tests"
if cargo test --locked determinism 2>&1; then
  pass "determinism golden vectors"
else
  fail "determinism tests failed"
fi

# ── G. Protocol version check ───────────────────────────────────────────────

step "G. Protocol version check"
if cargo test --locked test_version_for_height test_validate_block_version test_is_supported 2>&1; then
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
