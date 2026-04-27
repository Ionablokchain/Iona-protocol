#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IONA Release Checklist                                                     ║
# ║                                                                             ║
# ║  Run this script before every push / zip / release.                         ║
║  All steps must pass — if any fail, the build is NOT safe to ship.           ║
║                                                                             ║
║  Environment variables:                                                     ║
║    BIN_NAME      - name of the binary to build (default: iona-node)         ║
║    SKIP_*        - set to 1 to skip a section (e.g., SKIP_DOC=1)           ║
║    RUSTFLAGS     - passed to cargo (default: "-D warnings")                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

# ── Configuration ────────────────────────────────────────────────────────────

BIN_NAME="${BIN_NAME:-iona-node}"
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"
PASS=0
FAIL=0
START_TIME=$(date +%s)

# Colors for better readability (if terminal supports)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    NC='\033[0m' # No Color
else
    GREEN=''; RED=''; YELLOW=''; NC=''
fi

# ── Helper functions ─────────────────────────────────────────────────────────

step() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  STEP: $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
}

pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}[FAIL]${NC} $1" >&2
    FAIL=$((FAIL + 1))
}

warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1" >&2
}

# Check if a command exists
require_cmd() {
    if ! command -v "$1" &> /dev/null; then
        warn "$1 not installed; skipping related checks"
        return 1
    fi
    return 0
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

# ── C. Tests (including determinism and protocol) ────────────────────────────

step "C. cargo test --locked"
if cargo test --locked 2>&1; then
    pass "tests"
else
    fail "one or more tests failed"
fi

# ── D. Documentation build (ensures no warnings) ─────────────────────────────

if [[ "${SKIP_DOC:-0}" != "1" ]]; then
    step "D. cargo doc --no-deps --document-private-items"
    if RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items 2>&1; then
        pass "documentation"
    else
        fail "documentation warnings/errors found"
    fi
else
    warn "SKIP_DOC is set; skipping documentation build"
fi

# ── E. Security audit (cargo audit) ──────────────────────────────────────────

if [[ "${SKIP_AUDIT:-0}" != "1" ]] && require_cmd "cargo-audit"; then
    step "E. cargo audit"
    if cargo audit 2>&1; then
        pass "audit"
    else
        fail "security vulnerabilities found"
    fi
else
    warn "Skipping cargo audit (not installed or SKIP_AUDIT set)"
fi

# ── F. License and dependency checks (cargo deny) ────────────────────────────

if [[ "${SKIP_DENY:-0}" != "1" ]] && require_cmd "cargo-deny"; then
    step "F. cargo deny check"
    if cargo deny check 2>&1; then
        pass "deny checks (licenses, bans, sources)"
    else
        fail "cargo deny violations found"
    fi
else
    warn "Skipping cargo deny (not installed or SKIP_DENY set)"
fi

# ── G. Fuzzing (compile all targets to ensure they build) ────────────────────

if [[ "${SKIP_FUZZ:-0}" != "1" ]] && require_cmd "cargo-fuzz"; then
    step "G. fuzz targets (compile only)"
    # This compiles all fuzz targets without running them
    if cargo fuzz build --all 2>&1; then
        pass "fuzz targets compile"
    else
        fail "fuzz targets failed to compile"
    fi
else
    warn "Skipping fuzz (cargo-fuzz not installed or SKIP_FUZZ set)"
fi

# ── H. Release build ─────────────────────────────────────────────────────────

step "H. cargo build --release --locked --bin $BIN_NAME"
if cargo build --release --locked --bin "$BIN_NAME" 2>&1; then
    pass "release build"
else
    fail "release build failed"
fi

# ── I. Binary sanity ─────────────────────────────────────────────────────────

step "I. Binary exists and is executable"
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

# ── J. Determinism golden vectors ────────────────────────────────────────────

step "J. Determinism tests (golden vectors)"
if cargo test --locked determinism 2>&1; then
    pass "determinism golden vectors"
else
    fail "determinism tests failed"
fi

# ── K. Protocol version tests ────────────────────────────────────────────────

step "K. Protocol version tests"
if cargo test --locked test_version_for_height test_validate_block_version test_is_supported 2>&1; then
    pass "protocol version"
else
    fail "protocol version tests failed"
fi

# ── L. Check for uncommitted changes (optional) ──────────────────────────────

if [[ -n "$(git status --porcelain)" ]]; then
    warn "Uncommitted changes detected. Consider committing before release."
else
    pass "working directory clean"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "  Duration: ${DURATION}s"
if [[ $FAIL -gt 0 ]]; then
    echo "  STATUS: NOT READY FOR RELEASE"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    exit 1
else
    echo "  STATUS: READY FOR RELEASE"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    exit 0
fi
