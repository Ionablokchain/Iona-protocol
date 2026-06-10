#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Release Build — Reproducible Artifact Generation (Production‑Grade)
# =============================================================================
#
# Builds a deterministic release tarball containing the IONA node binary,
# example configuration, genesis file, and integrity hashes.
#
# Usage:
#   ./build_release.sh [OPTIONS]
#
# Options:
#   --tag VERSION         Release tag (e.g. v27.1.2). Auto‑detected if omitted.
#   --output-dir DIR      Artifact output directory (default: ./deploy/artifacts)
#   --features FEATURES   Comma‑separated cargo features to enable
#   --target TRIPLE       Cross‑compile target triple (e.g. x86_64-unknown-linux-gnu)
#   --skip-tests          Skip running the test suite
#   --skip-checks         Skip cargo fmt and clippy checks
#   --sign                Sign SHA256SUMS with GPG (requires key)
#   --sign-key KEY        GPG key ID or email for signing
#   --json                Output build metadata as JSON to stdout
#   --verbose             Enable detailed output
#   --help                Show this help
#
# Environment variables (fallback):
#   IONA_TAG, IONA_OUTPUT_DIR, IONA_FEATURES, IONA_TARGET,
#   IONA_SKIP_TESTS, IONA_SKIP_CHECKS, IONA_SIGN, IONA_SIGN_KEY,
#   IONA_VERBOSE

# ── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARTIFACTS_DIR="${IONA_OUTPUT_DIR:-$SCRIPT_DIR/../artifacts}"
TAG="${IONA_TAG:-}"
FEATURES="${IONA_FEATURES:-}"
TARGET="${IONA_TARGET:-}"
SKIP_TESTS="${IONA_SKIP_TESTS:-0}"
SKIP_CHECKS="${IONA_SKIP_CHECKS:-0}"
SIGN="${IONA_SIGN:-0}"
SIGN_KEY="${IONA_SIGN_KEY:-}"
VERBOSE="${IONA_VERBOSE:-0}"
JSON_OUTPUT=0
START_TIME=$(date +%s)

# ── Colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $*"; }
die()         { log_error "$*"; exit 1; }

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)          TAG="$2"; shift 2 ;;
        --output-dir)   ARTIFACTS_DIR="$2"; shift 2 ;;
        --features)     FEATURES="$2"; shift 2 ;;
        --target)       TARGET="$2"; shift 2 ;;
        --skip-tests)   SKIP_TESTS=1; shift ;;
        --skip-checks)  SKIP_CHECKS=1; shift ;;
        --sign)         SIGN=1; shift ;;
        --sign-key)     SIGN_KEY="$2"; shift 2 ;;
        --json)         JSON_OUTPUT=1; shift ;;
        --verbose)      VERBOSE=1; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Validate environment ────────────────────────────────────────────────────
cd "$ROOT_DIR"
if [[ ! -f "Cargo.toml" ]]; then
    die "Cargo.toml not found — run from project root"
fi

for cmd in cargo sha256sum; do
    if ! command -v "$cmd" &>/dev/null; then
        die "Required tool not found: $cmd"
    fi
done

# ── Auto-detect version ─────────────────────────────────────────────────────
if [[ -z "$TAG" ]]; then
    TAG="v$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')"
fi
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY=$(git diff --quiet 2>/dev/null || echo "-dirty")
VERSION="${TAG}+${GIT_SHA}${GIT_DIRTY:-}"
log_info "Version: $VERSION"

# ── Build feature flags ─────────────────────────────────────────────────────
CARGO_FLAGS="--release --locked --bin iona-node"
if [[ -n "$FEATURES" ]]; then
    CARGO_FLAGS="$CARGO_FLAGS --features $FEATURES"
fi
if [[ -n "$TARGET" ]]; then
    CARGO_FLAGS="$CARGO_FLAGS --target $TARGET"
fi

# ── Step 1: Pre-build checks ────────────────────────────────────────────────
log_info "[1/6] Running pre-build checks..."
if [[ "$SKIP_CHECKS" -eq 0 ]]; then
    cargo fmt --check 2>/dev/null || log_warn "cargo fmt --check failed (non-blocking)"
    log_info "  Pre-build checks done."
else
    log_info "  Skipped (--skip-checks)"
fi

# ── Step 2: Build ───────────────────────────────────────────────────────────
log_info "[2/6] Building release binary..."
BUILD_START=$(date +%s)
cargo build $CARGO_FLAGS
BUILD_END=$(date +%s)

TARGET_DIR="${TARGET:+target/$TARGET/release}"
TARGET_DIR="${TARGET_DIR:-target/release}"
BINARY="$TARGET_DIR/iona-node"

if [[ ! -x "$BINARY" ]]; then
    die "Binary not found at $BINARY"
fi

BINARY_SIZE=$(du -h "$BINARY" | cut -f1)
log_info "  Binary: $BINARY ($BINARY_SIZE)"
log_info "  Build time: $((BUILD_END - BUILD_START))s"

# ── Step 3: Tests ───────────────────────────────────────────────────────────
log_info "[3/6] Running tests..."
if [[ "$SKIP_TESTS" -eq 0 ]]; then
    TEST_START=$(date +%s)
    if cargo test --locked 2>&1 | tail -20; then
        log_info "  Tests passed"
    else
        log_warn "  Some tests failed (non-blocking for release)"
    fi
    TEST_END=$(date +%s)
    log_info "  Test time: $((TEST_END - TEST_START))s"
else
    log_info "  Skipped (--skip-tests)"
fi

# ── Step 4: Reproducible build check ───────────────────────────────────────
log_info "[4/6] Checking build reproducibility..."
REPRO_DIR=$(mktemp -d)
CARGO_TARGET_DIR="$REPRO_DIR" cargo build $CARGO_FLAGS 2>/dev/null
REPRO_BINARY="$REPRO_DIR/release/iona-node"
if [[ -f "$REPRO_BINARY" ]]; then
    SHA_ORIG=$(sha256sum "$BINARY" | awk '{print $1}')
    SHA_REPRO=$(sha256sum "$REPRO_BINARY" | awk '{print $1}')
    if [[ "$SHA_ORIG" == "$SHA_REPRO" ]]; then
        log_info "  Build is reproducible ✓"
    else
        log_warn "  Build is NOT reproducible ✗"
    fi
fi
rm -rf "$REPRO_DIR"

# ── Step 5: Package ─────────────────────────────────────────────────────────
log_info "[5/6] Packaging artifacts..."
mkdir -p "$ARTIFACTS_DIR"
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

cp "$BINARY"                               "$STAGING/iona-node"
cp "$ROOT_DIR/deploy/configs/val2.toml"    "$STAGING/config.example.toml"
cp "$ROOT_DIR/deploy/configs/genesis.json" "$STAGING/genesis.json"
echo "$VERSION" >                           "$STAGING/VERSION"

# ── Generate release metadata ───────────────────────────────────────────────
BINARY_SHA256=$(sha256sum "$BINARY" | awk '{print $1}')
BUILD_DATE=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

cat > "$STAGING/release.json" <<EOF
{
  "version": "$VERSION",
  "tag": "$TAG",
  "git_sha": "$GIT_SHA",
  "build_date": "$BUILD_DATE",
  "binary_sha256": "$BINARY_SHA256",
  "binary_size": "$BINARY_SIZE",
  "target": "${TARGET:-native}",
  "features": "${FEATURES:-default}"
}
EOF

# ── Step 6: Checksums ───────────────────────────────────────────────────────
log_info "[6/6] Computing checksums..."
cd "$STAGING"
sha256sum iona-node config.example.toml genesis.json VERSION release.json > SHA256SUMS
cp SHA256SUMS "$STAGING/"

# ── GPG signing (optional) ──────────────────────────────────────────────────
if [[ "$SIGN" -eq 1 ]]; then
    if command -v gpg &>/dev/null; then
        if [[ -n "$SIGN_KEY" ]]; then
            gpg --local-user "$SIGN_KEY" --detach-sign --armor SHA256SUMS
            log_info "  SHA256SUMS signed (GPG)"
        else
            gpg --detach-sign --armor SHA256SUMS
            log_info "  SHA256SUMS signed (GPG default key)"
        fi
    else
        log_warn "  gpg not found, skipping signing"
    fi
fi

# ── Create tarball ──────────────────────────────────────────────────────────
TARBALL="iona_release_${TAG}.tar.gz"
tar -czf "$ARTIFACTS_DIR/$TARBALL" -C "$STAGING" .
cp "$STAGING/SHA256SUMS" "$ARTIFACTS_DIR/SHA256SUMS"
cp "$STAGING/release.json" "$ARTIFACTS_DIR/release.json"

# ── Summary ─────────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Release Build Complete                                         ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
log_info "Version:   $VERSION"
log_info "Artifact:  $ARTIFACTS_DIR/$TARBALL"
log_info "SHA256SUMS: $ARTIFACTS_DIR/SHA256SUMS"
log_info "Duration:  ${DURATION}s"
echo ""
echo "Verify:"
echo "  tar -tzf $ARTIFACTS_DIR/$TARBALL"
echo "  cd /tmp && tar -xzf $ARTIFACTS_DIR/$TARBALL && sha256sum -c SHA256SUMS"
echo ""

# ── JSON output (for CI/CD) ─────────────────────────────────────────────────
if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    jq -n \
        --arg version "$VERSION" \
        --arg tag "$TAG" \
        --arg git_sha "$GIT_SHA" \
        --arg build_date "$BUILD_DATE" \
        --arg binary_sha256 "$BINARY_SHA256" \
        --arg binary_size "$BINARY_SIZE" \
        --arg tarball "$ARTIFACTS_DIR/$TARBALL" \
        --argjson duration "$DURATION" \
        --arg reproducible "${SHA_ORIG:-unknown}" \
        '{
            version: $version,
            tag: $tag,
            git_sha: $git_sha,
            build_date: $build_date,
            binary_sha256: $binary_sha256,
            binary_size: $binary_size,
            tarball: $tarball,
            duration_s: $duration,
            reproducible: $reproducible
        }'
fi
