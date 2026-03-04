#!/usr/bin/env bash
set -euo pipefail
#
# IONA Release Build — reproducible artifact generation.
#
# Usage:
#   ./deploy/scripts/build_release.sh
#   ./deploy/scripts/build_release.sh --tag v27.1.2
#
# Output:
#   deploy/artifacts/iona_release_<tag>.tar.gz
#   deploy/artifacts/SHA256SUMS
#
# The tarball contains:
#   iona-node              (release binary)
#   config.example.toml    (reference config)
#   genesis.json           (reference genesis)
#   SHA256SUMS             (integrity hashes)
#   VERSION                (version string)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"

# Parse args
TAG=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --tag) TAG="$2"; shift 2 ;;
        *)     echo "Unknown: $1"; exit 1 ;;
    esac
done

# Auto-detect version from Cargo.toml if no tag
if [[ -z "$TAG" ]]; then
    TAG="v$(grep '^version' "$ROOT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')"
fi

GIT_SHA=$(cd "$ROOT_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION="${TAG}+${GIT_SHA}"

echo "=== IONA Release Build ==="
echo "  Version:  $VERSION"
echo "  Root:     $ROOT_DIR"
echo "  Output:   $ARTIFACTS_DIR"
echo ""

# Step 1: Pre-build checks
echo "[1/5] Running pre-build checks..."
cd "$ROOT_DIR"
cargo fmt --check 2>/dev/null || echo "  WARN: cargo fmt --check failed (non-blocking)"
# clippy is advisory, don't block release on it
echo "  Pre-build checks done."

# Step 2: Build
echo "[2/5] Building release binary..."
cargo build --release --locked --bin iona-node
BINARY="$ROOT_DIR/target/release/iona-node"

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: Binary not found at $BINARY"
    exit 1
fi

echo "  Binary: $BINARY ($(du -h "$BINARY" | cut -f1))"

# Step 3: Run tests
echo "[3/5] Running tests..."
cargo test --locked 2>&1 | tail -20
echo "  Tests done."

# Step 4: Package
echo "[4/5] Packaging artifact..."
mkdir -p "$ARTIFACTS_DIR"
STAGING=$(mktemp -d)

cp "$BINARY"                              "$STAGING/iona-node"
cp "$ROOT_DIR/deploy/configs/val2.toml"   "$STAGING/config.example.toml"
cp "$ROOT_DIR/deploy/configs/genesis.json" "$STAGING/genesis.json"
echo "$VERSION" >                          "$STAGING/VERSION"

# Step 5: Checksums
echo "[5/5] Computing checksums..."
cd "$STAGING"
sha256sum iona-node config.example.toml genesis.json VERSION > SHA256SUMS
cp SHA256SUMS "$STAGING/"

# Create tarball
TARBALL="iona_release_${TAG}.tar.gz"
tar -czf "$ARTIFACTS_DIR/$TARBALL" -C "$STAGING" .

# Also copy SHA256SUMS to artifacts dir
cp "$STAGING/SHA256SUMS" "$ARTIFACTS_DIR/SHA256SUMS"

# Cleanup
rm -rf "$STAGING"

echo ""
echo "=== Release Build Complete ==="
echo "  Artifact: $ARTIFACTS_DIR/$TARBALL"
echo "  Checksum: $ARTIFACTS_DIR/SHA256SUMS"
echo "  Version:  $VERSION"
echo ""
echo "Verify:"
echo "  tar -tzf $ARTIFACTS_DIR/$TARBALL"
echo "  cd /tmp && tar -xzf $ARTIFACTS_DIR/$TARBALL && sha256sum -c SHA256SUMS"
