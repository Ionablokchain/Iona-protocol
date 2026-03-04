#!/usr/bin/env bash
set -euo pipefail

# Generates a CycloneDX SBOM + SHA256 hashes for release artifacts.
# Requires: cargo install cargo-cyclonedx

SBOM_OUT=${1:-sbom.cdx.json}
DIST_DIR=${2:-dist}

echo "=== Generating SBOM ==="
if command -v cargo-cyclonedx &>/dev/null || cargo cyclonedx --help &>/dev/null 2>&1; then
    cargo cyclonedx --format json --output "$SBOM_OUT"
    echo "Wrote SBOM: $SBOM_OUT"
else
    echo "WARN: cargo-cyclonedx not installed, skipping SBOM"
    echo "Install with: cargo install cargo-cyclonedx"
fi

echo ""
echo "=== Generating SHA256 hashes ==="
if [ -d "$DIST_DIR" ]; then
    (cd "$DIST_DIR" && sha256sum * > SHA256SUMS.txt 2>/dev/null || shasum -a 256 * > SHA256SUMS.txt)
    echo "Wrote: $DIST_DIR/SHA256SUMS.txt"
    cat "$DIST_DIR/SHA256SUMS.txt"
else
    echo "No dist directory found, building iona-node..."
    mkdir -p "$DIST_DIR"
    cargo build --release --locked --bin iona-node
    cp target/release/iona-node "$DIST_DIR/"
    (cd "$DIST_DIR" && sha256sum * > SHA256SUMS.txt 2>/dev/null || shasum -a 256 * > SHA256SUMS.txt)
    echo "Wrote: $DIST_DIR/SHA256SUMS.txt"
    cat "$DIST_DIR/SHA256SUMS.txt"
fi

if [ -f "$SBOM_OUT" ]; then
    cp "$SBOM_OUT" "$DIST_DIR/" 2>/dev/null || true
fi

echo ""
echo "=== Done ==="
