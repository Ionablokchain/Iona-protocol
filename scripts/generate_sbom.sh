#!/usr/bin/env bash
set -euo pipefail

# Generates a CycloneDX SBOM + SHA256 hashes for release artifacts.
# Requires: cargo install cargo-cyclonedx

SBOM_OUT=${1:-sbom.cdx.json}
DIST_DIR=${2:-dist}

echo "=== Generating SBOM ==="
if cargo cyclonedx --help &>/dev/null; then
    cargo cyclonedx --format json --output "$SBOM_OUT"
    echo "Wrote SBOM: $SBOM_OUT"
else
    echo "WARN: cargo-cyclonedx not installed, skipping SBOM"
    echo "Install with: cargo install cargo-cyclonedx"
fi

echo ""
echo "=== Generating SHA256 hashes ==="
if [ -d "$DIST_DIR" ]; then
    echo "Using existing dist directory: $DIST_DIR"
else
    echo "No dist directory found. Building iona-node into $DIST_DIR..."
    mkdir -p "$DIST_DIR"
    cargo build --release --locked --bin iona-node
    cp target/release/iona-node "$DIST_DIR/"
fi

# Generate SHA256SUMS.txt
(cd "$DIST_DIR" && {
    for f in *; do
        if [ -f "$f" ]; then
            if command -v sha256sum &>/dev/null; then
                sha256sum "$f"
            else
                shasum -a 256 "$f"
            fi
        fi
    done > SHA256SUMS.txt
})
echo "Wrote: $DIST_DIR/SHA256SUMS.txt"
cat "$DIST_DIR/SHA256SUMS.txt"

# Copy SBOM if generated
if [ -f "$SBOM_OUT" ]; then
    cp "$SBOM_OUT" "$DIST_DIR/"
    echo "Copied SBOM to $DIST_DIR/"
fi

echo ""
echo "=== Done ==="
