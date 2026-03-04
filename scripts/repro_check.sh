#!/usr/bin/env bash
set -euo pipefail

# Simple reproducible-build smoke check.
# Builds the release binary twice in separate target dirs and compares sha256.

BIN_NAME=${BIN_NAME:-iona-node}

rm -rf target_repro_a target_repro_b

CARGO_TARGET_DIR=target_repro_a cargo build --release --locked --bin "$BIN_NAME"
sha_a=$(sha256sum "target_repro_a/release/$BIN_NAME" | awk '{print $1}')

CARGO_TARGET_DIR=target_repro_b cargo build --release --locked --bin "$BIN_NAME"
sha_b=$(sha256sum "target_repro_b/release/$BIN_NAME" | awk '{print $1}')

echo "sha256 A: $sha_a"
echo "sha256 B: $sha_b"

if [[ "$sha_a" != "$sha_b" ]]; then
  echo "Repro check FAILED: hashes differ" >&2
  exit 2
fi

echo "Repro check OK"
