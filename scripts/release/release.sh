#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-iona-node}"
cargo build --release --locked --bin "${BIN}"
sha256sum "target/release/${BIN}" | tee "target/release/${BIN}.sha256"
echo "Built: target/release/${BIN}"
