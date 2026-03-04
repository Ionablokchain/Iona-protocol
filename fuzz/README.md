# Fuzzing (cargo-fuzz)

This repo includes a minimal fuzzing harness for high-risk decoding paths.

## Setup

```bash
cargo install cargo-fuzz
```

## Run

```bash
cargo fuzz run consensus_msg
cargo fuzz run tx_json
```

These targets are intended to harden:
- `bincode` decoding for P2P consensus messages
- `serde_json` decoding for transactions (RPC)
