# IONA Ultra (v24.5.0)

This release is a **single-shot full upgrade** that adds the missing production/enterprise primitives on top of v28.

## 1) Encrypted keystore (at-rest)

Set in `config.toml`:

```toml
[node]
keystore = "encrypted"
keystore_password_env = "IONA_KEYSTORE_PASSWORD"
```

Then export the password before starting the node:

```bash
export IONA_KEYSTORE_PASSWORD='a-strong-passphrase'
./target/release/iona-node --config config.toml
```

- First start generates a deterministic demo key (from `seed`) and stores it encrypted in `data_dir/keys.enc`.
- Subsequent starts load and decrypt `keys.enc`.

> Note: this is a minimal keystore meant to be easy to audit. For highest security, use an HSM/KMS/remote signer.

## 2) Local snapshots + restore on startup

`storage` section:

```toml
[storage]
enable_snapshots = true
snapshot_every_n_blocks = 500
snapshot_keep = 10
snapshot_zstd_level = 3
```

- Snapshots are written to `data_dir/snapshots/` as `state_<height>.json.zst`.
- On startup, if `state_full.json` is missing, the node restores it from the latest snapshot.

This enables practical **fast sync by file copy** in private networks:

1. Copy a recent snapshot directory from a healthy node.
2. Place it under `data_dir/snapshots/`.
3. Start the new node; it will restore `state_full.json` automatically.

## 3) OpenTelemetry tracing (optional)

Build with:

```bash
cargo build --release --features otel
```

Then enable in config:

```toml
[observability]
enable_otel = true
otel_endpoint = "http://127.0.0.1:4317"
service_name = "iona-node"
```

This exports distributed traces via **OTLP** to collectors like OpenTelemetry Collector / Jaeger / Tempo.

## 4) What is still intentionally out-of-scope

- Full remote-signer protocol and HSM integrations (design varies per environment).
- Full state-sync over P2P (snapshots are local + file-copy based).
- A full network simulator is best implemented as a dedicated harness; see `tests/simnet.rs` scaffold.
