## Mega++ additions (v24.8.0)
- Resume without boundary truncation: if a download is interrupted mid-chunk, the client requests only the missing tail bytes and verifies the assembled full chunk.
- Peer selection uses height, then throughput probe (256KiB) + RTT to pick the best source.

# P2P State Sync

Când `state_full.json` lipsește la startup și nu există snapshot local, nodul poate descărca automat cel mai recent snapshot de la peers (Request/Response).

## Protocol

- Protocol name: `/iona/state/1.0.0`
- Request types:
  - `Manifest` -> returnează `height`, `total_bytes`, `blake3_hex`
  - `Chunk`    -> returnează bytes de snapshot comprimat (zstd) pe bucăți

Snapshot-ul este fișierul `data_dir/snapshots/state_<HEIGHT>.json.zst`.

## Config

În `config.toml`:

```toml
[network]
enable_p2p_state_sync = true
state_sync_chunk_bytes = 1048576
state_sync_timeout_s = 15
```

## Mega-step: latency peer selection + incremental verify + resume

The P2P state sync client now:

- Requests manifests from multiple peers and measures RTT; it selects the peer set at the best height, preferring the lowest RTT.
- Uses per-chunk blake3 hashes (served in the manifest) to **verify each chunk** as it arrives.
- Supports **resume**: if `data_dir/snapshots/statesync_<height>.zst` exists, it verifies already-downloaded chunks, truncates to the last valid boundary, and continues.
- On timeouts or hash mismatches it automatically **fails over** to the next best peer.

On the serving side, nodes cache chunk hashes in:

- `data_dir/snapshots/state_<height>.statesync.json`

