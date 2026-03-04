# IONA Version Compatibility Matrix

## Protocol Version (PV) x Schema Version (SV) x Software Version (SW)

### Current Release Line

| SW Version | SupportedPV | CurrentPV | SupportedSV | CurrentSV | Notes |
|-----------|-------------|-----------|-------------|-----------|-------|
| v27.0.0 | {1} | 1 | {0..3} | 3 | Baseline: frozen toolchain, locked deps |
| v27.1.0 | {1} | 1 | {0..4} | 4 | + protocol versioning, node_meta.json |
| v28.0.0 (planned) | {1, 2} | 2 | {0..5} | 5 | Major upgrade: new consensus rules |

### Upgrade Path Matrix

| From \ To | v27.0.0 | v27.1.0 | v28.0.0 |
|-----------|---------|---------|---------|
| v27.0.0 | -- | Rolling (SV 3->4) | Rolling then activate at H |
| v27.1.0 | Rollback (restore SV3 backup) | -- | Rolling then activate at H |
| v28.0.0 | Unsafe (needs snapshot < H) | Unsafe (needs snapshot < H) | -- |

### Block Acceptance Rules

```
PV(height) = max { a.pv | a in Activations, a.activation_height <= height or a.activation_height = None }
```

#### Before Activation (height < H)

| Block PV | Node supports {1} | Node supports {1,2} |
|----------|-------------------|---------------------|
| 1 | ACCEPT | ACCEPT |
| 2 | REJECT (unsupported) | REJECT (too early) |

#### At Activation (height = H, grace G > 0)

| Block PV | Node supports {1} | Node supports {1,2} |
|----------|-------------------|---------------------|
| 1 | ACCEPT | ACCEPT (grace) |
| 2 | REJECT (unsupported) | ACCEPT |

#### After Grace (height >= H + G)

| Block PV | Node supports {1} | Node supports {1,2} |
|----------|-------------------|---------------------|
| 1 | ACCEPT (if H not reached) | REJECT (expired) |
| 2 | REJECT (unsupported) | ACCEPT |

### Schema Migration Compatibility

| From SV | To SV | Migration | Blocking? | Reversible? |
|---------|-------|-----------|-----------|-------------|
| 0 | 1 | Create schema.json | Yes (instant) | No (safe: just a marker) |
| 1 | 2 | Normalize state + stakes JSON | Yes (< 1s) | Yes (restore .v1.bak) |
| 2 | 3 | Flat WAL -> segmented WAL | Yes (instant) | No (rename only) |
| 3 | 4 | Create node_meta.json | Yes (instant) | Yes (delete node_meta.json) |

### P2P Handshake Compatibility

| Local PV | Remote PV | Connection? | Session PV |
|----------|-----------|-------------|------------|
| {1} | {1} | YES | 1 |
| {1} | {1,2} | YES | 1 |
| {1,2} | {1,2} | YES | 2 |
| {1} | {2} | NO (empty intersection) | -- |
| {1,2} | {2} | YES | 2 |

### RPC Compatibility

| RPC Field | Added In | Default | Impact on Old Clients |
|-----------|----------|---------|----------------------|
| `block.header.protocol_version` | v27.1.0 | 1 | None (new field, ignored) |
| `node_meta.migration_state` | v27.1.0 | null | None (new field) |
| `/protocol/version` endpoint | v27.1.0 | N/A | 404 on old nodes |
| `/protocol/activations` endpoint | v27.1.0 | N/A | 404 on old nodes |
