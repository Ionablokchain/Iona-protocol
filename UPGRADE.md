# IONA Upgrade Guide

> **Formal Specification**: See `spec/upgrade/UPGRADE_SPEC.md` for formal definitions,
> safety invariants, and conformance requirements.
> **Compatibility Matrix**: See `spec/upgrade/compat_matrix.md` for PV/SV/node support.
> **TLA+ Model**: See `formal/upgrade.tla` for formal safety verification.

## Current Version

- **Binary**: v28.0.0
- **Protocol**: v1
- **Schema**: v5

## Quick Reference

| Upgrade Type | Downtime | Coordination | Rollback |
|---|---|---|---|
| **Patch** (v27.0.x -> v27.0.y) | None | Rolling | Always safe |
| **Minor** (v27.x -> v27.y) | None | Rolling | Safe if schema compatible |
| **Major** (v27 -> v28) | None* | Coordinated at activation_height | Before activation only (see UPGRADE_SPEC.md §9) |

\* No downtime if all operators upgrade before the activation height.

---

## Minor Upgrade (Rolling, No Hard Fork)

**Example**: v27.0.0 -> v27.1.0 (schema bump, new RPC fields, no protocol change)

### Prerequisites

1. **Backup your data directory**:
   ```bash
   cp -r ./data/node ./data/node.bak.$(date +%s)
   ```

2. **Check disk space**: migrations may temporarily double state file size during backup creation.

3. **Check RAM**: ensure at least 2x the size of `state_full.json` is available.

### Steps

1. **Stop the node** (graceful):
   ```bash
   kill -SIGTERM $(pidof iona-node)
   # Wait for "shutdown complete" in logs
   ```

2. **Replace the binary**:
   ```bash
   cp iona-node-v27.1.0 /usr/local/bin/iona-node
   chmod +x /usr/local/bin/iona-node
   ```

3. **Start the node**:
   ```bash
   iona-node --config config.toml
   ```
   The node will:
   - Detect the old schema version
   - Run migrations automatically (v3 -> v4)
   - Log progress: `"running schema migrations"`, `"migration step complete"`
   - Resume consensus participation

4. **Verify health**:
   ```bash
   curl http://localhost:9001/health
   # Expected: {"status":"ok","height":...,"peers":...}
   ```

5. **Repeat** for each node in your fleet (one at a time).

### Rollback

- **Before migration**: restore from backup, start old binary.
- **After migration**: the new schema is backward-compatible; old binary will see `schema v4 > v3` and refuse to start. Restore from backup if needed.

---

## Major Upgrade (Protocol Upgrade at Activation Height)

**Example**: v27 -> v28 with `protocol_version` bump from 1 to 2.

### Phase A: Pre-Activation (Rolling Deploy)

1. **Release v28.0.0** with:
   - `SUPPORTED_PROTOCOL_VERSIONS = [1, 2]`
   - `CURRENT_PROTOCOL_VERSION = 2`
   - Activation config:
     ```toml
     [[consensus.protocol_activations]]
     protocol_version = 2
     activation_height = 2_000_000
     grace_blocks = 1000
     ```

2. **Deploy to all nodes** (rolling, no downtime):
   - Each node starts producing v1 blocks (before activation height).
   - Each node can validate both v1 and v2 blocks.

3. **Monitor**:
   ```bash
   # Check all nodes are on the new binary
   curl http://node1:9001/version
   curl http://node2:9001/version
   curl http://node3:9001/version
   ```

### Phase B: Activation

At `height = 2_000_000`:
- Nodes automatically switch to producing v2 blocks.
- v1 blocks are still accepted during the grace window (1000 blocks).
- After `height = 2_001_000`: only v2 blocks accepted.

### Phase C: Post-Activation

- Verify all nodes are producing v2 blocks.
- Monitor for any consensus stalls (validators on old binary).

### Rollback Plan

| Scenario | Action |
|---|---|
| Before activation_height | Roll back binary to v27; safe, no protocol change yet |
| During grace window | Roll back binary; v1 blocks still accepted |
| After grace window | **Cannot roll back** without a coordinated chain halt + snapshot restore |

---

## Storage Migration Details

### Current Migrations

| From | To | Description | Destructive? |
|---|---|---|---|
| v0 | v1 | Create schema.json marker | No |
| v1 | v2 | Normalize state_full.json + stakes.json (add missing fields) | No (creates .bak) |
| v2 | v3 | Migrate flat WAL to segmented WAL | No (rename only) |
| v3 | v4 | Create node_meta.json with protocol version tracking | No |

### Adding a New Migration

1. Create `src/storage/migrations/m00NN_description.rs`
2. Implement `pub fn migrate(data_dir: &str, meta: &mut SchemaMeta) -> io::Result<()>`
3. Register in `MIGRATIONS` array in `src/storage/migrations/mod.rs`
4. Bump `CURRENT_SCHEMA_VERSION` in `src/storage/mod.rs`
5. Add migration arm in `DataDir::run_migration()` match block

### Rules (UPGRADE_SPEC.md §5.2)

- **Never delete user data** -- rename or backup instead.
- **Atomic writes** -- write to `.tmp` then rename.
- **Idempotent** -- `Migrate(sv, sv, DB) = DB` (safe to run twice if interrupted).
- **Crash-safe** -- `migration_state` in `node_meta.json` tracks in-progress migrations.
- **Monotonic** -- SV increases strictly (`sv_old < sv_new`).
- **Logged** -- every step appends to `SchemaMeta.migration_log`.
- **Dual-read** -- node can read old format during migration (UPGRADE_SPEC.md §6.2).

---

## Release Checklist

Before every release, run:

```bash
./scripts/check.sh
```

This runs:
1. `cargo fmt --check` -- formatting
2. `cargo clippy --locked -- -D warnings` -- lint
3. `cargo test --locked` -- all tests
4. `cargo build --release --locked --bin iona-node` -- release binary
5. Binary exists and is executable
6. Determinism golden-vector tests pass
7. Protocol version tests pass

All steps must pass before shipping.

---

## Expected Behavior During Upgrade

### Schema Migration Logs

```
INFO running schema migrations, from=3, to=4
INFO v3 -> v4: node_meta.json created with protocol version tracking
INFO schema migration step complete, version=4
INFO schema fully migrated, version=4
```

### Time Estimates

| Dataset Size | Migration Time |
|---|---|
| < 100 MB | < 1 second |
| 100 MB - 1 GB | 1-5 seconds |
| 1 GB - 10 GB | 5-30 seconds |
| > 10 GB | 30+ seconds (mainly v1->v2 state normalization) |

### Monitoring

- Watch logs for `"schema fully migrated"`.
- Check `/health` endpoint returns 200.
- Verify `height` is advancing (consensus active).
- Check `peers` count matches expected.
