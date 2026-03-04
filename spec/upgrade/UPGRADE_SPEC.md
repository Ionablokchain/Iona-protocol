# IONA Formal Upgrade Specification

**Version**: 1.0
**Applies to**: IONA v27.1.0+
**Status**: Normative

---

## 1. Scope and Definitions

### 1.1 Terms

| Term | Symbol | Definition |
|------|--------|------------|
| **ProtocolVersion** | `PV` | Version of consensus rules, block validity rules, and wire format. Determines how blocks are produced, validated, and executed. |
| **SchemaVersion** | `SV` | Version of the on-disk storage format (state files, WAL, indices, metadata). Independent of PV. |
| **SoftwareVersion** | `SW` | Semver of the node binary (e.g. `27.1.0`). Operationally relevant but NOT protocol-significant. Two binaries with different SW may implement the same PV. |
| **ActivationPoint** | `H` | Block height at which a new PV becomes mandatory. All correct nodes MUST produce PV_new blocks at height >= H. |
| **GraceWindow** | `G` | Number of blocks after H during which PV_old blocks are still accepted (tolerance for late upgraders). After H+G, PV_old is rejected. |
| **SupportedPV** | `SPV` | Set of protocol versions a binary can validate/execute: `{k..m}`. |
| **SupportedSV** | `SSV` | Set of schema versions a binary can read/migrate: `{a..b}`. |

### 1.2 Invariants (Definitional)

1. **PV is deterministic from height**: `PV(height)` is a pure function of `height` and the activation schedule. It does NOT depend on local config, time, or node identity.

2. **PV uniqueness**: For any given height, exactly one PV is active: `forall h: exists! pv: PV(h) = pv`.

3. **PV monotonicity**: `PV(h1) <= PV(h2)` when `h1 <= h2`. Protocol versions never decrease.

4. **SV monotonicity**: Schema versions increase strictly during migration: `SV_old < SV_new`.

5. **SW independence**: `SW` does not appear in block headers, wire messages, or consensus state. It is metadata only.

### 1.3 Formal PV Function

```
PV(height) = max { a.pv | a in Activations, a.height <= height or a.height = None }
```

Where `Activations` is the ordered set of `(pv, height, grace)` tuples from genesis config or on-chain governance.

---

## 2. Compatibility Matrix

### 2.1 Node Support Declaration

Each binary declares:

```rust
SupportedPV = {k..m}     // e.g. {1, 2}
SupportedSV = {a..b}     // e.g. {0..4}
CurrentPV   = m           // highest PV this binary produces
CurrentSV   = b           // current on-disk schema
```

### 2.2 Accept Rules

| Condition | Accept Block? | Produce Block? |
|-----------|--------------|----------------|
| `height < H` | Only if `block.pv == PV_old` | `PV_old` |
| `height >= H` and `height < H + G` | `PV_old` OR `PV_new` | `PV_new` |
| `height >= H + G` | Only if `block.pv == PV_new` | `PV_new` |
| `block.pv not in SupportedPV` | REJECT | N/A |

### 2.3 Formal Accept Predicate

```
AcceptBlock(block, state) =
    block.pv in SupportedPV
    AND (
        block.pv == PV(block.height)
        OR (block.pv == PV(block.height - 1)
            AND exists a in Activations:
                a.pv == PV(block.height)
                AND a.height is Some(ah)
                AND block.height < ah + a.grace)
    )
```

### 2.4 Version Compatibility Table (Current)

| Binary Version | SupportedPV | SupportedSV | CurrentPV | CurrentSV |
|---------------|-------------|-------------|-----------|-----------|
| v27.0.x | {1} | {0..3} | 1 | 3 |
| v27.1.x | {1} | {0..4} | 1 | 4 |
| v28.0.x (future) | {1, 2} | {0..5} | 2 | 5 |

See also: `spec/upgrade/compat_matrix.md` for the full matrix.

---

## 3. Activation Rule (Protocol Upgrade)

### 3.1 Source of Truth for Activation

The activation height `H` is determined by one of (in priority order):

1. **Genesis parameter**: `H` fixed in genesis config (immutable after chain start).
2. **On-chain parameter**: `H` determined by finalized state (governance vote).
3. **Hard-coded release**: `H` embedded in binary (least flexible, used for testnets).

For IONA v27, the source is the **config parameter** `consensus.protocol_activations`:

```toml
[[consensus.protocol_activations]]
protocol_version = 2
activation_height = 2_000_000
grace_blocks = 1000
```

### 3.2 Producer Rule (Formal)

```
ProducerRule(height):
    header.protocol_version = PV(height)
```

A block producer MUST set `header.protocol_version` to `PV(height)`. Producing a block with any other PV is a protocol violation.

### 3.3 Validator Rule (Formal)

```
ValidateBlock(block):
    REQUIRE block.header.protocol_version in SupportedPV
    REQUIRE AcceptBlock(block, state)     // see section 2.3
    REQUIRE block.header.protocol_version == PV(block.header.height)
        OR InGraceWindow(block)
```

Where:
```
InGraceWindow(block) =
    exists a in Activations:
        a.pv == PV(block.header.height)
        AND a.height is Some(ah)
        AND block.header.height >= ah
        AND block.header.height < ah + a.grace
        AND block.header.protocol_version == PV(ah - 1)
```

### 3.4 Grace Window Semantics

- `G = 0`: No grace. Old-PV blocks are rejected immediately at activation height.
- `G > 0`: For `G` blocks after `H`, both PV_old and PV_new are accepted.
- Recommendation: `G = 0` for safety-critical upgrades; `G = 1000` for operational convenience.

---

## 4. Wire Compatibility (P2P / RPC)

### 4.1 P2P Message Versioning

Every P2P message carries an implicit protocol version derived from the consensus state:

```
Message = {
    type_id: u8,          // Proposal=0, Vote=1, Evidence=2, BlockReq=3, BlockResp=4
    payload: bytes,       // type-specific content
}
```

**Decode rule**:
```
Decode(type_id, bytes) -> Result<Message, Error>
```

Messages are decoded according to the **receiver's** supported PV set. Unknown `type_id` values are silently ignored (forward compatibility).

### 4.2 Message Forward/Backward Compatibility

| PV Change | Wire Impact | Handling |
|-----------|------------|---------|
| New field in BlockHeader | `#[serde(default)]` ensures old decoders skip it | Backward compatible |
| New message type | Unknown `type_id` ignored by old nodes | Forward compatible |
| Changed field semantics | Requires PV bump + activation | Breaking (coordinated) |
| Removed field | Old nodes read default; new nodes don't write it | Backward compatible |

### 4.3 Handshake / Capability Negotiation

When two nodes connect, they exchange a `Hello` message:

```rust
pub struct Hello {
    pub supported_pv: Vec<u32>,      // e.g. [1, 2]
    pub supported_sv: Vec<u32>,      // e.g. [0, 1, 2, 3, 4]
    pub software_version: String,    // e.g. "27.1.0" (informational)
    pub chain_id: u64,               // must match
    pub genesis_hash: Hash32,        // must match
    pub head_height: u64,            // tip of local chain
    pub head_pv: u32,                // PV of local tip
}
```

**Connection rule**:
```
Connect(local, remote) =
    local.chain_id == remote.chain_id
    AND local.genesis_hash == remote.genesis_hash
    AND intersection(local.supported_pv, remote.supported_pv) != {}
```

If the intersection is empty, the connection is rejected with a descriptive error.

### 4.4 Version Negotiation

After handshake, both nodes use `min(max(local.supported_pv), max(remote.supported_pv))` as the session PV for encoding new messages. This ensures both sides can decode.

---

## 5. Data Model and Schema Upgrade (SV)

### 5.1 On-Disk Metadata

```json
// schema.json
{
    "version": 4,
    "migrated_at": "1740000000",
    "migration_log": [
        "[1740000000] v3 -> v4: node_meta.json created"
    ]
}

// node_meta.json
{
    "schema_version": 4,
    "protocol_version": 1,
    "node_version": "27.1.0",
    "updated_at": "1740000000",
    "migration_state": null
}
```

Fields:
- `schema_version`: Current on-disk SV.
- `protocol_version`: Last PV this node operated under.
- `node_version`: SW version (informational).
- `migration_state`: If non-null, a migration is in progress (crash-resume).

### 5.2 Migration Function (Formal)

```
Migrate: (SV_old, SV_new, DB) -> DB'
```

**Requirements**:

1. **Idempotent**: `Migrate(sv, sv, DB) = DB` (no-op when already at target).
2. **Crash-safe**: Each step persists a checkpoint (`schema.json` updated after each step). If interrupted, `Migrate` resumes from the last checkpoint.
3. **Monotonic**: `SV_old < SV_new` (strictly increasing).
4. **No data loss**: `|keys(DB')| >= |keys(DB)|` (key count never decreases, modulo explicit garbage collection).
5. **Atomic per-step**: Each migration step writes via `.tmp` + `rename()`. A crash mid-step leaves the previous consistent state.

**Formal checkpoint invariant**:
```
After Migrate(v, v+1, DB) succeeds:
    schema.json.version == v + 1
    All files referenced by v+1 exist and are consistent
```

### 5.3 Online vs Offline Migrations

| Migration Type | Blocking? | Dual-Read? | Example |
|---------------|-----------|------------|---------|
| **Startup blocking** | Yes, node waits | No | v0->v1 (schema.json creation) |
| **Background** | No, node starts immediately | Yes | v3->v4 (index building) |
| **Offline** | Node must be stopped | No | (reserved for future destructive changes) |

Current migrations (v0 through v4) are all **startup blocking** but complete in < 1 second for typical datasets.

**Forbidden operations during background migration**:
- Snapshot creation (state may be inconsistent during dual-read window)
- Schema version downgrade

---

## 6. State Transition: Dual-Validate / Dual-Read

### 6.1 Dual-Validate (Protocol)

During the pre-activation window, a node running the new binary can perform **shadow validation**:

```
For height < H:
    REQUIRE ValidatePV_old(block)           // mandatory
    OPTIONAL ValidatePV_new(block)          // shadow, log-only

At height >= H:
    REQUIRE ValidatePV_new(block)           // mandatory
```

Shadow validation is **non-blocking**: failures are logged as warnings but do not reject the block. This allows operators to verify that the new rules work correctly before activation.

### 6.2 Dual-Read (Storage)

When a schema migration changes the storage format:

```
Read(key):
    try read_new_format(key)
    if not found: fallback read_old_format(key)

Write(key, value):
    write_new_format(key, value)
    // old format NOT written (one-way migration)
```

**Transition period**: Dual-read is active from the moment the migration starts until all old-format data has been read at least once (lazy migration) or a background sweep completes.

**Formal invariant**:
```
forall key:
    Read(key) after migration == Read(key) before migration
    // values are preserved, only format changes
```

---

## 7. Safety Properties (Invariants)

### 7.1 Safety Invariants (Must Hold Always)

**S1: No Split Finality**
```
forall h:
    |{b | Finalized(b) AND b.height == h}| <= 1
```
At most one block can be finalized at any height.

**S2: Finality Monotonic**
```
finalized_height(t1) <= finalized_height(t2)  when t1 < t2
```
The finalized height never decreases over time.

**S3: Deterministic PV Selection**
```
forall correct nodes N1, N2:
    PV_N1(height) == PV_N2(height)
```
All correct nodes compute the same PV for any given height. This follows from PV being a pure function of height + activation schedule, where the schedule is either in genesis or finalized state.

**S4: State Compatibility**
```
forall h >= H:
    ApplyBlock_PV_old(block, state) is NOT used
    // Only ApplyBlock_PV_new is applied
```
After activation, the old execution rules are never applied to new blocks.

**S5: Execution Determinism**
```
forall blocks b, states s:
    ApplyBlock(b, s) on node N1 == ApplyBlock(b, s) on node N2
    // regardless of platform, compiler, or timing
```

### 7.2 Migration Invariants

**M1: No State Loss**
```
forall accounts a:
    a in keys(state_before) => a in keys(state_after)
```
Account keys are never deleted by migration (renames/backups are allowed).

**M2: Value Conservation**
```
sum(balances_before) + sum(staked_before) ==
    sum(balances_after) + sum(staked_after) + delta_rewards - delta_slashing
```
Total token supply is conserved across migrations, modulo explicit economic events.

**M3: Root Equivalence (Format Refactors)**
```
If migration is pure format change (no semantic change):
    StateRoot(DB_before) == StateRoot(DB_after)
```
The Merkle state root is identical before and after a format-only migration.

---

## 8. Liveness Assumptions

For a protocol upgrade to succeed, the following must hold:

### 8.1 Synchrony

- **Partial synchrony**: After some unknown GST (Global Stabilization Time), all messages between correct nodes are delivered within bounded time `delta`.
- During the upgrade window, `delta` should be small enough that all nodes see the activation height within `G` blocks.

### 8.2 Byzantine Fault Tolerance

- **Maximum Byzantine fraction**: `f < n/3` where `n` is the total number of validators (by stake weight).
- Specifically: at least `2f + 1` validators must have upgraded before height `H`.

### 8.3 Upgrade Success Condition

```
UpgradeSucceeds(H) =
    |{v | v.upgraded AND v.stake > 0}| >= 2/3 * total_stake
    BEFORE height H is reached
```

If fewer than 2/3 of validators upgrade before `H`, the chain may halt (no quorum for PV_new blocks). This is a **safety-preserving halt**: the chain stops rather than finalizing invalid blocks.

### 8.4 Recovery from Failed Upgrade

If the chain halts due to insufficient upgraded validators:
1. Remaining validators upgrade their binaries.
2. Chain resumes automatically once quorum is restored.
3. No manual intervention needed (no "emergency mode").

---

## 9. Rollback Policy

### 9.1 Rollback Decision Matrix

| Scenario | Rollback? | Data Impact | Procedure |
|----------|-----------|-------------|-----------|
| `height < H` (before activation) | SAFE | None | Replace binary with old version; restart |
| `height in [H, H+G)` (grace window) | CONDITIONAL | Old SV may need restore | Replace binary; restore snapshot if SV changed |
| `height >= H+G` (after grace) | UNSAFE | Chain divergence | Requires coordinated snapshot restore |

### 9.2 Formal Rollback Rules

```
CanRollback(current_height, H, G, SV_changed) =
    current_height < H
    OR (current_height < H + G AND NOT SV_changed)
```

### 9.3 Rollback Procedure

**Before activation (safe)**:
1. Stop node.
2. Replace binary with previous version.
3. If SV was bumped: `cp data/node.bak.* data/node/` (restore backup).
4. Start node. It will resume consensus with PV_old.

**After activation (unsafe)**:
1. **STOP**: This requires coordination with all validators.
2. All validators must agree on a snapshot height `S < H`.
3. All validators restore from snapshot at height `S`.
4. All validators start old binary.
5. Chain resumes from height `S` (blocks `S+1..current` are lost).

### 9.4 Required Artifacts for Rollback

- `data/node.bak.<timestamp>/` — pre-upgrade backup of entire data directory.
- `data/node/schema.json` — records migration history.
- Snapshot at height `< H` (for post-activation rollback).

### 9.5 What is Lost on Rollback

- **Mempool**: All pending transactions are lost (clients must resubmit).
- **Caches**: Peer scores, connection state, rate limit counters.
- **Post-activation blocks**: If rolling back past `H`, blocks at height >= `H` are discarded.

---

## 10. Conformance Tests

### 10.1 Upgrade Simulation Tests (`tests/upgrade_sim.rs`)

Simulates a rolling upgrade across multiple nodes:

1. **Setup**: 5-node network, all on PV=1.
2. **Rolling upgrade**: Upgrade nodes one by one to PV={1,2} binary.
3. **Pre-activation**: All nodes produce PV=1 blocks (even upgraded ones).
4. **At activation height**: Upgraded nodes switch to PV=2.
5. **Verify invariants**:
   - No split finality (S1)
   - Finality monotonic (S2)
   - All correct nodes agree on PV(height) (S3)
   - After activation, only PV=2 blocks are produced (S4)

### 10.2 Golden Vectors (`tests/determinism.rs`)

Fixed inputs produce fixed outputs across all platforms:

- `hash_bytes(b"test")` -> expected 32-byte hash
- `tx_hash(canonical_tx)` -> expected hash
- `tx_root([])` -> expected empty root
- `tx_root([tx1, tx2])` -> expected root
- `receipts_root([r1])` -> expected root
- `block.id()` -> expected block ID
- `state.root()` -> expected state root (order-independent)

### 10.3 Determinism Suite

- Replay blocks `1..N` on two independent nodes -> identical `state_root` at every height.
- No nondeterminism sources: no `HashMap` iteration order in consensus-critical paths, no `SystemTime`, no RNG.
- All hashing uses BLAKE3 (deterministic).
- All serialization uses fixed binary format (not JSON) for consensus-critical data.

### 10.4 Migration Conformance

- Migrate empty DB from v0 to v4 -> no errors.
- Migrate populated DB from v3 to v4 -> `node_meta.json` created.
- Migrate is idempotent: running v3->v4 twice produces identical result.
- Future version guard: binary with SV=4 rejects DB at SV=5.

---

## Appendix A: File Inventory

| File | Purpose |
|------|---------|
| `src/protocol/version.rs` | PV constants, activation logic, validation |
| `src/protocol/wire.rs` | P2P message versioning, Hello handshake |
| `src/protocol/safety.rs` | Safety invariant checks |
| `src/protocol/dual_validate.rs` | Shadow validation for pre-activation |
| `src/storage/meta.rs` | NodeMeta persistence, compatibility check |
| `src/storage/mod.rs` | SchemaMeta, migration runner |
| `src/storage/migrations/` | Ordered migration modules |
| `spec/upgrade/UPGRADE_SPEC.md` | This document |
| `spec/upgrade/compat_matrix.md` | Version compatibility table |
| `formal/upgrade.tla` | TLA+ safety model |
| `tests/upgrade_sim.rs` | Upgrade simulation tests |
| `tests/determinism.rs` | Golden vector tests |

## Appendix B: Change History

| Date | Version | Change |
|------|---------|--------|
| 2026-02-25 | 1.0 | Initial formal specification |
