# IONA Security Policy

> **Security-first by design.** For the full manifesto — secure defaults, key isolation,
> fuzz-driven hardening, and reproducible builds — see [`docs/SECURITY_FIRST.md`](docs/SECURITY_FIRST.md).

## Supported Versions

| Version | Supported |
|---------|-----------|
| v28.0.x | Yes |
| v27.1.x | Security patches only |
| v27.0.x | Security patches only |
| < v27   | No |

## Reporting a Vulnerability

Please report security issues privately. **Do NOT** open a public GitHub issue.

Include:
- version / commit
- reproduction steps
- impact assessment
- logs if available

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

---

## Formal Safety Properties (UPGRADE_SPEC.md §7)

| Property | Description | Verified By |
|----------|-------------|-------------|
| **S1: No Split Finality** | At most one finalized block per height | `safety::check_no_split_finality()`, TLA+ model |
| **S2: Finality Monotonic** | `finalized_height` never decreases | `safety::check_finality_monotonic()`, TLA+ model |
| **S3: Deterministic PV** | All correct nodes agree on PV(height) | `safety::check_deterministic_pv()`, TLA+ model |
| **S4: State Compatibility** | Old PV not applied after activation | `safety::check_state_compat()`, TLA+ model |
| **M2: Value Conservation** | Token supply conserved across transitions | `safety::check_value_conservation()` |
| **M3: Root Equivalence** | State root unchanged after format migration | `safety::check_root_equivalence()` |

See `formal/upgrade.tla` for the TLA+ model that formally verifies S1-S4.
See `tests/upgrade_sim.rs` for executable conformance tests.

---

## Security Impact of v27.1.0 Update

### Protocol Versioning

**Threat**: Without protocol versioning, a hard fork could split the network if some nodes run incompatible rules.

**Mitigation**:
- Every block header now carries `protocol_version`.
- Nodes reject blocks with unsupported protocol versions.
- Activation height + grace window allow coordinated upgrades without halting.

**Residual risk**: If operators fail to upgrade before `activation_height + grace_blocks`, their nodes will be forked off. This is by design (safety over liveness for non-upgraded nodes).

### Schema Migrations

**Threat**: Corrupted or partial migrations could leave the node in an inconsistent state.

**Mitigation**:
- Migrations are atomic (write to `.tmp` + rename).
- Each step persists progress to `schema.json` before moving to the next.
- Interrupted migrations resume from the last successful step.
- Backup files (`.bak`) created before destructive changes.
- Future-version guard prevents running old binary on new data.

**Residual risk**: Disk full during migration could leave `.tmp` files. Recovery: delete `.tmp` files, restart.

### Node Metadata

**Threat**: Stale or missing metadata could cause a node to operate under wrong assumptions.

**Mitigation**:
- `node_meta.json` is checked at startup for compatibility.
- Atomic writes prevent partial metadata.

---

## Threat Model

### Consensus Safety

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Double-sign | `DoubleSignGuard` with persistent state | Implemented (v24.9) |
| Equivocation evidence | `Evidence::DoubleVote` detection + slashing | Implemented (v24.9) |
| Long-range attack | Weak subjectivity checkpoints | Planned |
| Nothing-at-stake | Slashing for double votes | Implemented |

### Network Security

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Eclipse attack | Peer diversity buckets + inbound gating | Implemented (v24.12) |
| DoS via P2P | Per-protocol rate limits + bandwidth caps | Implemented (v24.3) |
| Gossipsub spam | Topic ACL + per-topic caps + spam scoring | Implemented (v24.12) |
| Sybil | Peer scoring + quarantine escalation | Implemented (v24.4) |

### Cryptographic Security

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Key exposure | Encrypted keystore (AES-256-GCM + PBKDF2) | Implemented (v24.5) |
| Weak randomness | Ed25519 with deterministic key derivation | Implemented |
| Hash collision | BLAKE3 (256-bit) for all hashing | Implemented |

### Build Security

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Supply chain attack | `Cargo.lock` + `--locked` builds | Implemented (v27.0) |
| Non-reproducible builds | `scripts/repro_check.sh` + frozen toolchain | Implemented (v27.0) |
| CI tampering | SLSA provenance + signed releases | Implemented (v24.10) |
| Dependency vulnerabilities | `cargo-audit` + `cargo-deny` in CI | Implemented (v24.1) |

---

## Secure Upgrade Procedure

1. **Verify binary integrity**:
   ```bash
   sha256sum iona-node-v27.1.0
   # Compare with published hash in release notes
   ```

2. **Backup before upgrade**:
   ```bash
   cp -r ./data/node ./data/node.bak.$(date +%s)
   ```

3. **Verify after upgrade**:
   ```bash
   curl http://localhost:9001/health
   # Check: status=ok, height advancing, peers connected
   ```

4. **Monitor for anomalies**:
   - Unexpected consensus stalls
   - Peer count drops
   - Evidence of double-signing in logs

---

## Hardening Notes

This project is a prototype consensus node. Before running with real funds or on an open/public network, complete:
- fuzzing for all decode paths (RPC + P2P) — fuzz targets in `fuzz/fuzz_targets/` run in CI
- connection and message DoS protections — implemented; see `src/rpc_limits.rs`, `src/net/`
- key management (encrypted keys/HSM/KMS) — implemented; see `docs/remote_signer.md`
- upgrade/migration plan + snapshot compatibility guarantees — implemented in v27.1.0+
- formal safety verification — TLA+ model in `formal/upgrade.tla`
- independent security review/audit — **required before mainnet with real funds**

See [`docs/SECURITY_FIRST.md`](docs/SECURITY_FIRST.md) for the full security-first manifesto, including the complete checklist of controls, test evidence, and non-goals.

---

## Key Management

### Production Recommendations

1. **Use encrypted keystore** (`keystore = "encrypted"` in config.toml)
2. **Use environment variables** for passwords (never in config files)
3. **Consider remote signer** for validator keys (`signing.mode = "remote"`)
4. **Rotate keys periodically** (coordinate with network governance)
5. **Never commit key files** to version control

### File Permissions

```bash
chmod 600 data/node/keys.json    # or keys.enc
chmod 700 data/node/             # directory
```
