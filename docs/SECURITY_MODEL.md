# IONA Blockchain — Security Model Document

**Version:** 27.0.0  
**Date:** 2026-02-25  
**Classification:** Public  

---

## 1. Overview

This document defines the formal security model for the IONA blockchain, covering threat analysis, trust assumptions, cryptographic guarantees, network security, and operational security controls. It serves as the authoritative reference for security audits, penetration testing, and compliance assessments.

---

## 2. Trust Model & Assumptions

### 2.1 Byzantine Fault Tolerance

IONA uses a Tendermint-style BFT consensus protocol with the following assumptions:

| Parameter | Value | Description |
|-----------|-------|-------------|
| Total validators | N | Active validator set size |
| Byzantine tolerance | f < N/3 | Maximum faulty/malicious validators |
| Quorum threshold | 2f + 1 = 2N/3 + 1 | Votes required for finality |
| Network model | Partial synchrony | Messages eventually delivered within unknown bound Delta |

**Safety guarantee:** No two conflicting blocks can be finalized at the same height, provided f < N/3.

**Liveness guarantee:** The chain makes progress if f < N/3 and the network is eventually synchronous.

### 2.2 Cryptographic Assumptions

| Primitive | Algorithm | Security Level | Assumption |
|-----------|-----------|----------------|------------|
| Digital signatures | Ed25519 (RFC 8032) | 128-bit | Discrete log hardness on Curve25519 |
| Hashing | blake3 | 256-bit | Pre-image resistance, collision resistance |
| Symmetric encryption | AES-256-GCM | 256-bit | AES security, GCM authentication |
| Key derivation | PBKDF2-HMAC-SHA256 | Configurable | SHA-256 pre-image resistance |
| EVM addresses | Keccak-256 | 128-bit (collision) | Keccak pre-image resistance |
| Code hashing | SHA-256 | 128-bit (collision) | SHA-256 pre-image resistance |

### 2.3 Network Assumptions

- **Authenticated channels:** All P2P connections use Noise protocol (libp2p) for encryption and authentication
- **No trusted relay:** Nodes communicate peer-to-peer; no single point of trust
- **DNS is untrusted:** Bootnode addresses should use IP where possible; DNS used only for convenience
- **Clock assumptions:** No strict global clock synchrony required; monotonic ordering within jitter window for MEV protection

---

## 3. Threat Model

### 3.1 Adversary Capabilities

| Threat Actor | Capabilities | Mitigations |
|-------------|-------------|-------------|
| **External attacker** | Network-level DoS, message injection, eclipse attacks | Rate limiting, peer diversity, connection limits |
| **Malicious validator (< f)** | Equivocation, withholding, selective inclusion | BFT consensus, double-sign detection, slashing |
| **Colluding validators (< N/3)** | Coordinated equivocation, censorship attempts | Quorum requirement (2/3+1), evidence gossip |
| **Colluding validators (>= N/3)** | Safety violation (finality split) | **Out of model** — system cannot guarantee safety |
| **MEV searcher** | Frontrunning, sandwich attacks, backrunning | Commit-reveal, threshold encryption, fair ordering |
| **Insider (operator)** | Key theft, configuration tampering | Encrypted keystore, HSM/KMS, audit trail |
| **Supply chain** | Dependency compromise | Locked dependencies, SBOM, reproducible builds |

### 3.2 Attack Surface Analysis

```
+------------------------------------------------------------------+
|                     Attack Surface Map                            |
+------------------------------------------------------------------+
|                                                                  |
|  [External]                                                      |
|  +-- P2P port (TCP/7001)                                        |
|  |   +-- Gossipsub message flood           [MITIGATED: rate limit]
|  |   +-- Request-response abuse            [MITIGATED: governor]  |
|  |   +-- Connection exhaustion             [MITIGATED: conn limit]|
|  |   +-- Eclipse attack                    [MITIGATED: diversity] |
|  |   +-- Sybil attack                      [MITIGATED: peer score]|
|  |   +-- Malformed message crash           [MITIGATED: fuzz test] |
|  |                                                                |
|  +-- RPC port (TCP/9001)                                         |
|  |   +-- JSON-RPC injection                [MITIGATED: parsing]   |
|  |   +-- Request flood                     [MITIGATED: rpc_limits]|
|  |   +-- Large payload DoS                 [MITIGATED: size limit]|
|  |   +-- Information disclosure            [MITIGATED: auth]      |
|  |                                                                |
|  [Internal]                                                      |
|  +-- Key material on disk                                        |
|  |   +-- Plaintext key theft               [MITIGATED: encryption]|
|  |   +-- Memory dump key extraction        [MITIGATED: zeroize]   |
|  |   +-- Brute-force keystore password     [MITIGATED: PBKDF2]   |
|  |                                                                |
|  +-- State/DB files                                              |
|  |   +-- State corruption                  [MITIGATED: WAL]      |
|  |   +-- Snapshot tampering                [MITIGATED: blake3]    |
|  |   +-- Migration failure                 [MITIGATED: crash-safe]|
|  |                                                                |
|  [Consensus]                                                     |
|  +-- Double voting                         [MITIGATED: ds_guard]  |
|  +-- Proposal withholding                  [MITIGATED: timeout]   |
|  +-- Long-range attack                     [MITIGATED: finality]  |
|  +-- Nothing-at-stake                      [MITIGATED: slashing]  |
|                                                                  |
+------------------------------------------------------------------+
```

---

## 4. Consensus Security

### 4.1 Safety Properties (Formal)

**S1 — No Split Finality:**
```
forall h: Height, b1 b2: Block:
  finalized(b1, h) AND finalized(b2, h) => b1 == b2
```
Enforced by requiring 2/3+1 precommit votes for the same block_id. Since at most f < N/3 validators can be Byzantine, two conflicting quorums cannot both reach 2/3+1.

**S2 — Finality Monotonicity:**
```
forall t1 < t2:
  finalized_height(t1) <= finalized_height(t2)
```
The engine never decreases `height` after a commit. `next_height()` increments atomically.

**S3 — Deterministic Protocol Version:**
```
forall h: Height, node_i node_j: (correct nodes):
  PV(h, node_i) == PV(h, node_j)
```
Protocol version is determined solely by `height` and the activation schedule (which is part of genesis/config). No local state affects PV selection.

**S4 — State Compatibility:**
```
forall h: Height:
  NOT (ApplyBlock_PV1(h) AND ApplyBlock_PV2(h))
```
At any height, exactly one PV is active. The activation rule is deterministic and all correct nodes agree.

### 4.2 Equivocation Detection

The `DoubleSignGuard` prevents a validator from signing two different proposals or votes for the same (height, round):

```rust
// Persisted to ds_guard.json
check_proposal(height, round, block_id) -> Result
check_vote(height, round, vote_type, block_id) -> Result
```

If equivocation is detected from another validator:
1. `Evidence::DoubleVote` is created with both conflicting votes
2. Evidence is gossipped to all peers via `ConsensusMsg::Evidence`
3. `StakeLedger::apply_evidence()` applies the slashing penalty
4. Slashed stake is burned (not redistributed)

### 4.3 Slashing Conditions

| Offense | Penalty | Evidence Required |
|---------|---------|-------------------|
| Double vote (same height+round) | 100% stake slash | Two conflicting signed votes |
| Double proposal (same height+round) | 100% stake slash | Two conflicting signed proposals |
| Prolonged downtime | Gradual penalty (future) | Missed block tracking |

### 4.4 Finality Guarantees

| Scenario | Finality Time | Guarantee |
|----------|---------------|-----------|
| All validators honest, LAN | ~100 ms | Deterministic single-round |
| All validators honest, WAN | ~300-400 ms | Single-round with network latency |
| f < N/3 Byzantine, healthy network | ~500-800 ms | May need multiple rounds |
| f < N/3 Byzantine, partitioned | Unbounded (until synchrony) | Liveness suspended, safety holds |

---

## 5. Network Security

### 5.1 Transport Security

All P2P connections use libp2p's Noise protocol:
- **Key exchange:** XX handshake pattern
- **Encryption:** ChaChaPoly or AES-256-GCM (negotiated)
- **Authentication:** Ed25519 peer identity keys
- **Forward secrecy:** Ephemeral keys per session

### 5.2 Rate Limiting Architecture

```
Inbound Message
      |
      v
[Connection Limit Check]           max_connections_total: 200
      |                             max_connections_per_peer: 8
      v
[Per-Protocol Rate Limit]           governor (token bucket)
      |                             - block: 15 req/s, 2 MB/s
      |                             - status: 30 req/s, 200 KB/s
      |                             - range: 5 req/s, 4 MB/s
      |                             - state: 10 req/s, 8 MB/s
      v
[Global Bandwidth Cap]              in: 10 MB/s, out: 10 MB/s
      |
      v
[Gossipsub Limits]                  per-topic msg/byte limits
      |                             topic ACL (deny unknown)
      v
[Peer Score Check]                  strike -> quarantine -> ban
      |                             decay over time
      v
[Process Message]
```

### 5.3 Anti-Eclipse Protection

| Mechanism | Configuration | Description |
|-----------|--------------|-------------|
| Peer diversity buckets | `bucket_kind: ip16` | Group peers by /16 subnet |
| Max inbound per bucket | 4 | Prevent single-subnet dominance |
| Max outbound per bucket | 4 | Diversify outbound connections |
| Eclipse detection | `min_buckets: 3` | Alert if peer diversity is too low |
| Reseed cooldown | 60 seconds | Prevent rapid reconnection storms |
| Kademlia DHT | Enabled | Discover diverse peers |
| Quarantine persistence | `persist_quarantine: true` | Survive restarts |

### 5.4 Gossipsub Security

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Allowed topics | `iona/tx`, `iona/blocks`, `iona/evidence` | Whitelist |
| Deny unknown topics | `true` | Reject unexpected topics |
| Max publish msgs/s | 30 | Prevent local spam |
| Max publish bytes/s | 2 MB/s | Prevent bandwidth abuse |
| Max inbound msgs/s | 60 | Per-peer inbound limit |
| Max inbound bytes/s | 4 MB/s | Per-peer bandwidth limit |

---

## 6. Cryptographic Security

### 6.1 Key Management Lifecycle

```
Key Generation          Key Storage              Key Usage              Key Rotation
+----------------+     +------------------+     +----------------+     +----------------+
| Ed25519 from   |---->| Encrypted with   |---->| Sign proposals |---->| Generate new   |
| deterministic  |     | AES-256-GCM      |     | Sign votes     |     | key pair       |
| seed           |     | PBKDF2 (100k)    |     | Sign txs       |     | Re-register    |
|                |     | Random salt      |     |                |     | on-chain       |
| OR             |     |                  |     | Verify sigs    |     |                |
| HSM/KMS key    |     | OR HSM/KMS       |     | (remote or     |     | HSM key        |
| generation     |     | managed storage  |     |  local)        |     | rotation       |
+----------------+     +------------------+     +----------------+     +----------------+
```

### 6.2 Keystore Encryption Details

**Encrypted Keystore Format (`keys.enc`):**

```json
{
  "version": 1,
  "salt": "<base64-encoded 32-byte random salt>",
  "nonce": "<base64-encoded 12-byte random nonce>",
  "ciphertext": "<base64-encoded AES-256-GCM encrypted data>"
}
```

**Key Derivation:**
```
password = env(IONA_KEYSTORE_PASSWORD)
salt = random(32 bytes)
derived_key = PBKDF2-HMAC-SHA256(password, salt, iterations=100000, dklen=32)
```

**Encryption:**
```
plaintext = serialize(keys)
nonce = random(12 bytes)
ciphertext = AES-256-GCM.encrypt(derived_key, nonce, plaintext)
```

**Security Properties:**
- 100,000 PBKDF2 iterations: ~180ms on modern hardware, resistant to GPU brute-force
- Random salt: prevents rainbow table attacks
- AES-256-GCM: authenticated encryption (integrity + confidentiality)
- `zeroize` crate: keys zeroed from memory after use

### 6.3 HSM/KMS Integration

| Backend | Key Storage | Signing | Use Case |
|---------|------------|---------|----------|
| `LocalKeystore` | Encrypted file | In-process | Development, small deployments |
| `Pkcs11Hsm` | Hardware HSM | PKCS#11 API | Enterprise, high-security |
| `AwsKms` | AWS KMS | AWS SDK | Cloud-native (AWS) |
| `AzureKeyVault` | Azure Key Vault | Azure SDK | Cloud-native (Azure) |
| `GcpKms` | GCP Cloud KMS | GCP SDK | Cloud-native (GCP) |

**HSM Signer Trait:**
```rust
#[async_trait::async_trait]
pub trait HsmSigner: Send + Sync {
    fn public_key(&self) -> Vec<u8>;
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HsmError>;
    fn backend_name(&self) -> &str;
}
```

### 6.4 Transaction Signing Security

| Property | Implementation |
|----------|---------------|
| Replay protection | `chain_id` field in Tx (signed) |
| Nonce ordering | `nonce` field prevents replay within chain |
| Address derivation | `blake3(pubkey)[0..20]` — deterministic |
| Sign data format | Fixed binary format (not JSON — immune to serialization variance) |
| Signature scheme | Ed25519 (deterministic — no nonce reuse risk) |

---

## 7. MEV Security

### 7.1 Threat: Frontrunning

**Attack:** Validator sees pending transaction, inserts own tx before it.

**Mitigation — Commit-Reveal:**
1. User submits `commit_hash = blake3(sender || nonce || encrypted_tx || salt)`
2. Commit is included in block ordering (content hidden)
3. User reveals actual transaction after commit is ordered
4. Validator cannot frontrun because tx content is unknown at ordering time

**Security Analysis:**
- `commit_hash` is binding: changing tx content changes hash (collision-resistant)
- `salt` prevents dictionary attacks on common transactions
- TTL (20 blocks) prevents stale commits from being revealed out of context

### 7.2 Threat: Sandwich Attacks

**Attack:** Attacker wraps victim's trade: buy-before + sell-after.

**Mitigation — Threshold Encryption:**
1. Transactions encrypted with AES-256-GCM using epoch-derived key
2. Key is derived from validator set + block hash: `blake3("iona_epoch" || epoch || validator_set_hash)`
3. Decryption happens after block ordering is finalized
4. No single validator can decrypt alone (key requires block hash, which is unpredictable)

### 7.3 Threat: Backrunning

**Attack:** Validator inserts own tx immediately after observing profitable trade.

**Mitigation — Anti-Backrunning Delay:**
- Recent proposers tracked (last 100 heights)
- `backrun_delay_blocks = 1`: proposer cannot submit within 1 block of their own proposal
- `is_potential_backrun(tx)` check in mempool

### 7.4 Threat: Ordering Manipulation

**Attack:** Validator reorders transactions for profit.

**Mitigation — Fair Ordering (FCFS + Jitter):**
1. Transactions ordered by commit timestamp (first-come-first-served)
2. Jitter window (50ms): transactions within window are "simultaneous"
3. Deterministic shuffle within window using `prev_block_hash` as seed
4. Seed is unpredictable until previous block is finalized

---

## 8. Storage Security

### 8.1 Data Integrity

| Data | Integrity Mechanism | Verification |
|------|---------------------|-------------|
| State (`state_full.json`) | `state_root` in block header | Merkle root recomputation |
| Transactions | `tx_root` in block header | blake3 Merkle over tx hashes |
| Receipts | `receipts_root` in block header | blake3 Merkle over receipt data |
| Block identity | `Block::id()` deterministic binary hash | Recompute from header fields |
| Snapshots | blake3 checksum per chunk + manifest | Verify on import |
| WAL entries | Atomic writes | Replay on crash recovery |

### 8.2 Snapshot Security

| Property | Implementation |
|----------|---------------|
| Integrity | blake3 checksum per data chunk |
| Manifest integrity | blake3 over entire manifest |
| Compression | zstd (level 3, no security impact) |
| Import verification | Full checksum verification before state replacement |
| Attestation (P2P) | Threshold signatures from validators (optional) |

### 8.3 Migration Security

| Property | Implementation |
|----------|---------------|
| Idempotency | `Migrate(sv, sv, DB) = DB` |
| Crash safety | `MigrationState` checkpoint per step |
| Resume | Re-run from last checkpoint on crash |
| Monotonicity | `sv_old < sv_new` enforced |
| No data loss | Conservation invariants checked post-migration |
| Value conservation | `sum(balances_before) == sum(balances_after)` (M2) |
| Root equivalence | `StateRoot(DB_before) == StateRoot(DB_after)` for format-only changes (M3) |

---

## 9. Operational Security

### 9.1 Audit Trail

All critical operations are logged to `audit.log` as structured JSON events:

| Event Category | Events Logged |
|----------------|---------------|
| Key operations | Key generation, key load, key export, signing |
| Consensus | Block proposal, vote, commit, finality, equivocation |
| Network | Peer connect, disconnect, quarantine, ban |
| Storage | Migration start/complete, snapshot create/restore |
| Protocol | Upgrade activation, PV change, shadow validation |
| Configuration | Config load, config change, restart |

**Audit Entry Format:**
```json
{
  "timestamp": "2026-02-25T20:24:36Z",
  "event_type": "consensus.block_finalized",
  "height": 12345,
  "block_id": "abcdef...",
  "finality_ms": 105,
  "round": 0,
  "details": {}
}
```

### 9.2 Monitoring & Alerting

**Prometheus Metrics (70+ total):**

| Category | Key Metrics |
|----------|------------|
| Consensus | `iona_consensus_height`, `iona_consensus_round`, `iona_consensus_step` |
| Finality | `iona_finality_avg_ms`, `iona_finality_p95_ms`, `iona_finality_fast_commits` |
| Network | `iona_peers_connected`, `iona_peers_quarantined`, `iona_peers_banned` |
| Mempool | `iona_mempool_size`, `iona_mempool_mev_commits`, `iona_mempool_mev_reveals` |
| RPC | `iona_rpc_requests_total`, `iona_rpc_errors_total`, `iona_rpc_latency_ms` |
| Storage | `iona_storage_state_size_bytes`, `iona_storage_migration_progress` |
| Rate limiting | `iona_ratelimit_rejected_total`, `iona_ratelimit_quarantines_total` |

**Recommended Alerts:**

| Alert | Condition | Severity |
|-------|-----------|----------|
| Finality stalled | `iona_consensus_height` unchanged > 30s | CRITICAL |
| High round number | `iona_consensus_round` > 3 | WARNING |
| Peer count low | `iona_peers_connected` < 2 | CRITICAL |
| Memory high | Process RSS > 80% of available | WARNING |
| Disk usage high | Data directory > 80% of partition | WARNING |
| Rate limit triggered | `iona_ratelimit_rejected_total` increase > 100/min | WARNING |
| Equivocation detected | `iona_slashing_evidence_total` > 0 | CRITICAL |
| Migration stalled | `iona_storage_migration_progress` unchanged > 5min | WARNING |

### 9.3 Access Control

| Component | Access Control | Notes |
|-----------|---------------|-------|
| P2P port (7001) | Firewall + peer diversity | Public (required for consensus) |
| RPC port (9001) | Firewall + rate limiting | Restrict to trusted clients |
| Metrics port | Same as RPC (9001) | `/metrics` endpoint |
| Data directory | File permissions (600/700) | Sensitive (keys, state) |
| Keystore password | Environment variable | Never in config file |
| HSM/KMS credentials | Cloud IAM / HSM config | Role-based access |
| Audit log | Append-only (recommended) | `audit.log` |

### 9.4 Incident Response

| Scenario | Response | Recovery |
|----------|----------|----------|
| Key compromise | Immediately stop node, rotate keys, re-register | Generate new keypair, update on-chain registration |
| Double-sign detection | Automatic slashing | Evidence propagation, stake penalty |
| Node compromise | Isolate, forensics, rebuild | Restore from verified snapshot |
| State corruption | Stop node, investigate | Restore from snapshot, replay from peers |
| Network partition | Monitor, wait for sync | Consensus resumes automatically on reconnection |
| Supply chain attack | Verify SBOM, lock dependencies | Revert to known-good Cargo.lock |

---

## 10. Supply Chain Security

### 10.1 Dependency Management

| Control | Implementation |
|---------|---------------|
| Frozen toolchain | `rust-toolchain.toml` pins Rust 1.85.0 |
| Locked dependencies | `Cargo.lock` committed, `--locked` flag everywhere |
| SBOM generation | `cargo-cyclonedx` for CycloneDX JSON format |
| Artifact hashes | SHA256SUMS.txt for all release artifacts |
| Reproducible builds | Same toolchain + locked deps = identical binary |
| CI verification | All builds use `--locked` flag |

### 10.2 Build Verification

```bash
# Verify build reproducibility
cargo build --release --locked --bin iona-node
sha256sum target/release/iona-node

# Expected: same SHA256 on same platform + toolchain
```

### 10.3 Release Artifact Security

| Artifact | Integrity Check |
|----------|----------------|
| `iona-node` binary | SHA256 in `SHA256SUMS.txt` |
| `sbom.json` | SHA256 in `SHA256SUMS.txt` |
| Source tarball | SHA256 in `SHA256SUMS.txt` |
| SLSA provenance | GitHub Actions SLSA workflow (`.github/workflows/slsa_release.yml`) |

---

## 11. Protocol Upgrade Security

### 11.1 Upgrade Safety Invariants

During protocol upgrades (PV1 -> PV2):

| Invariant | Check | Enforcement |
|-----------|-------|-------------|
| S1: No split-finality | `check_no_split_finality()` | Consensus engine |
| S2: Finality monotonic | `check_finality_monotonic()` | Engine state |
| S3: Deterministic PV | `PV(height)` is pure function | Activation schedule |
| S4: State compatibility | Single PV active per height | Activation rule |
| M2: Value conservation | `sum(balances) + burned` invariant | Migration verification |
| M3: Root equivalence | `StateRoot(before) == StateRoot(after)` | Cross-migration test |

### 11.2 Shadow Validation (Pre-Activation)

Before activation height H, nodes that support PV2 can shadow-validate blocks:

```
For height < H:
  - Validate with PV1 (mandatory, blocks consensus)
  - Validate with PV2 (optional, log-only, non-blocking)
  - If PV2 validation fails: log warning (potential upgrade issue)
  - If PV2 validation succeeds: confidence in upgrade
```

### 11.3 Rollback Policy

| Scenario | Rollback Possible? | Requirements |
|----------|-------------------|-------------|
| Before activation height H | YES | Downgrade binary, SV must be compatible |
| After activation, with pre-H snapshot | YES | Restore snapshot, downgrade binary |
| After activation, no snapshot | NO | State is PV2-only, cannot revert |

---

## 12. Known Limitations & Future Work

### 12.1 Current Limitations

| Limitation | Risk | Mitigation Timeline |
|-----------|------|---------------------|
| JSON file storage | I/O bottleneck at scale | Planned: RocksDB migration |
| No BLS aggregate sigs | Larger certificates | Planned: BLS12-381 integration |
| Threshold encryption is symmetric | Epoch secret must be distributed | Planned: DKG protocol |
| No formal verification of Rust code | Potential implementation bugs | Ongoing: property testing, fuzzing |
| VM gas metering approximate | Potential gas griefing | Ongoing: formal gas model |

### 12.2 Future Security Enhancements

1. **Formal verification:** TLA+ model checking for consensus + upgrade protocols
2. **BLS aggregate signatures:** Reduce certificate size from O(N) to O(1)
3. **DKG for threshold encryption:** Distributed key generation for MEV protection
4. **Account abstraction:** Smart contract wallets for social recovery
5. **Zero-knowledge proofs:** ZK state proofs for light clients
6. **Hardware attestation:** TEE-based validator attestation

---

## Appendix A: Security Checklist for Operators

- [ ] Use encrypted keystore (`keystore = "encrypted"`) in production
- [ ] Set strong keystore password via environment variable
- [ ] Restrict RPC port access (firewall/VPN)
- [ ] Enable audit logging and monitor `audit.log`
- [ ] Set up Prometheus monitoring with recommended alerts
- [ ] Regularly verify snapshot integrity (blake3 checksums)
- [ ] Keep node binary up to date (follow UPGRADE.md procedures)
- [ ] Backup keystore and state before upgrades
- [ ] Verify SBOM and SHA256 hashes for release artifacts
- [ ] Use HSM/KMS for production validator keys (recommended)
- [ ] Review peer connections for diversity (anti-eclipse)
- [ ] Test disaster recovery procedures regularly

---

## Appendix B: Cryptographic Parameter Summary

| Parameter | Value | Justification |
|-----------|-------|---------------|
| Ed25519 key size | 256-bit | NIST recommended, ~128-bit security |
| blake3 output size | 256-bit | Full collision resistance |
| AES-256-GCM key size | 256-bit | Highest AES security level |
| AES-256-GCM nonce size | 96-bit (12 bytes) | GCM standard |
| PBKDF2 iterations | 100,000 | OWASP 2024 recommendation |
| PBKDF2 salt size | 256-bit (32 bytes) | Exceeds NIST minimum (128-bit) |
| PBKDF2 derived key size | 256-bit (32 bytes) | Matches AES-256 key size |
| Commit-reveal salt | 256-bit (32 bytes) | Prevents dictionary attacks |
| Epoch secret derivation | blake3(prefix + epoch + vset_hash) | Binding to epoch + validators |

---

*Security Model for IONA v27.0.0. This document should be reviewed and updated with each major release.*  
*For vulnerability reports, contact the security team. See SECURITY.md for disclosure policy.*
