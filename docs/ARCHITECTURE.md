# IONA Blockchain — Architecture Diagram

**Version:** 27.0.0  
**Last Updated:** 2026-02-25

---

## High-Level Architecture

```
+===========================================================================+
|                           IONA Node (iona-node)                           |
+===========================================================================+
|                                                                           |
|  +-------------------+    +-------------------+    +-------------------+  |
|  |    RPC Layer      |    |   P2P Network     |    |   Metrics /       |  |
|  |   (axum HTTP)     |    |   (libp2p)        |    |   Observability   |  |
|  |                   |    |                   |    |   (prometheus)    |  |
|  | - JSON-RPC 2.0    |    | - Gossipsub       |    |                   |  |
|  | - REST endpoints  |    | - Kademlia DHT    |    | - /metrics HTTP   |  |
|  | - WebSocket       |    | - Request-Response|    | - 70+ metrics     |  |
|  | - Rate limiting   |    | - mDNS discovery  |    | - Audit trail     |  |
|  +--------+----------+    +--------+----------+    +--------+----------+  |
|           |                        |                        |             |
|           v                        v                        v             |
|  +--------+------------------------+------------------------+----------+  |
|  |                        Core Engine                                  |  |
|  |  +------------------+  +------------------+  +------------------+   |  |
|  |  |    Consensus     |  |    Execution     |  |     Mempool      |   |  |
|  |  |   (Tendermint)   |  |   (Parallel)     |  |  (MEV-Resistant) |   |  |
|  |  |                  |  |                  |  |                  |   |  |
|  |  | - Engine         |  | - KV execution   |  | - Commit-reveal  |   |  |
|  |  | - Fast finality  |  | - VM execution   |  | - Threshold enc  |   |  |
|  |  | - Validator set  |  | - EVM (revm)     |  | - Fair ordering  |   |  |
|  |  | - Quorum logic   |  | - Parallel exec  |  | - Anti-backrun   |   |  |
|  |  | - Double-sign    |  | - Sig verify     |  | - Standard pool  |   |  |
|  |  +--------+---------+  +--------+---------+  +--------+---------+   |  |
|  |           |                     |                      |            |  |
|  +-----------+---------------------+----------------------+------------+  |
|              |                     |                      |               |
|              v                     v                      v               |
|  +-----------+---------------------+----------------------+------------+  |
|  |                       State Management                              |  |
|  |  +------------------+  +------------------+  +------------------+   |  |
|  |  |   KvState        |  |   StakeLedger    |  |   VmStorage      |   |  |
|  |  | - kv: BTreeMap   |  | - validators     |  | - code: BTreeMap |   |  |
|  |  | - balances       |  | - slashing       |  | - storage slots  |   |  |
|  |  | - nonces         |  | - evidence       |  | - nonces         |   |  |
|  |  | - burned         |  | - penalties      |  | - logs           |   |  |
|  |  +--------+---------+  +--------+---------+  +--------+---------+   |  |
|  +-----------+---------------------+----------------------+------------+  |
|              |                     |                      |               |
|              v                     v                      v               |
|  +-----------+---------------------+----------------------+------------+  |
|  |                      Storage Layer                                  |  |
|  |  +------------------+  +------------------+  +------------------+   |  |
|  |  |  JSON Files      |  |   Snapshots      |  |   WAL (Write-    |   |  |
|  |  | - state_full.json|  | - zstd compressed|  |    Ahead Log)    |   |  |
|  |  | - stakes.json    |  | - blake3 checksum|  | - Crash recovery |   |  |
|  |  | - blocks.json    |  | - Delta sync     |  | - Atomic writes  |   |  |
|  |  | - node_meta.json |  | - Chunk transfer |  |                  |   |  |
|  |  +------------------+  +------------------+  +------------------+   |  |
|  +---------------------------------------------------------------------+  |
|                                                                           |
|  +-------------------+    +-------------------+    +-------------------+  |
|  |   Crypto Layer    |    |   Protocol Mgmt   |    |   Economics       |  |
|  | - Ed25519 signing |    | - Version control |    | - EIP-1559 fees   |  |
|  | - AES-256-GCM     |    | - Dual-validate   |    | - PoS staking     |  |
|  | - PBKDF2 KDF      |    | - Wire compat     |    | - Epoch rewards   |  |
|  | - HSM/KMS support |    | - Safety invariant|    | - Slashing        |  |
|  | - Keystore (enc)  |    | - Migration mgr   |    | - Governance      |  |
|  +-------------------+    +-------------------+    +-------------------+  |
|                                                                           |
+===========================================================================+
```

---

## Module Dependency Graph

```
                    iona-node (binary)
                         |
            +------------+------------+
            |            |            |
            v            v            v
         config       rpc/mod      net/p2p
            |            |            |
            v            v            v
    +-------+----+   +---+---+   +---+----+
    | consensus/ |   | types |   | net/   |
    |  engine    |   |       |   | simnet |
    |  fast_fin  |   +---+---+   | inmem  |
    |  quorum    |       |       | p2p    |
    |  messages  |       |       | state_ |
    |  val_set   |       |       |  sync  |
    |  dbl_sign  |       |       +--------+
    |  blk_prod  |       |
    +------+-----+       |
           |             |
           v             v
    +------+-------------+-------+
    |       execution            |
    | - execute_block            |
    | - execute_block_with_staking|
    | - parallel (rayon)         |
    | - vm_executor              |
    | - verify_tx_signature      |
    +------+---------------------+
           |
    +------+------+------+------+
    |      |      |      |      |
    v      v      v      v      v
  crypto merkle mempool evm  economics
    |             |      |      |
    v             v      v      v
  ed25519    pool.rs   revm   staking
  keystore   mev_      kv_    rewards
  hsm        resistant state_ params
  tx                   db
  remote_
  signer
```

---

## Component Details

### 1. Consensus Layer (`src/consensus/`)

```
+============================================+
|              Consensus Engine               |
+============================================+
|                                            |
|  State Machine (Tendermint-style):         |
|                                            |
|  PROPOSE --> PREVOTE --> PRECOMMIT --> COMMIT
|     |           |            |              |
|     |     (fast_quorum)      |              |
|     |    skip timeout if     |              |
|     |    2/3+ votes arrive   |              |
|     |           |            |              |
|     +---(round change)-------+              |
|                                            |
|  Key Components:                           |
|  - Engine<V: Verifier>: Main state machine |
|  - ValidatorSet: Round-robin proposer      |
|  - FinalityTracker: Adaptive timeouts      |
|  - PipelineState: Overlapped preparation   |
|  - DoubleSignGuard: Equivocation protection|
|  - CommitCertificate: 2/3+ precommit proof |
|                                            |
|  Safety Properties:                        |
|  - S1: No split-finality                   |
|  - S2: Finality monotonic                  |
|  - S3: Deterministic PV selection          |
|  - S4: State compatibility                 |
+============================================+
```

### 2. Execution Layer (`src/execution.rs`)

```
+============================================+
|            Execution Pipeline              |
+============================================+
|                                            |
|  Phase 1: Parallel Signature Verification  |
|  +-----------------------------------------+
|  | rayon::par_iter over all tx signatures  |
|  | Ed25519 verify (~50us/sig, 8x parallel) |
|  | Threshold: > 16 tx triggers parallel    |
|  +-----------------------------------------+
|                    |                        |
|                    v                        |
|  Phase 2: Transaction Routing              |
|  +-----------------------------------------+
|  | "set/del/inc"  -> KV payload engine     |
|  | "stake ..."    -> Staking module        |
|  | "vm ..."       -> IONA VM executor      |
|  | "evm_unified " -> EVM (revm) executor   |
|  +-----------------------------------------+
|                    |                        |
|                    v                        |
|  Phase 3: State Application                |
|  +-----------------------------------------+
|  | Sequential: nonce check, fee deduction  |
|  | EIP-1559: base_fee burn + priority tip  |
|  | State update: KvState mutation          |
|  +-----------------------------------------+
|                    |                        |
|                    v                        |
|  Phase 4: Block Finalization               |
|  +-----------------------------------------+
|  | tx_root: blake3 Merkle over tx hashes   |
|  | receipts_root: blake3 over receipt data  |
|  | state_root: Merkle over KvState entries  |
|  | Block ID: deterministic binary hash     |
|  +-----------------------------------------+
+============================================+
```

### 3. MEV-Resistant Mempool (`src/mempool/`)

```
+============================================+
|         MEV-Resistant Mempool              |
+============================================+
|                                            |
|  Layer 1: Commit-Reveal                    |
|  +----------------------------------------+
|  | Tx Submission:                          |
|  |   commit_hash = blake3(sender||nonce    |
|  |                       ||encrypted||salt)|
|  | Phase 1: Submit commit (hides content)  |
|  | Phase 2: Reveal after commit included   |
|  | TTL: 20 blocks (configurable)           |
|  +----------------------------------------+
|                    |                        |
|  Layer 2: Threshold Encryption             |
|  +----------------------------------------+
|  | AES-256-GCM with epoch-derived key      |
|  | Decrypt only after block ordering       |
|  | Prevents sandwich attacks               |
|  +----------------------------------------+
|                    |                        |
|  Layer 3: Fair Ordering (FCFS + Jitter)    |
|  +----------------------------------------+
|  | FCFS by commit timestamp                |
|  | Jitter window: 50ms (configurable)      |
|  | Deterministic shuffle within window     |
|  | Seed: prev_block_hash (unpredictable)   |
|  +----------------------------------------+
|                    |                        |
|  Layer 4: Anti-Backrunning                 |
|  +----------------------------------------+
|  | Delay window: 1 block (configurable)    |
|  | Recent proposer tracking                |
|  | Block proposer tx insertion delay       |
|  +----------------------------------------+
|                                            |
|  Standard Pool (backward compatible):      |
|  +----------------------------------------+
|  | Capacity: 200,000 tx                    |
|  | Priority: by nonce + gas price          |
|  | Direct submit (bypasses MEV protection) |
|  +----------------------------------------+
+============================================+
```

### 4. Network Layer (`src/net/`)

```
+============================================+
|              P2P Network                   |
+============================================+
|                                            |
|  Transport: libp2p                         |
|  +----------------------------------------+
|  | TCP + Noise (encrypted) + Yamux (mux)  |
|  | DNS resolution for bootnodes           |
|  +----------------------------------------+
|                                            |
|  Protocols:                                |
|  +----------------------------------------+
|  | Gossipsub: tx, blocks, evidence topics  |
|  | Request-Response: block/state/range/    |
|  |                   status sync           |
|  | Kademlia DHT: peer discovery            |
|  | mDNS: LAN discovery (optional)          |
|  | Identify: peer info exchange            |
|  +----------------------------------------+
|                                            |
|  Rate Limiting & DoS Protection:           |
|  +----------------------------------------+
|  | Per-protocol request limits (req/s)     |
|  | Per-protocol bandwidth caps (bytes/s)   |
|  | Global bandwidth caps (in/out)          |
|  | Peer scoring (decay + penalties)        |
|  | Strike system -> quarantine -> ban      |
|  | Gossipsub topic ACL + per-topic limits  |
|  | Connection limits (total + per-peer)    |
|  | Peer diversity / eclipse resistance     |
|  +----------------------------------------+
|                                            |
|  State Sync:                               |
|  +----------------------------------------+
|  | Chunk-based state transfer (1 MB/chunk) |
|  | Snapshot attestation (threshold sigs)   |
|  | Validator-set binding                   |
|  | Epoch-based security                    |
|  +----------------------------------------+
+============================================+
```

### 5. Crypto Layer (`src/crypto/`)

```
+============================================+
|             Cryptographic Layer            |
+============================================+
|                                            |
|  Signing:                                  |
|  +----------------------------------------+
|  | Ed25519 (ed25519-dalek)                 |
|  | Signer trait: sign(msg) -> SignatureBytes|
|  | Verifier trait: verify(pk, msg, sig)    |
|  +----------------------------------------+
|                                            |
|  Key Storage:                              |
|  +----------------------------------------+
|  | Plain: keys.json (development only)     |
|  | Encrypted: keys.enc                     |
|  |   - AES-256-GCM encryption             |
|  |   - PBKDF2-HMAC-SHA256 (100k iter)     |
|  |   - Random salt per keystore            |
|  |   - Password via env var                |
|  +----------------------------------------+
|                                            |
|  HSM/KMS Integration:                      |
|  +----------------------------------------+
|  | HsmSigner trait (async):                |
|  |   - LocalKeystore (default)             |
|  |   - PKCS#11 (hardware HSM)             |
|  |   - AWS KMS                             |
|  |   - Azure Key Vault                     |
|  |   - GCP Cloud KMS                       |
|  +----------------------------------------+
|                                            |
|  Hashing:                                  |
|  +----------------------------------------+
|  | blake3: Block IDs, tx hashes, state root|
|  | SHA-256: VM code hashes, PBKDF2         |
|  | Keccak-256: EVM address derivation      |
|  +----------------------------------------+
|                                            |
|  Transaction Signing:                      |
|  +----------------------------------------+
|  | tx_sign_bytes: deterministic sign data  |
|  | derive_address: blake3(pubkey)[0..20]   |
|  | chain_id: replay protection             |
|  +----------------------------------------+
+============================================+
```

### 6. Storage & Migration Layer (`src/storage/`)

```
+============================================+
|           Storage Architecture             |
+============================================+
|                                            |
|  On-Disk Layout (data_dir/):               |
|  +----------------------------------------+
|  | state_full.json  - Current KvState      |
|  | stakes.json      - StakeLedger          |
|  | blocks.json      - Block history        |
|  | node_meta.json   - Schema/protocol ver  |
|  | keys.json/.enc   - Validator keys       |
|  | quarantine.json  - Banned peers         |
|  | ds_guard.json    - Double-sign guard    |
|  | audit.log        - Audit trail          |
|  | snapshots/       - Compressed snapshots |
|  +----------------------------------------+
|                                            |
|  Schema Versioning:                        |
|  +----------------------------------------+
|  | Current SV: 4                           |
|  | node_meta.json tracks schema_version    |
|  | Migrations are ordered + idempotent     |
|  +----------------------------------------+
|                                            |
|  Migration System:                         |
|  +----------------------------------------+
|  | m0001: Initialize state                 |
|  | m0002: Add nonces + fee fields          |
|  | m0003: Initialize balances              |
|  | m0004: Add node_meta.json + protocol_ver|
|  |                                         |
|  | Background runner:                      |
|  |   - Non-blocking startup                |
|  |   - Crash-safe resume (MigrationState)  |
|  |   - Progress tracking                   |
|  +----------------------------------------+
|                                            |
|  Snapshot System:                          |
|  +----------------------------------------+
|  | Export: state -> zstd compressed file   |
|  | Import: compressed file -> state        |
|  | Integrity: blake3 checksums             |
|  | Delta sync: chunk-based transfer        |
|  | Configurable: every N blocks, keep M    |
|  +----------------------------------------+
+============================================+
```

### 7. RPC Layer (`src/rpc/`)

```
+============================================+
|               RPC Architecture             |
+============================================+
|                                            |
|  HTTP Server (axum):                       |
|  +----------------------------------------+
|  | POST /  - JSON-RPC 2.0 endpoint        |
|  | GET  /health - Node health check       |
|  | GET  /status - Node status             |
|  | GET  /metrics - Prometheus metrics      |
|  | POST /vm/deploy - VM contract deploy   |
|  | POST /vm/call   - VM contract call     |
|  | POST /tx        - Submit transaction   |
|  +----------------------------------------+
|                                            |
|  JSON-RPC Methods:                         |
|  +----------------------------------------+
|  | eth_blockNumber                         |
|  | eth_getBalance                          |
|  | eth_getTransactionCount                 |
|  | eth_sendRawTransaction                  |
|  | eth_getBlockByNumber                    |
|  | eth_getBlockByHash                      |
|  | eth_call                                |
|  | eth_estimateGas                         |
|  | eth_getLogs                             |
|  | eth_getProof                            |
|  | net_version                             |
|  | net_peerCount                           |
|  | web3_clientVersion                      |
|  | iona_getState                           |
|  | iona_getValidators                      |
|  +----------------------------------------+
|                                            |
|  Rate Limiting (rpc_limits):               |
|  +----------------------------------------+
|  | Per-IP request limits                   |
|  | Method-specific limits                  |
|  | Global throughput caps                  |
|  +----------------------------------------+
+============================================+
```

### 8. Protocol Upgrade System (`src/protocol/`)

```
+============================================+
|          Protocol Upgrade Flow             |
+============================================+
|                                            |
|  Pre-Activation (height < H):             |
|  +----------------------------------------+
|  | - Node supports PV_old + PV_new        |
|  | - Produces blocks with PV_old           |
|  | - Shadow-validates with PV_new          |
|  |   (non-blocking, logs only)             |
|  | - Operators upgrade rolling             |
|  +----------------------------------------+
|              |                              |
|              v (height == H)                |
|  Activation Point:                         |
|  +----------------------------------------+
|  | - Switch to PV_new for production       |
|  | - Reject PV_old blocks (after grace)    |
|  | - Run schema migrations if needed       |
|  | - Safety invariants checked             |
|  +----------------------------------------+
|              |                              |
|              v                              |
|  Post-Activation (height > H):             |
|  +----------------------------------------+
|  | - PV_new only                           |
|  | - Grace window for late blocks          |
|  | - No rollback without pre-H snapshot    |
|  +----------------------------------------+
|                                            |
|  Wire Compatibility:                       |
|  +----------------------------------------+
|  | Hello handshake:                        |
|  |   supported_pv, supported_sv, sw_ver    |
|  | Connect iff intersection(PV) != empty   |
|  | New msg types ignorable by old nodes    |
|  +----------------------------------------+
+============================================+
```

---

## Data Flow Diagrams

### Transaction Lifecycle

```
Client                    Node                      Network
  |                        |                          |
  |-- POST /tx ----------->|                          |
  |                        |-- Validate signature     |
  |                        |-- Check nonce            |
  |                        |-- Check gas/balance      |
  |                        |-- Add to mempool         |
  |                        |-- Gossip tx ------------>|
  |                        |                          |
  |                        |<-- Propose block --------|
  |                        |-- Drain mempool          |
  |                        |-- Execute txs            |
  |                        |-- Compute state root     |
  |                        |-- Broadcast proposal     |
  |                        |                          |
  |                        |<-- Prevote --------------|
  |                        |-- Check 2/3+ prevotes    |
  |                        |-- Broadcast precommit    |
  |                        |                          |
  |                        |<-- Precommit ------------|
  |                        |-- Check 2/3+ precommits  |
  |                        |-- Finalize block         |
  |                        |-- Persist state          |
  |                        |-- Emit metrics           |
  |                        |                          |
  |<-- Receipt ------------|                          |
```

### Block Production Pipeline

```
Height H                        Height H+1
+--------+    +--------+    +--------+    +--------+
| Propose|    | Prevote|    |Precommit|    | Commit |
| ~10ms  |--->| ~20ms  |--->| ~20ms   |--->| ~5ms   |
+--------+    +--------+    +--------+    +--------+
                                              |
                                    +---------+---------+
                                    | Pipeline: prepare |
                                    | H+1 proposal      |
                                    | while H commits   |
                                    +-------------------+
```

### Validator Set & Proposer Selection

```
Validators: [V1, V2, V3, V4]  (stake-weighted)

Height 1, Round 0: V1 proposes  (round-robin)
Height 1, Round 1: V2 proposes  (if round 0 fails)
Height 2, Round 0: V2 proposes
Height 3, Round 0: V3 proposes
Height 4, Round 0: V4 proposes
Height 5, Round 0: V1 proposes  (cycle)
```

---

## Deployment Topology

### Single Node (Development)

```
+-------------------+
|   iona-node       |
|   :7001 (P2P)     |
|   :9001 (RPC)     |
+-------------------+
```

### 3-Node Local Testnet

```
+-------------------+    +-------------------+    +-------------------+
|   Node 1          |    |   Node 2          |    |   Node 3          |
|   seed=1          |<-->|   seed=2          |<-->|   seed=3          |
|   :7001 P2P       |    |   :7002 P2P       |    |   :7003 P2P       |
|   :9001 RPC       |    |   :9002 RPC       |    |   :9003 RPC       |
+-------------------+    +-------------------+    +-------------------+
```

### Production Deployment

```
                    +------------------+
                    |   Load Balancer  |
                    |   (RPC traffic)  |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
     +--------+--+  +--------+--+  +--------+--+
     | Validator1|  | Validator2|  | Validator3|
     | encrypted |  | encrypted |  | HSM/KMS  |
     | keystore  |  | keystore  |  | signer   |
     | :7001 P2P |  | :7001 P2P |  | :7001 P2P|
     | :9001 RPC |  | :9001 RPC |  | :9001 RPC|
     +-----+-----+  +-----+-----+  +-----+----+
           |               |              |
     +-----+---------------+--------------+-----+
     |              P2P Full Mesh                |
     |         (Gossipsub + Kademlia)            |
     +-------------------------------------------+
           |               |              |
     +-----+-----+  +-----+-----+  +-----+-----+
     | Sentry 1  |  | Sentry 2  |  | Sentry 3  |
     | (public)  |  | (public)  |  | (public)  |
     +-----+-----+  +-----+-----+  +-----+-----+
           |               |              |
     +-----+---------------+--------------+-----+
     |           Public Internet                 |
     +-------------------------------------------+
                       |
              +--------+--------+
              |  Monitoring     |
              |  Prometheus     |
              |  + Grafana      |
              |  + AlertManager |
              +-----------------+
```

---

## File Structure

```
iona_v27/
+-- Cargo.toml                    # Package manifest (v27.0.0)
+-- Cargo.lock                    # Locked dependencies
+-- rust-toolchain.toml           # Frozen toolchain (1.85.0)
+-- src/
|   +-- lib.rs                    # Library root (all modules)
|   +-- bin/
|   |   +-- iona-node.rs          # Main node binary
|   |   +-- iona-cli.rs           # CLI tool (optional)
|   |   +-- iona-chaos.rs         # Chaos testing (optional)
|   |   +-- iona-remote-signer.rs # Remote signer (optional)
|   |   +-- iona-evm-rpc.rs       # EVM RPC adapter (optional)
|   |   +-- iona-chaindb-tool.rs  # Chain DB tool (optional)
|   |   +-- block_store.rs        # Block store (optional)
|   +-- config.rs                 # TOML configuration
|   +-- types/
|   |   +-- mod.rs                # Core types (Block, Tx, Hash32, Receipt)
|   |   +-- tx_vm.rs              # VM transaction types
|   |   +-- tx_evm.rs             # EVM transaction types
|   +-- consensus/
|   |   +-- mod.rs                # Consensus module root
|   |   +-- engine.rs             # Tendermint consensus engine
|   |   +-- fast_finality.rs      # Sub-second finality tracker
|   |   +-- messages.rs           # Consensus messages (Proposal, Vote)
|   |   +-- quorum.rs             # Quorum logic (2/3+1 threshold)
|   |   +-- validator_set.rs      # Validator set management
|   |   +-- double_sign.rs        # Equivocation protection
|   |   +-- block_producer.rs     # Block production logic
|   +-- execution.rs              # Block execution + parallel engine
|   |   +-- parallel.rs           # Parallel execution (rayon)
|   |   +-- vm_executor.rs        # IONA VM executor
|   +-- mempool/
|   |   +-- mod.rs                # Mempool module root
|   |   +-- pool.rs               # Standard mempool
|   |   +-- mev_resistant.rs      # MEV-resistant mempool
|   +-- net/
|   |   +-- mod.rs                # Network module root
|   |   +-- p2p.rs                # libp2p networking + rate limiting
|   |   +-- simnet.rs             # Simulated network for testing
|   |   +-- inmem.rs              # In-memory network
|   |   +-- peer_score.rs         # Peer scoring system
|   |   +-- state_sync.rs         # State synchronization
|   +-- crypto/
|   |   +-- mod.rs                # Crypto traits (Signer, Verifier)
|   |   +-- ed25519.rs            # Ed25519 implementation
|   |   +-- keystore.rs           # Encrypted key storage
|   |   +-- hsm.rs                # HSM/KMS integration
|   |   +-- tx.rs                 # Transaction signing helpers
|   |   +-- remote_signer.rs      # Remote signing service
|   +-- storage/
|   |   +-- mod.rs                # Storage module root
|   |   +-- meta.rs               # Node metadata + schema version
|   |   +-- migrations/
|   |       +-- mod.rs            # Migration registry
|   |       +-- background.rs     # Background migration runner
|   |       +-- m0004_protocol_version.rs  # Latest migration
|   +-- protocol/
|   |   +-- mod.rs                # Protocol module root
|   |   +-- version.rs            # Protocol versioning
|   |   +-- wire.rs               # Wire compatibility
|   |   +-- safety.rs             # Safety invariant checks
|   |   +-- dual_validate.rs      # Shadow validation
|   +-- rpc/
|   |   +-- mod.rs                # RPC server
|   |   +-- eth_rpc.rs            # Ethereum-compatible RPC
|   +-- vm/                       # IONA custom VM
|   +-- evm/                      # EVM (revm) integration
|   +-- economics/                # PoS economics
|   +-- evidence.rs               # Slashing evidence
|   +-- governance.rs             # On-chain governance
|   +-- merkle.rs                 # Merkle tree utilities
|   +-- metrics.rs                # Prometheus metrics (70+)
|   +-- audit.rs                  # Audit trail logging
|   +-- snapshot.rs               # Snapshot export/import
|   +-- slashing.rs               # Slashing logic
|   +-- wal.rs                    # Write-ahead log
|   +-- rpc_limits.rs             # RPC rate limiting
+-- tests/
|   +-- integration.rs            # Integration tests
|   +-- determinism.rs            # Determinism golden vectors
|   +-- upgrade_sim.rs            # Upgrade simulation tests
|   +-- replay.rs                 # Replay tests
|   +-- simnet_five_node_eventual.rs  # 5-node simnet test
+-- benches/
|   +-- core_benchmarks.rs        # Criterion benchmarks
+-- fuzz/
|   +-- Cargo.toml                # Fuzz testing config
|   +-- fuzz_targets/             # Fuzz targets (6)
+-- scripts/
|   +-- check.sh                  # Release checklist
|   +-- run_3nodes_local.sh       # Local testnet launcher
|   +-- generate_sbom.sh          # SBOM generation
+-- docs/                         # Documentation
+-- spec/                         # Formal specifications
+-- formal/                       # TLA+ models
+-- api/
|   +-- openapi.yaml              # OpenAPI 3.0.3 spec
+-- .github/
    +-- workflows/
        +-- ci.yml                # CI workflow
        +-- release.yml           # Release workflow
        +-- slsa_release.yml      # SLSA provenance
```

---

*Architecture document for IONA v27.0.0. See also: [OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md), [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md), [SECURITY_MODEL.md](SECURITY_MODEL.md).*
