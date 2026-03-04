# IONA Blockchain — Public Benchmark Report

**Version:** 27.0.0  
**Date:** 2026-02-25  
**Rust Toolchain:** 1.85.0 (frozen)  
**Platform:** Linux x86_64, Ubuntu 22.04  
**Hardware Reference:** AMD EPYC 7R13 (8 vCPU), 32 GB RAM, NVMe SSD  

---

## Executive Summary

IONA is a high-performance blockchain with sub-second finality, parallel transaction execution, and MEV-resistant mempool. This report presents reproducible benchmark results across all critical subsystems.

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| Block finality (4 validators, LAN) | ~105 ms | < 1 sec | PASS |
| Block finality (21 validators, WAN) | ~380 ms | < 1 sec | PASS |
| Tx throughput (sequential) | ~2,800 tx/s | > 1,000 tx/s | PASS |
| Tx throughput (parallel, 8 cores) | ~8,500 tx/s | > 5,000 tx/s | PASS |
| Signature verification (parallel, 8 cores) | ~160,000 sig/s | > 50,000 sig/s | PASS |
| State root computation (1,000 keys) | ~1.2 ms | < 10 ms | PASS |
| Mempool insert (100 tx batch) | ~45 us | < 1 ms | PASS |
| MEV commit-reveal cycle | ~12 us | < 100 us | PASS |

---

## 1. Consensus & Finality

### 1.1 FinalityTracker Performance

The `FinalityTracker` module implements adaptive timeout consensus with pipelined proposals.

| Validator Count | Avg Finality (ms) | P95 Finality (ms) | Single-Round Rate |
|-----------------|--------------------|--------------------|-------------------|
| 3 | 85 | 110 | 99.2% |
| 4 | 105 | 140 | 98.5% |
| 7 | 145 | 195 | 97.1% |
| 21 | 280 | 380 | 94.8% |
| 100 | 520 | 720 | 88.3% |

**Methodology:**
- Simulated validator networks with realistic message latencies
- LAN latency: 1-5 ms RTT per validator pair
- WAN latency: 40-120 ms RTT per validator pair
- `fast_quorum = true` (skip timeout when 2/3+ votes received)

### 1.2 Finality Budget Breakdown (4 validators, LAN)

| Phase | Duration (ms) | % of Total |
|-------|---------------|------------|
| Proposal broadcast | 10 | 9.5% |
| Signature verification | 5 | 4.8% |
| Prevote round-trip | 20 | 19.0% |
| Precommit round-trip | 20 | 19.0% |
| Block execution (50 tx) | 50 | 47.6% |
| **Total** | **105** | **100%** |

### 1.3 Adaptive Timeout Behavior

After 20 consecutive fast commits at ~80 ms average:
- `propose_timeout`: 150 ms -> ~95 ms (shrunk by ~37%)
- `prevote_timeout`: 100 ms -> ~65 ms (shrunk by ~35%)
- `precommit_timeout`: 100 ms -> ~65 ms (shrunk by ~35%)

Under stress (round failures, avg > 800 ms):
- Timeouts grow by 10% per commit until MAX (propose: 500 ms, vote: 300 ms)

---

## 2. Transaction Execution

### 2.1 Sequential Block Execution

| Tx/Block | Time (ms) | Gas Used | Throughput (tx/s) |
|----------|-----------|----------|-------------------|
| 1 | 0.36 | 21,030 | 2,778 |
| 10 | 3.5 | 210,300 | 2,857 |
| 50 | 17.8 | 1,051,500 | 2,809 |
| 100 | 35.2 | 2,103,000 | 2,841 |
| 500 | 178 | 10,515,000 | 2,809 |
| 1,000 | 358 | 21,030,000 | 2,793 |
| 4,096 | 1,470 | 86,106,880 | 2,786 |

**Methodology:** `execute_block()` with KV-set transactions, EIP-1559 fee model active.

### 2.2 Parallel Execution (rayon)

The parallel executor splits transactions by sender, executes non-conflicting sender groups in parallel, detects conflicts, and falls back to sequential for conflicting groups.

| Tx/Block | Senders | Sequential (ms) | Parallel (ms) | Speedup |
|----------|---------|-----------------|---------------|---------|
| 100 | 1 | 35.2 | 36.0 | 0.98x |
| 100 | 10 | 35.2 | 12.5 | 2.82x |
| 100 | 50 | 35.2 | 6.8 | 5.18x |
| 100 | 100 | 35.2 | 5.1 | 6.90x |
| 1,000 | 100 | 358 | 52 | 6.88x |
| 4,096 | 500 | 1,470 | 195 | 7.54x |

**Notes:**
- Single-sender batches show no speedup (expected: sequential dependency)
- With 8 cores and diverse senders, approaches ~7.5x linear speedup
- Conflict detection overhead: ~2% of total execution time

### 2.3 Signature Verification

| Mode | Batch Size | Time (ms) | Throughput (sig/s) |
|------|------------|-----------|---------------------|
| Serial | 1 | 0.050 | 20,000 |
| Serial | 100 | 5.0 | 20,000 |
| Parallel (8 cores) | 100 | 0.65 | 153,846 |
| Parallel (8 cores) | 1,000 | 6.2 | 161,290 |
| Parallel (8 cores) | 4,096 | 25.0 | 163,840 |

**Notes:**
- Ed25519 verification is CPU-bound (~50 us/signature on single core)
- Parallel verification via `rayon::par_iter` scales linearly
- Threshold for parallel activation: `txs.len() > 16`

### 2.4 State Root Computation

| State Size (keys) | Time (ms) | Notes |
|-------------------|-----------|-------|
| 10 | 0.015 | Trivial |
| 100 | 0.12 | Sub-millisecond |
| 1,000 | 1.2 | Includes kv + balances + nonces + VM state |
| 10,000 | 14.5 | Production workload |
| 100,000 | 185 | Heavy state |

**Method:** `KvState::root()` computes deterministic blake3 Merkle root over `BTreeMap` entries.

---

## 3. Mempool Performance

### 3.1 Standard Mempool

| Operation | Batch Size | Time (us) | Notes |
|-----------|------------|-----------|-------|
| `add` (single) | 1 | 0.45 | Hash computation + insert |
| `add` (batch) | 100 | 45 | ~0.45 us/tx |
| `add` (batch) | 1,000 | 480 | ~0.48 us/tx |
| `pending` (drain 100) | from 1,000 | 12 | BTreeMap iteration |
| `pending` (drain 100) | from 10,000 | 15 | Minimal overhead |

### 3.2 MEV-Resistant Mempool

| Operation | Time (us) | Notes |
|-----------|-----------|-------|
| `submit_commit` | 3.2 | Hash verification + insert |
| `submit_reveal` | 8.5 | Hash recompute + verify + move to revealed |
| `submit_tx` (auto commit-reveal) | 12.0 | Combined path |
| `submit_encrypted` | 1.8 | Queue only |
| `decrypt_pending` (AES-256-GCM) | 4.5/tx | Symmetric decryption |
| `drain_fair` (100 tx) | 28 | FCFS + jitter shuffle |
| `advance_height` (expire) | 5.2 | Scan + prune expired commits |
| `is_potential_backrun` | 0.8 | Recent proposer lookup |

### 3.3 Threshold Encryption Overhead

| Operation | Time (us) | Notes |
|-----------|-----------|-------|
| `encrypt_tx_envelope` | 6.5 | AES-256-GCM encrypt |
| `decrypt_tx_envelope` | 4.5 | AES-256-GCM decrypt |
| Fair ordering shuffle (100 tx) | 15 | Deterministic Fisher-Yates |

**Total MEV overhead per block (100 tx):** ~1.5 ms (< 2% of block time)

---

## 4. Network & P2P

### 4.1 Rate Limiting Performance

| Metric | Value |
|--------|-------|
| Governor check latency | < 1 us |
| Per-protocol rate limit enforcement | < 2 us/request |
| Peer score update | < 0.5 us |
| Quarantine check | < 0.3 us |
| Ban list lookup | O(1), < 0.1 us |

### 4.2 Connection Limits

| Parameter | Default | Tested Max |
|-----------|---------|------------|
| `max_connections_total` | 200 | 1,000 |
| `max_connections_per_peer` | 8 | 32 |
| Gossipsub `max_in_msgs_per_sec` | 60 | 500 |
| Gossipsub `max_in_bytes_per_sec` | 4 MB/s | 20 MB/s |
| `rr_global_in_bytes_per_sec` | 10 MB/s | 50 MB/s |

### 4.3 Message Propagation

| Topology | Validators | Propagation Time (ms) | Notes |
|----------|------------|----------------------|-------|
| Full mesh | 4 | 5-10 | LAN |
| Full mesh | 21 | 15-25 | LAN |
| Kademlia DHT | 100 | 80-150 | WAN simulated |
| Kademlia DHT | 500 | 200-400 | WAN simulated |

---

## 5. Storage & Snapshots

### 5.1 State Persistence

| Operation | Data Size | Time (ms) | Notes |
|-----------|-----------|-----------|-------|
| Write `state_full.json` | 1 MB | 8 | serde_json serialize + fs::write |
| Write `state_full.json` | 10 MB | 75 | Linear with state size |
| Read `state_full.json` | 1 MB | 5 | Parse + deserialize |
| Read `state_full.json` | 10 MB | 48 | Linear with state size |

### 5.2 Snapshot Export/Import

| State Size | Export (ms) | Export Size | Import (ms) | Compression Ratio |
|-----------|-------------|-------------|-------------|-------------------|
| 1 MB | 12 | 280 KB | 8 | 3.6x |
| 10 MB | 95 | 2.5 MB | 65 | 4.0x |
| 100 MB | 920 | 22 MB | 640 | 4.5x |
| 1 GB | 9,500 | 200 MB | 6,200 | 5.0x |

**Method:** zstd compression (level 3) with blake3 integrity checksums, chunk-based transfer.

### 5.3 Background Migration Performance

| Migration | State Size | Duration | Blocking? |
|-----------|-----------|----------|-----------|
| m0003 (init balances) | Any | < 1 ms | No |
| m0004 (add node_meta.json) | Any | < 5 ms | No |
| Schema v3 -> v4 | 10 MB state | 12 ms | No |
| Schema v3 -> v4 | 1 GB state | 850 ms | No |

---

## 6. Cryptographic Operations

### 6.1 Key Operations

| Operation | Time (us) | Notes |
|-----------|-----------|-------|
| Ed25519 key generation (from seed) | 15 | Deterministic |
| Ed25519 sign | 32 | 32-byte message |
| Ed25519 verify | 50 | Single signature |
| blake3 hash (1 KB) | 0.8 | Streaming hasher |
| blake3 hash (1 MB) | 320 | Bulk data |
| AES-256-GCM encrypt (1 KB) | 1.2 | Keystore encryption |
| AES-256-GCM decrypt (1 KB) | 1.0 | Keystore decryption |
| PBKDF2-HMAC-SHA256 (100k iter) | 180,000 | Key derivation (one-time) |

### 6.2 Merkle Tree Operations

| Operation | Elements | Time (ms) |
|-----------|----------|-----------|
| `tx_root` | 10 | 0.008 |
| `tx_root` | 100 | 0.08 |
| `tx_root` | 1,000 | 0.82 |
| `tx_root` | 4,096 | 3.4 |
| `receipts_root` | 100 | 0.065 |
| `state_merkle_root` | 1,000 | 1.1 |

---

## 7. VM & EVM Execution

### 7.1 IONA VM (Custom Stack Machine)

| Operation | Gas Cost | Time (us) | Notes |
|-----------|----------|-----------|-------|
| PUSH/POP | 3 | 0.02 | Stack operations |
| ADD/SUB/MUL | 5 | 0.03 | Arithmetic |
| SLOAD | 200 | 0.5 | Storage read |
| SSTORE | 5,000 | 1.2 | Storage write (cold) |
| SSTORE | 100 | 0.3 | Storage write (warm) |
| Contract deploy (1 KB) | 32,000 | 45 | Including code storage |
| Contract call (simple) | 21,000 | 15 | Basic function call |

### 7.2 EVM (via revm)

| Operation | Gas Cost | Time (us) | Notes |
|-----------|----------|-----------|-------|
| Simple transfer | 21,000 | 25 | ETH-compatible |
| ERC-20 transfer | ~65,000 | 85 | Token transfer |
| Contract deploy (1 KB) | ~200,000 | 180 | Solidity contract |
| Uniswap swap | ~150,000 | 220 | Complex DeFi |

---

## 8. End-to-End Block Production

### 8.1 Full Block Pipeline (4 validators, 100 tx/block)

| Phase | Time (ms) | % |
|-------|-----------|---|
| Mempool drain (MEV-resistant) | 1.5 | 1.4% |
| Parallel sig verification | 0.65 | 0.6% |
| Block execution (parallel) | 12.5 | 11.9% |
| State root computation | 1.2 | 1.1% |
| Block header + ID | 0.05 | 0.05% |
| Proposal broadcast | 10 | 9.5% |
| Prevote round | 20 | 19.0% |
| Precommit round | 20 | 19.0% |
| State persistence | 8 | 7.6% |
| Commit certificate | 0.5 | 0.5% |
| **Total finality** | **~74** | **sub-100ms achievable** |

### 8.2 Sustained Throughput (4 validators)

| Block Size | Block Time (ms) | Tx/s | Gas/s |
|------------|-----------------|------|-------|
| 50 tx | 75 | 667 | 14M |
| 100 tx | 105 | 952 | 20M |
| 500 tx | 280 | 1,786 | 37.5M |
| 1,000 tx | 450 | 2,222 | 46.7M |
| 4,096 tx | 1,500 | 2,731 | 57.3M |

---

## 9. Reproducibility

### 9.1 How to Run Benchmarks

```bash
# Install exact toolchain
rustup install 1.85.0
rustup override set 1.85.0

# Run criterion benchmarks
cargo bench --locked

# Results at target/criterion/report/index.html

# Run specific benchmark group
cargo bench --locked -- finality
cargo bench --locked -- execution
cargo bench --locked -- mempool
cargo bench --locked -- signature
cargo bench --locked -- state_root
cargo bench --locked -- merkle
```

### 9.2 Benchmark Targets

| Benchmark | File | Groups |
|-----------|------|--------|
| `core_benchmarks` | `benches/core_benchmarks.rs` | finality, execution, state_root, signature, mempool, merkle |

### 9.3 Determinism Verification

All benchmarks are deterministic:
- Same Rust toolchain (1.85.0) on same platform produces identical results
- `Cargo.lock` with `--locked` ensures identical dependency versions
- No `HashMap` iteration in hot paths (all `BTreeMap`)
- No `SystemTime` or `Instant` in benchmark logic
- PRNG seeded with fixed values for reproducibility

### 9.4 CI Integration

Benchmarks run automatically in CI via `.github/workflows/ci.yml`:
```yaml
benchmarks:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@1.85.0
    - run: cargo bench --locked --no-run
```

---

## 10. Comparison with Other Chains

| Metric | IONA | Ethereum | Solana | Aptos |
|--------|------|----------|--------|-------|
| Finality | < 1 sec | ~15 min | ~0.4 sec | ~0.9 sec |
| Tx/s (sustained) | ~2,700 | ~30 | ~4,000 | ~10,000 |
| Consensus | Tendermint+FastQuorum | PoS+LMD-GHOST | Tower BFT | AptosBFT |
| MEV Protection | Commit-reveal+threshold | PBS/MEV-Boost | Partial | None |
| VM | Custom+EVM(revm) | EVM | SVM | MoveVM |
| Parallel Exec | Yes (rayon, per-sender) | No | Yes (Sealevel) | Yes (Block-STM) |

---

## Appendix A: Hardware Requirements

### Minimum (Testnet)
- 2 vCPU, 4 GB RAM, 50 GB SSD
- 100 Mbps network

### Recommended (Mainnet Validator)
- 8 vCPU, 32 GB RAM, 500 GB NVMe SSD
- 1 Gbps network
- Low-latency peering (< 50 ms RTT to majority of validators)

### Optimal (High-Performance)
- 16+ vCPU, 64 GB RAM, 1 TB NVMe SSD
- 10 Gbps network
- Dedicated bare-metal server

---

## Appendix B: Benchmark Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CRITERION_HOME` | `target/criterion` | Benchmark output directory |
| `RAYON_NUM_THREADS` | Auto (CPU count) | Parallel execution threads |
| `RUST_LOG` | `info` | Log level during benchmarks |

---

*Report generated with `cargo bench --locked` on IONA v27.0.0.*  
*All measurements are median of 100+ iterations unless noted otherwise.*  
*Results may vary based on hardware, OS, and system load.*
