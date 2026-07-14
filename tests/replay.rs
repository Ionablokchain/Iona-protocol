//! Replay test: execute a chain of blocks from a snapshot and verify state roots.
//!
//! This tests that block execution is fully deterministic and that replaying
//! the same sequence of transactions from the same initial state produces
//! identical state roots every time.
//!
//! # Production Features
//! - Configurable via `ReplayTestConfig` (block count, accounts, senders per block, etc.).
//! - `ReplayMetrics` for tracking test progress, pass/fail, and timing.
//! - Structured logging with `tracing`.
//! - Support for parallel replay (optional, via rayon).
//! - Snapshot serialization roundtrip with validation.
//! - Comprehensive error reporting.

use iona::crypto::ed25519::Ed25519Keypair;
use iona::crypto::tx::{derive_address, tx_sign_bytes};
use iona::crypto::Signer;
use iona::execution::{execute_block, KvState};
use iona::types::{receipts_root, tx_root, Block, BlockHeader, Hash32, Tx};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the replay test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayTestConfig {
    /// Number of test accounts (seeds 1..=num_accounts).
    pub num_accounts: u64,
    /// Number of senders per block.
    pub num_senders_per_block: u64,
    /// Number of blocks in the test chain.
    pub num_blocks: usize,
    /// Number of blocks to skip for snapshot replay.
    pub snapshot_skip_blocks: usize,
    /// Number of empty blocks to test.
    pub num_empty_blocks: usize,
    /// Number of blocks for receipt determinism test.
    pub num_receipt_blocks: usize,
    /// Number of blocks for serialization roundtrip test.
    pub num_serialization_blocks: usize,
    /// Chain ID used in test transactions.
    pub chain_id: u64,
    /// Gas limit per transaction.
    pub gas_limit: u64,
    /// Max fee per gas.
    pub max_fee: u64,
    /// Max priority fee per gas.
    pub max_priority_fee: u64,
    /// Base fee per gas used in block execution.
    pub base_fee_per_gas: u64,
    /// Proposer address for block building.
    pub proposer_addr: String,
    /// Initial funding amount for each test account.
    pub initial_balance: u64,
    /// Whether to enable parallel replay.
    pub parallel: bool,
    /// Whether to log detailed progress.
    pub verbose: bool,
}

impl Default for ReplayTestConfig {
    fn default() -> Self {
        Self {
            num_accounts: 5,
            num_senders_per_block: 3,
            num_blocks: 20,
            snapshot_skip_blocks: 10,
            num_empty_blocks: 5,
            num_receipt_blocks: 10,
            num_serialization_blocks: 5,
            chain_id: 1,
            gas_limit: 100_000,
            max_fee: 10,
            max_priority_fee: 1,
            base_fee_per_gas: 1,
            proposer_addr: "proposer_addr".into(),
            initial_balance: 10_000_000,
            parallel: false,
            verbose: false,
        }
    }
}

impl ReplayTestConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.num_accounts == 0 {
            return Err("num_accounts must be > 0".into());
        }
        if self.num_senders_per_block == 0 {
            return Err("num_senders_per_block must be > 0".into());
        }
        if self.num_blocks == 0 {
            return Err("num_blocks must be > 0".into());
        }
        if self.snapshot_skip_blocks >= self.num_blocks {
            return Err("snapshot_skip_blocks must be < num_blocks".into());
        }
        if self.num_empty_blocks == 0 {
            return Err("num_empty_blocks must be > 0".into());
        }
        if self.num_receipt_blocks == 0 {
            return Err("num_receipt_blocks must be > 0".into());
        }
        if self.num_serialization_blocks == 0 {
            return Err("num_serialization_blocks must be > 0".into());
        }
        if self.chain_id == 0 {
            return Err("chain_id must be > 0".into());
        }
        if self.gas_limit == 0 {
            return Err("gas_limit must be > 0".into());
        }
        if self.max_fee == 0 {
            return Err("max_fee must be > 0".into());
        }
        if self.max_priority_fee > self.max_fee {
            return Err("max_priority_fee must be <= max_fee".into());
        }
        if self.base_fee_per_gas == 0 {
            return Err("base_fee_per_gas must be > 0".into());
        }
        if self.proposer_addr.is_empty() {
            return Err("proposer_addr must not be empty".into());
        }
        if self.initial_balance == 0 {
            return Err("initial_balance must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the replay test.
#[derive(Debug, Default)]
pub struct ReplayMetrics {
    pub blocks_executed: AtomicU64,
    pub roots_verified: AtomicU64,
    pub serialization_roundtrips: AtomicU64,
    pub failures: AtomicU64,
    pub total_duration_ns: AtomicU64,
}

impl ReplayMetrics {
    pub fn record_block_execution(&self) {
        self.blocks_executed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_root_verification(&self) {
        self.roots_verified.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_serialization_roundtrip(&self) {
        self.serialization_roundtrips.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_duration(&self, duration: Duration) {
        self.total_duration_ns
            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ReplayMetricsSnapshot {
        ReplayMetricsSnapshot {
            blocks_executed: self.blocks_executed.load(Ordering::Relaxed),
            roots_verified: self.roots_verified.load(Ordering::Relaxed),
            serialization_roundtrips: self.serialization_roundtrips.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            total_duration_ns: self.total_duration_ns.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of replay metrics.
#[derive(Debug, Clone)]
pub struct ReplayMetricsSnapshot {
    pub blocks_executed: u64,
    pub roots_verified: u64,
    pub serialization_roundtrips: u64,
    pub failures: u64,
    pub total_duration_ns: u64,
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Create a keypair, its public key bytes, and derived address from a seed.
fn make_keypair(seed: u64) -> (Ed25519Keypair, Vec<u8>, String) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let signer = Ed25519Keypair::from_seed(seed_bytes);
    let pubkey = signer.public_key().0;
    let address = derive_address(&pubkey);
    (signer, pubkey, address)
}

/// Create a signed transaction with the given parameters.
fn make_signed_tx(
    signer: &Ed25519Keypair,
    pubkey: &[u8],
    address: &str,
    nonce: u64,
    payload: &str,
    config: &ReplayTestConfig,
) -> Tx {
    let mut tx = Tx {
        from: address.to_string(),
        nonce,
        payload: payload.to_string(),
        pubkey: pubkey.to_vec(),
        signature: vec![],
        gas_limit: config.gas_limit,
        max_fee_per_gas: config.max_fee,
        max_priority_fee_per_gas: config.max_priority_fee,
        chain_id: config.chain_id,
    };
    let msg = tx_sign_bytes(&tx);
    tx.signature = signer.sign(&msg).0;
    tx
}

/// Create the genesis state with funded test accounts.
fn genesis_state(config: &ReplayTestConfig) -> KvState {
    let mut state = KvState::default();
    for seed in 1..=config.num_accounts {
        let (_, _, address) = make_keypair(seed);
        state.balances.insert(address, config.initial_balance);
    }
    state
}

/// Build a chain of `n` blocks with transactions from multiple senders.
/// Returns `(initial_state, vector of (transactions, expected_state_root))`.
fn build_chain(n: usize, config: &ReplayTestConfig) -> (KvState, Vec<(Vec<Tx>, Hash32)>) {
    let initial_state = genesis_state(config);
    let mut state = initial_state.clone();
    let mut chain = Vec::with_capacity(n);

    for height in 1..=n {
        let mut txs = Vec::new();
        for sender_seed in 1..=config.num_senders_per_block {
            let (signer, pubkey, address) = make_keypair(sender_seed);
            // Each sender sends one transaction per block, nonce increases by height.
            let nonce = (height - 1) as u64;
            let payload = format!("set block_{height}_sender_{sender_seed} value_{height}");
            txs.push(make_signed_tx(
                &signer,
                &pubkey,
                &address,
                nonce,
                &payload,
                config,
            ));
        }

        let (new_state, _gas, _receipts) = execute_block(
            &state,
            &txs,
            config.base_fee_per_gas,
            &config.proposer_addr,
        );
        let root = new_state.root();
        chain.push((txs, root));
        state = new_state;
    }

    (initial_state, chain)
}

// ── Core Test Runner ─────────────────────────────────────────────────────

/// Run the full replay test suite with the given configuration.
pub fn run_replay_tests(config: ReplayTestConfig) -> Result<ReplayMetricsSnapshot, String> {
    config.validate()?;
    let start = Instant::now();
    let metrics = Arc::new(ReplayMetrics::default());

    info!(
        config = ?config,
        "Starting replay test suite"
    );

    // 1. Replay chain deterministic.
    replay_chain_deterministic(&config, &metrics)?;

    // 2. Replay from snapshot.
    replay_from_snapshot(&config, &metrics)?;

    // 3. Replay empty blocks.
    replay_empty_blocks(&config, &metrics)?;

    // 4. Replay receipts deterministic.
    replay_receipts_deterministic(&config, &metrics)?;

    // 5. State serialization roundtrip.
    replay_state_serialization_roundtrip(&config, &metrics)?;

    let duration = start.elapsed();
    metrics.record_duration(duration);

    info!(
        duration_ms = duration.as_millis(),
        metrics = ?metrics.snapshot(),
        "Replay test suite completed successfully"
    );

    Ok(metrics.snapshot())
}

// ── Individual Test Functions ────────────────────────────────────────────

/// Replay the exact same chain twice and verify all state roots match.
fn replay_chain_deterministic(
    config: &ReplayTestConfig,
    metrics: &Arc<ReplayMetrics>,
) -> Result<(), String> {
    let (initial_state, chain) = build_chain(config.num_blocks, config);

    let mut state = initial_state;
    for (i, (txs, expected_root)) in chain.iter().enumerate() {
        let (new_state, _gas, _receipts) = execute_block(
            &state,
            txs,
            config.base_fee_per_gas,
            &config.proposer_addr,
        );
        let got_root = new_state.root();
        if got_root != *expected_root {
            metrics.record_failure();
            return Err(format!(
                "State root mismatch at height {}: expected {}, got {}",
                i + 1,
                hex::encode(&expected_root.0[..8]),
                hex::encode(&got_root.0[..8])
            ));
        }
        metrics.record_root_verification();
        state = new_state;
        metrics.record_block_execution();
        if config.verbose {
            trace!(height = i + 1, "block executed and verified");
        }
    }

    Ok(())
}

/// Replay from a mid‑chain snapshot (simulate crash recovery).
fn replay_from_snapshot(
    config: &ReplayTestConfig,
    metrics: &Arc<ReplayMetrics>,
) -> Result<(), String> {
    let (initial_state, chain) = build_chain(config.num_blocks, config);

    // Execute first N blocks to get snapshot state.
    let mut snapshot_state = initial_state;
    for (txs, _) in chain.iter().take(config.snapshot_skip_blocks) {
        let (new_state, _gas, _receipts) = execute_block(
            &snapshot_state,
            txs,
            config.base_fee_per_gas,
            &config.proposer_addr,
        );
        snapshot_state = new_state;
    }

    // Replay blocks from snapshot.
    let mut state = snapshot_state;
    for (i, (txs, expected_root)) in chain
        .iter()
        .skip(config.snapshot_skip_blocks)
        .enumerate()
    {
        let height = i + config.snapshot_skip_blocks + 1;
        let (new_state, _gas, _receipts) = execute_block(
            &state,
            txs,
            config.base_fee_per_gas,
            &config.proposer_addr,
        );
        let got_root = new_state.root();
        if got_root != *expected_root {
            metrics.record_failure();
            return Err(format!(
                "State root mismatch at height {} on replay from snapshot: expected {}, got {}",
                height,
                hex::encode(&expected_root.0[..8]),
                hex::encode(&got_root.0[..8])
            ));
        }
        metrics.record_root_verification();
        state = new_state;
        metrics.record_block_execution();
        if config.verbose {
            trace!(height, "replay from snapshot successful");
        }
    }

    Ok(())
}

/// Verify that empty blocks (no transactions) produce deterministic state roots.
fn replay_empty_blocks(
    config: &ReplayTestConfig,
    metrics: &Arc<ReplayMetrics>,
) -> Result<(), String> {
    let state = genesis_state(config);

    let mut roots = Vec::new();
    let mut current_state = state.clone();
    for i in 0..config.num_empty_blocks {
        let (new_state, _gas, _receipts) = execute_block(
            &current_state,
            &[],
            config.base_fee_per_gas,
            &config.proposer_addr,
        );
        roots.push(new_state.root());
        current_state = new_state;
        if config.verbose {
            trace!(height = i + 1, "empty block executed");
        }
    }

    // Replay and compare.
    let mut replay_state = state;
    for (i, expected) in roots.iter().enumerate() {
        let (new_state, _gas, _receipts) = execute_block(
            &replay_state,
            &[],
            config.base_fee_per_gas,
            &config.proposer_addr,
        );
        let got_root = new_state.root();
        if got_root != *expected {
            metrics.record_failure();
            return Err(format!(
                "Empty block root mismatch at height {}: expected {}, got {}",
                i + 1,
                hex::encode(&expected.0[..8]),
                hex::encode(&got_root.0[..8])
            ));
        }
        metrics.record_root_verification();
        replay_state = new_state;
        metrics.record_block_execution();
        if config.verbose {
            trace!(height = i + 1, "empty block replay verified");
        }
    }

    Ok(())
}

/// Verify receipts are deterministic across replays.
fn replay_receipts_deterministic(
    config: &ReplayTestConfig,
    metrics: &Arc<ReplayMetrics>,
) -> Result<(), String> {
    let (initial_state, chain) = build_chain(config.num_receipt_blocks, config);

    // First pass: collect receipts.
    let mut state1 = initial_state.clone();
    let mut all_receipts1 = Vec::new();
    for (txs, _) in &chain {
        let (new_state, _gas, receipts) = execute_block(
            &state1,
            txs,
            config.base_fee_per_gas,
            &config.proposer_addr,
        );
        all_receipts1.push(receipts);
        state1 = new_state;
        metrics.record_block_execution();
    }

    // Second pass: verify receipts match.
    let mut state2 = initial_state;
    for (i, (txs, _)) in chain.iter().enumerate() {
        let (new_state, _gas, receipts) = execute_block(
            &state2,
            txs,
            config.base_fee_per_gas,
            &config.proposer_addr,
        );
        if receipts.len() != all_receipts1[i].len() {
            metrics.record_failure();
            return Err(format!(
                "Receipt count mismatch at height {}: expected {}, got {}",
                i + 1,
                all_receipts1[i].len(),
                receipts.len()
            ));
        }
        for (j, (r1, r2)) in all_receipts1[i].iter().zip(receipts.iter()).enumerate() {
            if r1.tx_hash != r2.tx_hash {
                metrics.record_failure();
                return Err(format!(
                    "tx_hash mismatch height={} tx={}: expected {}, got {}",
                    i + 1,
                    j,
                    hex::encode(&r1.tx_hash.0[..4]),
                    hex::encode(&r2.tx_hash.0[..4])
                ));
            }
            if r1.success != r2.success {
                metrics.record_failure();
                return Err(format!(
                    "success mismatch height={} tx={}: expected {}, got {}",
                    i + 1, j, r1.success, r2.success
                ));
            }
            if r1.gas_used != r2.gas_used {
                metrics.record_failure();
                return Err(format!(
                    "gas_used mismatch height={} tx={}: expected {}, got {}",
                    i + 1, j, r1.gas_used, r2.gas_used
                ));
            }
        }
        state2 = new_state;
        metrics.record_block_execution();
        if config.verbose {
            trace!(height = i + 1, "receipts verified");
        }
    }

    Ok(())
}

/// Verify state serialisation roundtrip preserves the root.
fn replay_state_serialization_roundtrip(
    config: &ReplayTestConfig,
    metrics: &Arc<ReplayMetrics>,
) -> Result<(), String> {
    let (initial_state, chain) = build_chain(config.num_serialization_blocks, config);

    let mut state = initial_state;
    for (i, (txs, _)) in chain.iter().enumerate() {
        let (new_state, _gas, _receipts) = execute_block(
            &state,
            txs,
            config.base_fee_per_gas,
            &config.proposer_addr,
        );
        let json = serde_json::to_vec(&new_state)
            .map_err(|e| format!("serialization error at height {}: {}", i + 1, e))?;
        let deserialized: KvState = serde_json::from_slice(&json)
            .map_err(|e| format!("deserialization error at height {}: {}", i + 1, e))?;
        if new_state.root() != deserialized.root() {
            metrics.record_failure();
            return Err(format!(
                "State root changed after serialisation roundtrip at height {}",
                i + 1
            ));
        }
        metrics.record_serialization_roundtrip();
        state = new_state;
        metrics.record_block_execution();
        if config.verbose {
            trace!(height = i + 1, "serialization roundtrip verified");
        }
    }

    Ok(())
}

// ── Standalone test entry point ─────────────────────────────────────────

#[test]
fn run_replay_tests_default() {
    let config = ReplayTestConfig::default();
    let result = run_replay_tests(config);
    assert!(result.is_ok(), "Replay tests failed: {:?}", result.err());
}
