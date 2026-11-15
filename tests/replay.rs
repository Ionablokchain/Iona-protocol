//! Replay test: execute a chain of blocks from a snapshot and verify state roots.
//!
//! Verifies that block execution is deterministic and — the deeper
//! property — that state evolution is **Markovian**: the state produced
//! by executing blocks N+1..=M from the state at N depends only on that
//! state, not on the history that produced it, and not on whether the
//! state was carried in memory or serialized to disk and reloaded.
//!
//! # What is verified
//!
//! * **Determinism** — the same chain, executed twice, produces the
//!   same per-height state roots.
//! * **Intermediate-state replay** — executing blocks 1..=N then N+1..=M
//!   produces the same final state as executing 1..=M in one pass.
//! * **Serialized-snapshot replay** — serializing the state at N,
//!   reloading it, and executing N+1..=M produces the same roots as the
//!   in-memory path. This is the actual crash-recovery test.
//! * **Empty-block determinism** — empty blocks don't perturb the state
//!   root differently across runs.
//! * **Receipt determinism** — receipts are byte-identical across two
//!   runs of the same chain.
//!
//! # What is **not** verified here
//!
//! * Cross-machine determinism (e.g., between x86-64 and aarch64).
//!   That is the responsibility of `tests/golden_vectors.rs`, which
//!   pins exact hashes.
//! * Fee/gas arithmetic beyond what `execute_block` computes internally.
//!   Covered in `tests/integration.rs`.
//!
//! # Verbose output
//!
//! `ReplayTestConfig::verbose` gates `tracing::trace!` calls. **No
//! tracing subscriber is installed by this file.** A caller that wants
//! the trace output must install one (e.g.
//! `tracing_subscriber::fmt::init()`) before invoking any `#[test]` in
//! this module. Otherwise `verbose = true` has no visible effect.
//!
//! Run with: `cargo test --test replay`
//! Run with trace output:
//!     `RUST_LOG=trace cargo test --test replay -- --nocapture`

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use iona::crypto::ed25519::Ed25519Keypair;
use iona::crypto::tx::{derive_address, tx_sign_bytes};
use iona::crypto::Signer;
use iona::execution::{execute_block, KvState};
use iona::types::{Hash32, Tx};
use serde::{Deserialize, Serialize};
use tracing::{info, trace};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayTestConfig {
    /// Number of funded test accounts (seeds `1..=num_accounts`).
    pub num_accounts: u64,

    /// Senders per block. Must not exceed `num_accounts`.
    pub num_senders_per_block: u64,

    /// Number of blocks in the primary determinism chain.
    pub num_blocks: usize,

    /// Blocks to execute before the "snapshot" point. Must be
    /// `0 < snapshot_skip_blocks < num_blocks`.
    pub snapshot_skip_blocks: usize,

    /// Number of empty blocks to exercise.
    pub num_empty_blocks: usize,

    /// Number of blocks for the receipt-determinism chain.
    pub num_receipt_blocks: usize,

    /// Chain ID used in test transactions.
    pub chain_id: u64,

    /// Gas limit per transaction.
    pub gas_limit: u64,

    /// Maximum fee per gas.
    pub max_fee: u64,

    /// Maximum priority fee per gas; must not exceed `max_fee`.
    pub max_priority_fee: u64,

    /// Base fee per gas used during execution.
    pub base_fee_per_gas: u64,

    /// Proposer address used during block execution.
    pub proposer_addr: String,

    /// Starting balance for each funded account.
    pub initial_balance: u64,

    /// Gate `tracing::trace!` calls. **Requires a tracing subscriber
    /// to be installed by the caller** for the logs to be visible.
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
            chain_id: 1,
            gas_limit: 100_000,
            max_fee: 10,
            max_priority_fee: 1,
            base_fee_per_gas: 1,
            proposer_addr: "proposer_addr".into(),
            initial_balance: 10_000_000,
            verbose: false,
        }
    }
}

impl ReplayTestConfig {
    pub fn validate(&self) -> Result<(), String> {
        let must_be_positive = [
            ("num_accounts", self.num_accounts),
            ("num_senders_per_block", self.num_senders_per_block),
            ("chain_id", self.chain_id),
            ("gas_limit", self.gas_limit),
            ("max_fee", self.max_fee),
            ("base_fee_per_gas", self.base_fee_per_gas),
            ("initial_balance", self.initial_balance),
        ];
        for (name, value) in must_be_positive {
            if value == 0 {
                return Err(format!("{name} must be > 0"));
            }
        }

        // Senders must be a subset of the funded accounts, otherwise
        // block execution silently fails every transaction from an
        // unfunded sender and the determinism test passes on
        // garbage.
        if self.num_senders_per_block > self.num_accounts {
            return Err(format!(
                "num_senders_per_block ({}) must not exceed num_accounts ({})",
                self.num_senders_per_block, self.num_accounts,
            ));
        }

        if self.num_blocks == 0 {
            return Err("num_blocks must be > 0".into());
        }
        if self.snapshot_skip_blocks == 0 {
            return Err("snapshot_skip_blocks must be > 0".into());
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
        if self.max_priority_fee > self.max_fee {
            return Err("max_priority_fee must be <= max_fee".into());
        }
        if self.proposer_addr.is_empty() {
            return Err("proposer_addr must not be empty".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ReplayMetrics {
    blocks_executed:        AtomicU64,
    roots_verified:         AtomicU64,
    serialization_roundtrips: AtomicU64,
    failures:               AtomicU64,
    total_duration_ns:      AtomicU64,
}

impl ReplayMetrics {
    pub fn record_block(&self) {
        self.blocks_executed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_root(&self) {
        self.roots_verified.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_serialization(&self) {
        self.serialization_roundtrips.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_duration(&self, d: Duration) {
        self.total_duration_ns.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
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

#[derive(Debug, Clone)]
pub struct ReplayMetricsSnapshot {
    pub blocks_executed: u64,
    pub roots_verified: u64,
    pub serialization_roundtrips: u64,
    pub failures: u64,
    pub total_duration_ns: u64,
}

// ---------------------------------------------------------------------------
// Fixture construction
// ---------------------------------------------------------------------------

fn make_keypair(seed: u64) -> (Ed25519Keypair, Vec<u8>, String) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let signer = Ed25519Keypair::from_seed(seed_bytes);
    let pubkey = signer.public_key().0;
    let address = derive_address(&pubkey);
    (signer, pubkey, address)
}

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

fn genesis_state(config: &ReplayTestConfig) -> KvState {
    let mut state = KvState::default();
    for seed in 1..=config.num_accounts {
        let (_, _, address) = make_keypair(seed);
        state.balances.insert(address, config.initial_balance);
    }
    state
}

/// Build a chain of `n` blocks. Returns the genesis state and, for each
/// block, its transactions plus the state root produced by executing it
/// from the running chain state.
///
/// Nonce per sender increases by exactly one per block, which is
/// correct because every sender in `1..=num_senders_per_block` submits
/// exactly one transaction per block.
fn build_chain(n: usize, config: &ReplayTestConfig) -> (KvState, Vec<(Vec<Tx>, Hash32)>) {
    let initial_state = genesis_state(config);
    let mut state = initial_state.clone();
    let mut chain = Vec::with_capacity(n);

    for height in 1..=n {
        let mut txs = Vec::with_capacity(config.num_senders_per_block as usize);
        for sender_seed in 1..=config.num_senders_per_block {
            let (signer, pubkey, address) = make_keypair(sender_seed);
            // Sender's transaction count before this block.
            let nonce = (height - 1) as u64;
            let payload = format!("set block_{height}_sender_{sender_seed} value_{height}");
            txs.push(make_signed_tx(
                &signer, &pubkey, &address, nonce, &payload, config,
            ));
        }
        let (new_state, _gas, _receipts) =
            execute_block(&state, &txs, config.base_fee_per_gas, &config.proposer_addr);
        chain.push((txs, new_state.root()));
        state = new_state;
    }

    (initial_state, chain)
}

// ---------------------------------------------------------------------------
// Entry point (runs all sub-tests sequentially)
//
// Kept for callers that want to run the whole suite in one shot. Each
// sub-test also exists as its own `#[test]` below, so `cargo test` will
// run them in parallel.
// ---------------------------------------------------------------------------

pub fn run_replay_tests(config: ReplayTestConfig) -> Result<ReplayMetricsSnapshot, String> {
    config.validate()?;
    let start = Instant::now();
    let metrics = Arc::new(ReplayMetrics::default());

    info!(config = ?config, "starting replay test suite");

    replay_chain_deterministic(&config, &metrics)?;
    replay_from_intermediate_state(&config, &metrics)?;
    replay_from_serialized_snapshot(&config, &metrics)?;
    replay_empty_blocks(&config, &metrics)?;
    replay_receipts_deterministic(&config, &metrics)?;

    let duration = start.elapsed();
    metrics.record_duration(duration);

    info!(
        duration_ms = duration.as_millis(),
        metrics = ?metrics.snapshot(),
        "replay test suite completed"
    );

    Ok(metrics.snapshot())
}

// ---------------------------------------------------------------------------
// Sub-tests
// ---------------------------------------------------------------------------

/// Execute the chain twice from genesis and verify every per-height root
/// matches. Fails if `execute_block` is non-deterministic in-process.
fn replay_chain_deterministic(
    config: &ReplayTestConfig,
    metrics: &Arc<ReplayMetrics>,
) -> Result<(), String> {
    let (initial_state, chain) = build_chain(config.num_blocks, config);

    let mut state = initial_state;
    for (i, (txs, expected_root)) in chain.iter().enumerate() {
        let (new_state, _gas, _receipts) =
            execute_block(&state, txs, config.base_fee_per_gas, &config.proposer_addr);
        let got_root = new_state.root();
        if got_root != *expected_root {
            metrics.record_failure();
            return Err(format!(
                "state root mismatch at height {}: expected {}, got {}",
                i + 1,
                hex_prefix(&expected_root),
                hex_prefix(&got_root),
            ));
        }
        metrics.record_root();
        metrics.record_block();
        state = new_state;
        if config.verbose {
            trace!(height = i + 1, "block executed and verified");
        }
    }
    Ok(())
}

/// Execute blocks 1..=N, then continue from the resulting state through
/// blocks N+1..=M. Verifies that the state at each height is identical
/// to what a single-pass execution produces — the Markov property.
fn replay_from_intermediate_state(
    config: &ReplayTestConfig,
    metrics: &Arc<ReplayMetrics>,
) -> Result<(), String> {
    let (initial_state, chain) = build_chain(config.num_blocks, config);

    // First pass: execute up to and including the snapshot point.
    let mut intermediate = initial_state;
    for (txs, _) in chain.iter().take(config.snapshot_skip_blocks) {
        let (new_state, _gas, _receipts) =
            execute_block(&intermediate, txs, config.base_fee_per_gas, &config.proposer_addr);
        intermediate = new_state;
    }

    // Second pass: continue from the intermediate state.
    let mut state = intermediate;
    for (i, (txs, expected_root)) in chain
        .iter()
        .skip(config.snapshot_skip_blocks)
        .enumerate()
    {
        let height = i + config.snapshot_skip_blocks + 1;
        let (new_state, _gas, _receipts) =
            execute_block(&state, txs, config.base_fee_per_gas, &config.proposer_addr);
        let got_root = new_state.root();
        if got_root != *expected_root {
            metrics.record_failure();
            return Err(format!(
                "state root mismatch at height {height} after intermediate-state replay: \
                 expected {}, got {}",
                hex_prefix(&expected_root),
                hex_prefix(&got_root),
            ));
        }
        metrics.record_root();
        metrics.record_block();
        state = new_state;
        if config.verbose {
            trace!(height, "intermediate-state replay verified");
        }
    }
    Ok(())
}

/// The crash-recovery test: execute blocks 1..=N, serialize the state,
/// reload it, and execute N+1..=M from the reloaded state. Verifies
/// that (a) the serialized form is faithful and (b) continuing from it
/// produces the same roots as the in-memory path.
fn replay_from_serialized_snapshot(
    config: &ReplayTestConfig,
    metrics: &Arc<ReplayMetrics>,
) -> Result<(), String> {
    let (initial_state, chain) = build_chain(config.num_blocks, config);

    // First pass: execute up to the snapshot point.
    let mut state = initial_state;
    for (txs, _) in chain.iter().take(config.snapshot_skip_blocks) {
        let (new_state, _gas, _receipts) =
            execute_block(&state, txs, config.base_fee_per_gas, &config.proposer_addr);
        state = new_state;
    }

    // Serialize the state. This is what a crash-recovery snapshot would
    // persist to disk.
    let snapshot_bytes = serde_json::to_vec(&state).map_err(|e| {
        metrics.record_failure();
        format!("snapshot serialization failed at height {}: {e}", config.snapshot_skip_blocks)
    })?;

    // Reload. This is what a restarted node would read back.
    let mut reloaded: KvState = serde_json::from_slice(&snapshot_bytes).map_err(|e| {
        metrics.record_failure();
        format!("snapshot deserialization failed: {e}")
    })?;

    // The reloaded state must have the same root as the in-memory state
    // it was serialized from.
    if reloaded.root() != state.root() {
        metrics.record_failure();
        return Err(format!(
            "state root changed across snapshot round-trip at height {}: \
             before {}, after {}",
            config.snapshot_skip_blocks,
            hex_prefix(&state.root()),
            hex_prefix(&reloaded.root()),
        ));
    }
    metrics.record_serialization();

    // Continue executing from the reloaded state and verify roots.
    for (i, (txs, expected_root)) in chain
        .iter()
        .skip(config.snapshot_skip_blocks)
        .enumerate()
    {
        let height = i + config.snapshot_skip_blocks + 1;
        let (new_state, _gas, _receipts) =
            execute_block(&reloaded, txs, config.base_fee_per_gas, &config.proposer_addr);
        let got_root = new_state.root();
        if got_root != *expected_root {
            metrics.record_failure();
            return Err(format!(
                "state root mismatch at height {height} after serialized-snapshot replay: \
                 expected {}, got {}",
                hex_prefix(&expected_root),
                hex_prefix(&got_root),
            ));
        }
        metrics.record_root();
        metrics.record_block();
        reloaded = new_state;
        if config.verbose {
            trace!(height, "serialized-snapshot replay verified");
        }
    }
    Ok(())
}

fn replay_empty_blocks(
    config: &ReplayTestConfig,
    metrics: &Arc<ReplayMetrics>,
) -> Result<(), String> {
    let initial = genesis_state(config);

    // First pass: collect roots from executing empty blocks.
    let mut expected_roots = Vec::with_capacity(config.num_empty_blocks);
    let mut state = initial.clone();
    for _ in 0..config.num_empty_blocks {
        let (new_state, _gas, _receipts) =
            execute_block(&state, &[], config.base_fee_per_gas, &config.proposer_addr);
        expected_roots.push(new_state.root());
        state = new_state;
    }

    // Second pass: replay from genesis and compare.
    let mut state = initial;
    for (i, expected) in expected_roots.iter().enumerate() {
        let (new_state, _gas, _receipts) =
            execute_block(&state, &[], config.base_fee_per_gas, &config.proposer_addr);
        let got = new_state.root();
        if got != *expected {
            metrics.record_failure();
            return Err(format!(
                "empty block root mismatch at height {}: expected {}, got {}",
                i + 1,
                hex_prefix(expected),
                hex_prefix(&got),
            ));
        }
        metrics.record_root();
        metrics.record_block();
        state = new_state;
    }
    Ok(())
}

fn replay_receipts_deterministic(
    config: &ReplayTestConfig,
    metrics: &Arc<ReplayMetrics>,
) -> Result<(), String> {
    let (initial_state, chain) = build_chain(config.num_receipt_blocks, config);

    // Pass 1: collect receipts.
    let mut state = initial_state.clone();
    let mut first_pass = Vec::with_capacity(chain.len());
    for (txs, _) in &chain {
        let (new_state, _gas, receipts) =
            execute_block(&state, txs, config.base_fee_per_gas, &config.proposer_addr);
        first_pass.push(receipts);
        state = new_state;
        metrics.record_block();
    }

    // Pass 2: recompute and compare.
    let mut state = initial_state;
    for (i, (txs, _)) in chain.iter().enumerate() {
        let (new_state, _gas, receipts) =
            execute_block(&state, txs, config.base_fee_per_gas, &config.proposer_addr);

        let expected = &first_pass[i];
        if receipts.len() != expected.len() {
            metrics.record_failure();
            return Err(format!(
                "receipt count mismatch at height {}: expected {}, got {}",
                i + 1, expected.len(), receipts.len(),
            ));
        }
        for (j, (e, g)) in expected.iter().zip(receipts.iter()).enumerate() {
            if e.tx_hash != g.tx_hash {
                metrics.record_failure();
                return Err(format!(
                    "tx_hash mismatch at height {} tx {}: expected {}, got {}",
                    i + 1, j, hex_prefix(&e.tx_hash), hex_prefix(&g.tx_hash),
                ));
            }
            if e.success != g.success {
                metrics.record_failure();
                return Err(format!(
                    "success mismatch at height {} tx {}: expected {}, got {}",
                    i + 1, j, e.success, g.success,
                ));
            }
            if e.gas_used != g.gas_used {
                metrics.record_failure();
                return Err(format!(
                    "gas_used mismatch at height {} tx {}: expected {}, got {}",
                    i + 1, j, e.gas_used, g.gas_used,
                ));
            }
        }
        state = new_state;
        metrics.record_block();
    }
    Ok(())
}

fn hex_prefix(h: &Hash32) -> String {
    hex::encode(&h.0[..8])
}

// ---------------------------------------------------------------------------
// #[test] entry points
//
// Each sub-test gets its own `#[test]` so `cargo test` can run them in
// parallel and so a failure names the property it broke without needing
// to decode the error string.
// ---------------------------------------------------------------------------

#[test]
fn test_config_validates_default() {
    ReplayTestConfig::default()
        .validate()
        .expect("default config must be valid");
}

#[test]
fn test_config_rejects_oversized_sender_set() {
    let mut config = ReplayTestConfig::default();
    config.num_senders_per_block = config.num_accounts + 1;
    assert!(
        config.validate().is_err(),
        "config with more senders than accounts must be rejected",
    );
}

#[test]
fn test_config_rejects_zero_snapshot_skip() {
    let mut config = ReplayTestConfig::default();
    config.snapshot_skip_blocks = 0;
    assert!(config.validate().is_err(), "zero snapshot_skip must be rejected");
}

#[test]
fn test_config_rejects_skip_beyond_chain() {
    let mut config = ReplayTestConfig::default();
    config.snapshot_skip_blocks = config.num_blocks;
    assert!(
        config.validate().is_err(),
        "snapshot_skip_blocks >= num_blocks must be rejected",
    );
}

#[test]
fn test_replay_chain_deterministic() {
    let config = ReplayTestConfig::default();
    config.validate().unwrap();
    let metrics = Arc::new(ReplayMetrics::default());
    replay_chain_deterministic(&config, &metrics).expect("chain must be deterministic");
    assert!(metrics.snapshot().failures == 0);
}

#[test]
fn test_replay_from_intermediate_state() {
    let config = ReplayTestConfig::default();
    config.validate().unwrap();
    let metrics = Arc::new(ReplayMetrics::default());
    replay_from_intermediate_state(&config, &metrics)
        .expect("intermediate-state replay must succeed");
}

#[test]
fn test_replay_from_serialized_snapshot() {
    let config = ReplayTestConfig::default();
    config.validate().unwrap();
    let metrics = Arc::new(ReplayMetrics::default());
    replay_from_serialized_snapshot(&config, &metrics)
        .expect("serialized-snapshot replay must succeed");
    let snap = metrics.snapshot();
    assert!(snap.serialization_roundtrips >= 1, "must have done a round-trip");
}

#[test]
fn test_replay_empty_blocks() {
    let config = ReplayTestConfig::default();
    config.validate().unwrap();
    let metrics = Arc::new(ReplayMetrics::default());
    replay_empty_blocks(&config, &metrics).expect("empty-block replay must succeed");
}

#[test]
fn test_replay_receipts_deterministic() {
    let config = ReplayTestConfig::default();
    config.validate().unwrap();
    let metrics = Arc::new(ReplayMetrics::default());
    replay_receipts_deterministic(&config, &metrics).expect("receipts must be deterministic");
}

#[test]
fn run_replay_tests_default() {
    let config = ReplayTestConfig::default();
    let result = run_replay_tests(config);
    assert!(result.is_ok(), "replay test suite failed: {:?}", result.err());
    let snap = result.unwrap();
    assert_eq!(snap.failures, 0, "no failures expected in default run");
}
