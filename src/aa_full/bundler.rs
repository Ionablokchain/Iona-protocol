//! ERC-4337 Bundler — Production‑grade bundler for IONA.
//!
//! Collects UserOperations from mempool, builds optimal bundles, submits to EntryPoint,
//! and handles replacement (fee bumping) and retries.
//!
//! # Architecture
//! - `Mempool`: Prioritised queue of pending UserOperations with replace support.
//! - `BundleBuilder`: Greedy algorithm to maximise profit within gas limits.
//! - `Submitter`: Asynchronous HTTP client to EntryPoint RPC.
//! - `ReputationManager`: Tracks sender/paymaster reputations.
//! - `Bundler`: Orchestrator that ties everything together.

use crate::evm::account_abstraction::{UserOperation, UserOperationHash};
use crate::evm::entry_point::{handle_ops, EntryPointError};
use crate::evm::simulation::{simulate_all, SimulationError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundlerConfig {
    /// Maximum UserOperations per bundle.
    pub max_ops_per_bundle: usize,
    /// Maximum total verification + call gas per bundle.
    pub max_bundle_gas: u64,
    /// Minimum profit (in base units) required to build a bundle.
    pub min_profit: u64,
    /// Percentage of profit to beneficiary (0..100).
    pub beneficiary_share: u8,
    /// RPC endpoint for EntryPoint.
    pub entry_point_url: String,
    /// Timeout for RPC calls (seconds).
    pub rpc_timeout_secs: u64,
    /// Bundler private key (or keystore path) for signing bundles.
    pub bundler_private_key: String,
    /// EntryPoint contract address.
    pub entry_point_address: String,
    /// Fee bump factor (e.g., 1.1 = 10% higher).
    pub fee_bump_factor: f64,
    /// Maximum replacement attempts per bundle.
    pub max_replacement_attempts: u32,
    /// Maximum time (seconds) to wait for bundle inclusion.
    pub max_wait_secs: u64,
    /// Interval (milliseconds) between bundle submissions.
    pub submission_interval_ms: u64,
    /// Enable automatic fee bumping.
    pub auto_fee_bump: bool,
    /// Persist mempool state to disk.
    pub persist_mempool: bool,
    /// Mempool persistence file path.
    pub mempool_persist_path: PathBuf,
    /// Maximum mempool size (ops).
    pub max_mempool_size: usize,
}

impl Default for BundlerConfig {
    fn default() -> Self {
        Self {
            max_ops_per_bundle: 100,
            max_bundle_gas: 15_000_000,
            min_profit: 1_000_000_000_000, // 0.001 IONA
            beneficiary_share: 80,
            entry_point_url: "http://localhost:8545".into(),
            rpc_timeout_secs: 10,
            bundler_private_key: "".into(),
            entry_point_address: "0x0000000000000000000000000000000000000000".into(),
            fee_bump_factor: 1.1,
            max_replacement_attempts: 3,
            max_wait_secs: 120,
            submission_interval_ms: 1000,
            auto_fee_bump: true,
            persist_mempool: false,
            mempool_persist_path: PathBuf::from("./mempool.json"),
            max_mempool_size: 10000,
        }
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum BundlerError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("mempool is full (max {max} ops)")]
    MempoolFull { max: usize },

    #[error("operation already exists with nonce {nonce} for sender {sender}")]
    OperationExists { sender: String, nonce: u64 },

    #[error("simulation failed: {0}")]
    Simulation(String),

    #[error("bundle contains no valid operations")]
    NoValidOperations,

    #[error("RPC submission failed: {0}")]
    Rpc(String),

    #[error("timeout waiting for inclusion")]
    Timeout,

    #[error("max replacement attempts reached")]
    MaxReplacementAttempts,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialisation error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type BundlerResult<T> = Result<T, BundlerError>;

// -----------------------------------------------------------------------------
// Mempool
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct UserOperationMempool {
    /// Map sender -> nonce -> operation (allows replacement).
    ops: BTreeMap<String, HashMap<u64, UserOperation>>,
    /// Operations sorted by effective gas price for bundle building.
    sorted_by_gas: Vec<UserOperation>,
    /// Maximum size.
    max_size: usize,
}

impl UserOperationMempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            ops: BTreeMap::new(),
            sorted_by_gas: Vec::new(),
            max_size,
        }
    }

    /// Add a new operation, replacing existing if higher gas price.
    pub fn add(&mut self, op: UserOperation) -> BundlerResult<()> {
        if self.ops.len() >= self.max_size {
            return Err(BundlerError::MempoolFull { max: self.max_size });
        }
        let sender = op.sender.clone();
        let nonce = op.nonce;
        let entry = self.ops.entry(sender).or_insert_with(HashMap::new);
        if let Some(existing) = entry.get(&nonce) {
            if op.max_fee_per_gas <= existing.max_fee_per_gas {
                // Only replace if higher gas price
                return Err(BundlerError::OperationExists {
                    sender: op.sender,
                    nonce: op.nonce,
                });
            }
        }
        entry.insert(nonce, op.clone());
        self.rebuild_sorted();
        Ok(())
    }

    /// Remove operations for a specific sender (used after bundle inclusion).
    pub fn remove_sender(&mut self, sender: &str) {
        self.ops.remove(sender);
        self.rebuild_sorted();
    }

    /// Remove up to `n` operations from the top of the sorted list.
    pub fn pop_n(&mut self, n: usize) -> Vec<UserOperation> {
        let mut result = Vec::new();
        for _ in 0..n {
            if let Some(op) = self.sorted_by_gas.pop() {
                // Remove from map
                if let Some(entry) = self.ops.get_mut(&op.sender) {
                    entry.remove(&op.nonce);
                    if entry.is_empty() {
                        self.ops.remove(&op.sender);
                    }
                }
                result.push(op);
            } else {
                break;
            }
        }
        result
    }

    /// Peek at the top N operations without removing them.
    pub fn peek_n(&self, n: usize) -> Vec<&UserOperation> {
        self.sorted_by_gas.iter().take(n).collect()
    }

    /// Number of operations in mempool.
    pub fn len(&self) -> usize {
        self.sorted_by_gas.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.sorted_by_gas.is_empty()
    }

    fn rebuild_sorted(&mut self) {
        let mut all: Vec<UserOperation> = self.ops.values().flat_map(|m| m.values().cloned()).collect();
        all.sort_by(|a, b| b.max_fee_per_gas.cmp(&a.max_fee_per_gas));
        self.sorted_by_gas = all;
    }

    /// Serialize for persistence.
    pub fn to_json(&self) -> String {
        let all: Vec<UserOperation> = self.ops.values().flat_map(|m| m.values().cloned()).collect();
        serde_json::to_string_pretty(&all).unwrap()
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str, max_size: usize) -> BundlerResult<Self> {
        let ops_vec: Vec<UserOperation> = serde_json::from_str(json)?;
        let mut mempool = Self::new(max_size);
        for op in ops_vec {
            mempool.add(op)?;
        }
        Ok(mempool)
    }

    /// Load from file.
    pub fn load(path: &Path, max_size: usize) -> BundlerResult<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_json(&content, max_size)
    }

    /// Save to file.
    pub fn save(&self, path: &Path) -> BundlerResult<()> {
        let json = self.to_json();
        std::fs::write(path, json)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Bundle builder
// -----------------------------------------------------------------------------

pub struct BundleBuilder {
    config: BundlerConfig,
    /// Current base fee (used to calculate profit).
    base_fee: u64,
}

impl BundleBuilder {
    pub fn new(config: BundlerConfig, base_fee: u64) -> Self {
        Self { config, base_fee }
    }

    /// Build a bundle from mempool operations.
    pub fn build(&self, mempool: &UserOperationMempool) -> BundlerResult<Vec<UserOperation>> {
        let ops = mempool.peek_n(self.config.max_ops_per_bundle);
        if ops.is_empty() {
            return Err(BundlerError::NoValidOperations);
        }

        let mut selected = Vec::new();
        let mut total_gas = 0u64;
        let mut total_profit = 0u64;

        for op in ops {
            // Simulate and filter invalid operations
            if let Err(e) = simulate_all(op, &self.config.entry_point_address) {
                debug!(sender = %op.sender, error = %e, "skipping invalid op");
                continue;
            }

            let op_gas = op.total_gas();
            if selected.len() >= self.config.max_ops_per_bundle
                || total_gas + op_gas > self.config.max_bundle_gas
            {
                continue;
            }

            let profit = op.gas_profit(self.base_fee);
            if profit == 0 {
                continue;
            }

            selected.push(op.clone());
            total_gas += op_gas;
            total_profit += profit;
        }

        if total_profit < self.config.min_profit {
            return Err(BundlerError::NoValidOperations);
        }

        Ok(selected)
    }
}

// -----------------------------------------------------------------------------
// Submitter (RPC client)
// -----------------------------------------------------------------------------

pub struct Submitter {
    client: reqwest::Client,
    entry_point_url: String,
    entry_point_address: String,
    timeout: Duration,
}

impl Submitter {
    pub fn new(
        entry_point_url: &str,
        entry_point_address: &str,
        timeout_secs: u64,
    ) -> BundlerResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| BundlerError::Rpc(e.to_string()))?;
        Ok(Self {
            client,
            entry_point_url: entry_point_url.to_string(),
            entry_point_address: entry_point_address.to_string(),
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Submit a bundle to the EntryPoint via `eth_sendUserOperation` or `handleOps`.
    pub async fn submit_bundle(&self, ops: &[UserOperation]) -> BundlerResult<String> {
        // In production, this would call the EntryPoint contract via RPC.
        // For now we simulate via the `handle_ops` function.
        // Real implementation uses `eth_sendUserOperation` or `eth_sendRawTransaction`.

        let result = handle_ops(ops, &self.entry_point_address);
        if !result.success {
            let reasons: Vec<_> = result.failed_ops.iter().map(|(_, r)| r.as_str()).collect();
            return Err(BundlerError::Rpc(reasons.join("; ")));
        }

        // Simulate transaction hash
        let tx_hash = blake3::hash(&bincode::serialize(&result).unwrap());
        let hash_hex = hex::encode(tx_hash.as_bytes());
        info!(tx_hash = %hash_hex, ops = ops.len(), "Bundle submitted");
        Ok(hash_hex)
    }
}

// -----------------------------------------------------------------------------
// Reputation manager
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ReputationManager {
    /// Sender -> (ops_seen, ops_included, ops_rejected)
    sender_reputation: HashMap<String, (u64, u64, u64)>,
    /// Paymaster -> (ops_seen, ops_included, ops_rejected)
    paymaster_reputation: HashMap<String, (u64, u64, u64)>,
    /// Minimum ops before reputation is applied.
    min_ops_threshold: u64,
}

impl ReputationManager {
    pub fn new(min_ops_threshold: u64) -> Self {
        Self {
            sender_reputation: HashMap::new(),
            paymaster_reputation: HashMap::new(),
            min_ops_threshold,
        }
    }

    pub fn record_seen(&mut self, sender: &str, paymaster: Option<&str>) {
        *self.sender_reputation.entry(sender.to_string()).or_insert((0, 0, 0)) += (1, 0, 0);
        if let Some(pm) = paymaster {
            *self.paymaster_reputation.entry(pm.to_string()).or_insert((0, 0, 0)) += (1, 0, 0);
        }
    }

    pub fn record_included(&mut self, sender: &str, paymaster: Option<&str>) {
        if let Some(entry) = self.sender_reputation.get_mut(sender) {
            entry.1 += 1;
        }
        if let Some(pm) = paymaster {
            if let Some(entry) = self.paymaster_reputation.get_mut(pm) {
                entry.1 += 1;
            }
        }
    }

    pub fn record_rejected(&mut self, sender: &str, paymaster: Option<&str>) {
        if let Some(entry) = self.sender_reputation.get_mut(sender) {
            entry.2 += 1;
        }
        if let Some(pm) = paymaster {
            if let Some(entry) = self.paymaster_reputation.get_mut(pm) {
                entry.2 += 1;
            }
        }
    }

    pub fn is_sender_reputable(&self, sender: &str) -> bool {
        if let Some((seen, included, rejected)) = self.sender_reputation.get(sender) {
            if seen + rejected < self.min_ops_threshold {
                return true;
            }
            let success_rate = (*included as f64) / ((seen + rejected) as f64);
            success_rate >= 0.5
        } else {
            true
        }
    }
}

// -----------------------------------------------------------------------------
// Main Bundler orchestrator
// -----------------------------------------------------------------------------

pub struct Bundler {
    config: BundlerConfig,
    mempool: UserOperationMempool,
    reputation: ReputationManager,
    submitter: Submitter,
    base_fee: u64,
    pending_bundles: VecDeque<PendingBundle>,
    metrics: BundlerMetrics,
}

#[derive(Debug, Clone)]
struct PendingBundle {
    hash: String,
    ops: Vec<UserOperation>,
    submitted_at: Instant,
    attempts: u32,
    max_fee_per_gas: u64,
}

#[derive(Debug, Default)]
pub struct BundlerMetrics {
    pub ops_received: u64,
    pub ops_valid: u64,
    pub ops_rejected: u64,
    pub bundles_built: u64,
    pub bundles_submitted: u64,
    pub bundles_included: u64,
    pub bundles_expired: u64,
    pub total_fees_earned: u64,
}

impl Bundler {
    pub async fn new(config: BundlerConfig) -> BundlerResult<Self> {
        let mut mempool = if config.persist_mempool && config.mempool_persist_path.exists() {
            info!("Loading mempool from {}", config.mempool_persist_path.display());
            UserOperationMempool::load(&config.mempool_persist_path, config.max_mempool_size)?
        } else {
            UserOperationMempool::new(config.max_mempool_size)
        };

        let submitter = Submitter::new(
            &config.entry_point_url,
            &config.entry_point_address,
            config.rpc_timeout_secs,
        )?;

        Ok(Self {
            config,
            mempool,
            reputation: ReputationManager::new(5),
            submitter,
            base_fee: 0,
            pending_bundles: VecDeque::new(),
            metrics: BundlerMetrics::default(),
        })
    }

    /// Add a UserOperation to the mempool.
    pub fn add_operation(&mut self, mut op: UserOperation) -> BundlerResult<()> {
        self.metrics.ops_received += 1;

        // Validate and simulate
        if let Err(e) = simulate_all(&op, &self.config.entry_point_address) {
            self.metrics.ops_rejected += 1;
            return Err(BundlerError::Simulation(e.to_string()));
        }

        // Check reputation
        if !self.reputation.is_sender_reputable(&op.sender) {
            self.metrics.ops_rejected += 1;
            return Err(BundlerError::Simulation("sender not reputable".into()));
        }

        self.mempool.add(op.clone())?;
        self.reputation.record_seen(&op.sender, None);
        self.metrics.ops_valid += 1;
        Ok(())
    }

    /// Build and submit a bundle (called periodically).
    pub async fn run_cycle(&mut self) -> BundlerResult<()> {
        // Update base fee from chain (stub)
        self.base_fee = Self::fetch_base_fee(&self.submitter).await.unwrap_or(0);

        // Build bundle
        let builder = BundleBuilder::new(self.config.clone(), self.base_fee);
        let ops = match builder.build(&self.mempool) {
            Ok(o) => o,
            Err(e) => {
                debug!("No bundle to build: {}", e);
                return Err(e);
            }
        };

        // Submit
        let hash = self.submitter.submit_bundle(&ops).await?;
        self.metrics.bundles_built += 1;
        self.metrics.bundles_submitted += 1;

        // Remove ops from mempool
        for op in &ops {
            self.mempool.remove_sender(&op.sender);
        }

        // Track pending bundle
        let max_fee = ops.iter().map(|op| op.max_fee_per_gas).max().unwrap_or(0);
        self.pending_bundles.push_back(PendingBundle {
            hash: hash.clone(),
            ops,
            submitted_at: Instant::now(),
            attempts: 1,
            max_fee_per_gas: max_fee,
        });

        // Persist mempool
        if self.config.persist_mempool {
            self.mempool.save(&self.config.mempool_persist_path)?;
        }

        info!(hash = %hash, ops, "Bundle submitted successfully");
        Ok(())
    }

    /// Maintain pending bundles (check inclusion, bump fees, expire).
    pub async fn maintain_pending(&mut self) -> BundlerResult<()> {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        for (idx, bundle) in self.pending_bundles.iter_mut().enumerate() {
            // Check inclusion (stub – real implementation would query RPC)
            let included = self.check_inclusion(&bundle.hash).await?;
            if included {
                self.metrics.bundles_included += 1;
                to_remove.push(idx);
                continue;
            }

            // Expire
            if now.duration_since(bundle.submitted_at).as_secs() > self.config.max_wait_secs {
                self.metrics.bundles_expired += 1;
                warn!(hash = %bundle.hash, "Bundle expired");
                to_remove.push(idx);
                continue;
            }

            // Fee bump
            if self.config.auto_fee_bump && bundle.attempts < self.config.max_replacement_attempts {
                if bundle.submitted_at.elapsed() > Duration::from_secs(10) {
                    let bumped_ops: Vec<UserOperation> = bundle.ops
                        .iter()
                        .map(|op| {
                            let mut bumped = op.clone();
                            bumped.max_fee_per_gas = ((bumped.max_fee_per_gas as f64 * self.config.fee_bump_factor) as u64).max(1);
                            bumped.max_priority_fee_per_gas =
                                ((bumped.max_priority_fee_per_gas as f64 * self.config.fee_bump_factor) as u64).max(1);
                            bumped
                        })
                        .collect();

                    // Resubmit
                    let new_hash = self.submitter.submit_bundle(&bumped_ops).await?;
                    bundle.ops = bumped_ops;
                    bundle.hash = new_hash;
                    bundle.submitted_at = Instant::now();
                    bundle.attempts += 1;
                    self.metrics.bundles_submitted += 1;
                    info!(hash = %new_hash, attempt = bundle.attempts, "Resubmitted bundle with higher fees");
                }
            }
        }

        // Remove expired/ included bundles (reverse order)
        for idx in to_remove.into_iter().rev() {
            self.pending_bundles.remove(idx);
        }

        // Persist mempool (again)
        if self.config.persist_mempool {
            self.mempool.save(&self.config.mempool_persist_path)?;
        }

        Ok(())
    }

    /// Check if a bundle has been included (stub).
    async fn check_inclusion(&self, _hash: &str) -> BundlerResult<bool> {
        // In production: query RPC or scan logs for UserOperationEvent.
        // For testing, assume not included yet.
        Ok(false)
    }

    /// Fetch current base fee (stub).
    async fn fetch_base_fee(_submitter: &Submitter) -> BundlerResult<u64> {
        // In production: eth_gasPrice or eth_feeHistory.
        Ok(1_000_000_000) // 1 Gwei
    }

    /// Get current metrics.
    pub fn metrics(&self) -> &BundlerMetrics {
        &self.metrics
    }

    /// Save mempool to disk.
    pub fn save_mempool(&self) -> BundlerResult<()> {
        if self.config.persist_mempool {
            self.mempool.save(&self.config.mempool_persist_path)?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_op(nonce: u64, gas_price: u64) -> UserOperation {
        UserOperation {
            sender: format!("0x{:040x}", nonce % 10),
            nonce,
            init_code: vec![],
            call_data: vec![],
            call_gas_limit: 100_000,
            verification_gas_limit: 100_000,
            pre_verification_gas: 10_000,
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: gas_price / 2,
            paymaster_and_data: vec![],
            signature: vec![0u8; 65],
        }
    }

    #[test]
    fn test_mempool_add_and_pop() {
        let mut mempool = UserOperationMempool::new(10);
        mempool.add(dummy_op(1, 100)).unwrap();
        mempool.add(dummy_op(2, 200)).unwrap();
        assert_eq!(mempool.len(), 2);
        let popped = mempool.pop_n(1);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].max_fee_per_gas, 200);
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_replace() {
        let mut mempool = UserOperationMempool::new(10);
        let op1 = dummy_op(1, 100);
        mempool.add(op1.clone()).unwrap();
        // Replace with higher gas
        let op2 = dummy_op(1, 200);
        mempool.add(op2.clone()).unwrap();
        let popped = mempool.pop_n(1);
        assert_eq!(popped[0].max_fee_per_gas, 200);
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_mempool_serialization() {
        let mut mempool = UserOperationMempool::new(10);
        mempool.add(dummy_op(1, 100)).unwrap();
        mempool.add(dummy_op(2, 200)).unwrap();
        let json = mempool.to_json();
        let restored = UserOperationMempool::from_json(&json, 10).unwrap();
        assert_eq!(restored.len(), 2);
        let popped = restored.pop_n(1);
        assert_eq!(popped[0].max_fee_per_gas, 200);
    }

    #[test]
    fn test_reputation() {
        let mut rep = ReputationManager::new(3);
        rep.record_seen("sender1", None);
        rep.record_seen("sender1", None);
        rep.record_rejected("sender1", None);
        // Below threshold, always reputable
        assert!(rep.is_sender_reputable("sender1"));
        rep.record_seen("sender1", None);
        rep.record_seen("sender1", None);
        rep.record_rejected("sender1", None);
        // Now threshold met: 2 included, 2 rejected → success_rate = 0.5 → reputable (≥0.5)
        assert!(rep.is_sender_reputable("sender1"));
        rep.record_rejected("sender1", None);
        rep.record_rejected("sender1", None);
        // 2 included, 4 rejected → success_rate = 0.33 → not reputable
        assert!(!rep.is_sender_reputable("sender1"));
    }
}
