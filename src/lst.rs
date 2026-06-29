//! IONA — Quantum Liquid Staking Tokens (stIONA).
//!
//! # Quantum Liquid Staking Model
//!
//! Liquid staking is modeled as a quantum superposition of staked and
//! liquid states. stIONA tokens represent shares in the staking pool,
//! analogous to quantum harmonic oscillator eigenstates.
//!
//! # Production Features
//! - Thread‑safe pool management with `parking_lot::Mutex`.
//! - Persistent state with atomic writes and file locking (`flock`).
//! - Configurable parameters with validation.
//! - Comprehensive metrics and statistics.
//! - Validation of all operations.
//! - Proper error handling with descriptive variants.
//! - Structured logging with `tracing`.

use fs2::FileExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// stIONA token symbol.
pub const STIONA_SYMBOL: &str = "stIONA";

/// Precision: stIONA uses 18 decimal places (quantum precision).
pub const STIONA_DECIMALS: u8 = 18;

/// Minimum stake to receive stIONA (prevents quantum dust attacks).
pub const DEFAULT_MIN_STAKE: u64 = 1_000;

/// Exchange rate scaling factor (1e18 for fixed-point arithmetic).
pub const RATE_SCALING_FACTOR: u128 = 1_000_000_000_000_000_000;

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum tunneling coefficient for unbonding.
const DEFAULT_TUNNELING_COEFFICIENT: f64 = 0.95;

/// Default coherence decay per operation.
const DEFAULT_OPERATION_DECOHERENCE: f64 = 0.0001;

/// Default minimum coherence threshold.
const DEFAULT_MIN_COHERENCE: f64 = 0.9;

/// Default unbonding blocks.
const DEFAULT_UNBONDING_BLOCKS: u64 = 50400; // ~7 days at 5s blocks

/// Lock timeout in seconds.
const LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the liquid staking pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LstConfig {
    /// Minimum stake to receive stIONA.
    pub min_stake: u64,
    /// Quantum tunneling coefficient for unbonding (0.0 – 1.0).
    pub tunneling_coefficient: f64,
    /// Coherence decay per operation (0.0 – 1.0).
    pub operation_decoherence: f64,
    /// Minimum coherence threshold for operations (0.0 – 1.0).
    pub min_coherence: f64,
    /// Default unbonding blocks.
    pub default_unbonding_blocks: u64,
    /// Whether to persist state to disk.
    pub persist_state: bool,
    /// Lock timeout in seconds.
    pub lock_timeout_secs: u64,
}

impl Default for LstConfig {
    fn default() -> Self {
        Self {
            min_stake: DEFAULT_MIN_STAKE,
            tunneling_coefficient: DEFAULT_TUNNELING_COEFFICIENT,
            operation_decoherence: DEFAULT_OPERATION_DECOHERENCE,
            min_coherence: DEFAULT_MIN_COHERENCE,
            default_unbonding_blocks: DEFAULT_UNBONDING_BLOCKS,
            persist_state: true,
            lock_timeout_secs: LOCK_TIMEOUT_SECS,
        }
    }
}

impl LstConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_stake == 0 {
            return Err("min_stake must be > 0".into());
        }
        if !(0.0..=1.0).contains(&self.tunneling_coefficient) {
            return Err("tunneling_coefficient must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.operation_decoherence) {
            return Err("operation_decoherence must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.min_coherence) {
            return Err("min_coherence must be between 0.0 and 1.0".into());
        }
        if self.default_unbonding_blocks == 0 {
            return Err("default_unbonding_blocks must be > 0".into());
        }
        if self.lock_timeout_secs == 0 {
            return Err("lock_timeout_secs must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Quantum LST Errors
// -----------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum LstError {
    #[error("amount too small: min={min}, got={got}")]
    AmountTooSmall { min: u64, got: u64 },

    #[error("zero shares minted — quantum amplitude collapsed to zero")]
    ZeroShares,

    #[error("insufficient shares: have={have}, need={need}")]
    InsufficientShares { have: u128, need: u128 },

    #[error("quantum decoherence: coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },

    #[error("unbonding not complete: current_height={current}, completes_at={completes}")]
    UnbondingNotComplete { current: u64, completes: u64 },

    #[error("entanglement broken: pool state corrupted")]
    EntanglementBroken,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("lock acquisition failed: {0}")]
    LockFailed(String),

    #[error("invalid amount: {0}")]
    InvalidAmount(String),

    #[error("address not found: {0}")]
    AddressNotFound(String),

    #[error("pool is frozen (coherence = 0)")]
    PoolFrozen,
}

pub type LstResult<T> = Result<T, LstError>;

// -----------------------------------------------------------------------------
// Persistent State (versioned)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentStateV1 {
    version: u32,
    total_staked: u64,
    total_shares: u128,
    last_reward_epoch: u64,
    balances: BTreeMap<String, u128>,
    pending_withdrawals: Vec<(String, u64, u64)>,
    coherence: f64,
    entanglement_entropy: f64,
    total_rewards_distributed: u64,
    total_stake_operations: u64,
    total_unstake_operations: u64,
    last_modified: u64,
}

impl PersistentStateV1 {
    fn from_pool(pool: &LstPool) -> Self {
        Self {
            version: CURRENT_VERSION,
            total_staked: pool.total_staked,
            total_shares: pool.total_shares,
            last_reward_epoch: pool.last_reward_epoch,
            balances: pool.balances.clone(),
            pending_withdrawals: pool.pending_withdrawals.clone(),
            coherence: pool.coherence,
            entanglement_entropy: pool.entanglement_entropy,
            total_rewards_distributed: pool.total_rewards_distributed,
            total_stake_operations: pool.total_stake_operations,
            total_unstake_operations: pool.total_unstake_operations,
            last_modified: current_timestamp(),
        }
    }

    fn into_pool(self) -> LstPool {
        LstPool {
            total_staked: self.total_staked,
            total_shares: self.total_shares,
            last_reward_epoch: self.last_reward_epoch,
            balances: self.balances,
            pending_withdrawals: self.pending_withdrawals,
            coherence: self.coherence,
            entanglement_entropy: self.entanglement_entropy,
            total_rewards_distributed: self.total_rewards_distributed,
            total_stake_operations: self.total_stake_operations,
            total_unstake_operations: self.total_unstake_operations,
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// -----------------------------------------------------------------------------
// File I/O with locking
// -----------------------------------------------------------------------------

fn acquire_lock(path: &Path, timeout_secs: u64) -> Result<File, LstError> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| LstError::LockFailed(e.to_string()))?;
    let timeout = Duration::from_secs(timeout_secs);
    let start = SystemTime::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed().unwrap_or_default() > timeout {
                    return Err(LstError::LockFailed(format!(
                        "timeout after {}s",
                        timeout_secs
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn release_lock(file: File) -> Result<(), LstError> {
    file.unlock().map_err(|e| LstError::LockFailed(e.to_string()))
}

fn load_state(path: &Path, config: &LstConfig) -> Result<LstPool, LstError> {
    if !path.exists() {
        return Ok(LstPool::default());
    }
    let _lock = acquire_lock(path, config.lock_timeout_secs)?;
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value = serde_json::from_reader(reader)?;
    if let Some(version) = raw.get("version").and_then(|v| v.as_u64()) {
        if version != CURRENT_VERSION as u64 {
            return Err(LstError::Config(format!(
                "unsupported version: {} (expected {})",
                version, CURRENT_VERSION
            )));
        }
        let st: PersistentStateV1 = serde_json::from_value(raw)?;
        Ok(st.into_pool())
    } else {
        // Legacy format
        match serde_json::from_value::<LstPool>(raw) {
            Ok(pool) => Ok(pool),
            Err(e) => Err(LstError::Serialization(e)),
        }
    }
}

fn save_state(path: &Path, pool: &LstPool, config: &LstConfig) -> Result<(), LstError> {
    let st = PersistentStateV1::from_pool(pool);
    let json = serde_json::to_string_pretty(&st)?;
    let _lock = acquire_lock(path, config.lock_timeout_secs)?;
    let temp_path = path.with_extension(TEMP_EXT);
    fs::write(&temp_path, &json)?;
    fs::rename(&temp_path, path)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Quantum Liquid Staking Pool
// -----------------------------------------------------------------------------

/// The quantum liquid staking pool state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LstPool {
    pub total_staked: u64,
    pub total_shares: u128,
    pub last_reward_epoch: u64,
    pub balances: BTreeMap<String, u128>,
    pub pending_withdrawals: Vec<(String, u64, u64)>,
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    #[serde(default)]
    pub entanglement_entropy: f64,
    #[serde(default)]
    pub total_rewards_distributed: u64,
    #[serde(default)]
    pub total_stake_operations: u64,
    #[serde(default)]
    pub total_unstake_operations: u64,
}

fn default_coherence() -> f64 {
    1.0
}

impl Default for LstPool {
    fn default() -> Self {
        Self {
            total_staked: 0,
            total_shares: 0,
            last_reward_epoch: 0,
            balances: BTreeMap::new(),
            pending_withdrawals: Vec::new(),
            coherence: 1.0,
            entanglement_entropy: 0.0,
            total_rewards_distributed: 0,
            total_stake_operations: 0,
            total_unstake_operations: 0,
        }
    }
}

impl LstPool {
    // ── Exchange Rate ──────────────────────────────────────────────────

    pub fn exchange_rate(&self) -> u128 {
        if self.total_shares == 0 || self.total_staked == 0 {
            return RATE_SCALING_FACTOR;
        }
        (self.total_staked as u128)
            .saturating_mul(RATE_SCALING_FACTOR)
            .checked_div(self.total_shares)
            .unwrap_or(RATE_SCALING_FACTOR)
    }

    pub fn exchange_rate_f64(&self) -> f64 {
        self.exchange_rate() as f64 / RATE_SCALING_FACTOR as f64
    }

    // ── Stake ──────────────────────────────────────────────────────────

    pub fn stake(
        &mut self,
        staker: &str,
        iona_amount: u64,
        config: &LstConfig,
    ) -> LstResult<u128> {
        if iona_amount < config.min_stake {
            return Err(LstError::AmountTooSmall {
                min: config.min_stake,
                got: iona_amount,
            });
        }

        if self.coherence < config.min_coherence {
            return Err(LstError::Decoherence {
                coherence: self.coherence,
                threshold: config.min_coherence,
            });
        }

        let rate = self.exchange_rate();
        let shares = (iona_amount as u128)
            .saturating_mul(RATE_SCALING_FACTOR)
            .checked_div(rate)
            .unwrap_or(0);

        if shares == 0 {
            return Err(LstError::ZeroShares);
        }

        self.total_staked = self.total_staked.saturating_add(iona_amount);
        self.total_shares = self.total_shares.saturating_add(shares);
        *self.balances.entry(staker.to_string()).or_insert(0) += shares;

        self.total_stake_operations += 1;
        self.apply_decoherence(config);

        info!(
            staker = %staker,
            iona = iona_amount,
            stiona = shares,
            rate = rate,
            coherence = self.coherence,
            "staked"
        );

        Ok(shares)
    }

    // ── Unstake ────────────────────────────────────────────────────────

    pub fn request_unstake(
        &mut self,
        staker: &str,
        shares: u128,
        current_height: u64,
        unbonding_blocks: u64,
        config: &LstConfig,
    ) -> LstResult<u64> {
        let balance = self.balances.get(staker).copied().unwrap_or(0);
        if balance < shares {
            return Err(LstError::InsufficientShares {
                have: balance,
                need: shares,
            });
        }

        if self.coherence < config.min_coherence {
            return Err(LstError::Decoherence {
                coherence: self.coherence,
                threshold: config.min_coherence,
            });
        }

        let rate = self.exchange_rate();
        let iona_amount =
            (shares.saturating_mul(rate) / RATE_SCALING_FACTOR) as u64;

        *self.balances.entry(staker.to_string()).or_insert(0) =
            balance.saturating_sub(shares);
        self.total_shares = self.total_shares.saturating_sub(shares);
        self.total_staked = self.total_staked.saturating_sub(iona_amount);

        let tunneling = config.tunneling_coefficient
            * (1.0 - self.entanglement_entropy).max(0.0);
        let effective_unbonding = (unbonding_blocks as f64 * tunneling.max(0.5)) as u64;
        let completion_height = current_height
            .saturating_add(effective_unbonding)
            .max(current_height + 1);

        self.pending_withdrawals.push((
            staker.to_string(),
            iona_amount,
            completion_height,
        ));

        self.total_unstake_operations += 1;
        self.apply_decoherence(config);

        info!(
            staker = %staker,
            shares = shares,
            iona = iona_amount,
            unlocks_at = completion_height,
            tunneling = tunneling,
            "unstake queued"
        );

        Ok(iona_amount)
    }

    // ── Process Withdrawals ───────────────────────────────────────────

    pub fn process_withdrawals(
        &mut self,
        current_height: u64,
        config: &LstConfig,
    ) -> Vec<(String, u64)> {
        let (ready, pending): (Vec<_>, Vec<_>) = self
            .pending_withdrawals
            .drain(..)
            .partition(|(_, _, h)| current_height >= *h);

        self.pending_withdrawals = pending;

        if !ready.is_empty() {
            self.apply_decoherence(config);
            info!(count = ready.len(), "withdrawals processed");
        }

        ready.into_iter().map(|(addr, amt, _)| (addr, amt)).collect()
    }

    // ── Rewards ────────────────────────────────────────────────────────

    pub fn add_rewards(&mut self, reward_iona: u64, config: &LstConfig) {
        self.total_staked = self.total_staked.saturating_add(reward_iona);
        self.total_rewards_distributed =
            self.total_rewards_distributed.saturating_add(reward_iona);

        // Rewards slightly increase coherence
        self.coherence = (self.coherence * 1.0001).min(1.0);
        self.entanglement_entropy = (self.entanglement_entropy * 0.9999).max(0.0);

        debug!(
            reward = reward_iona,
            new_rate = self.exchange_rate(),
            coherence = self.coherence,
            "rewards added"
        );
    }

    // ── Transfer ──────────────────────────────────────────────────────

    pub fn transfer(
        &mut self,
        from: &str,
        to: &str,
        shares: u128,
        config: &LstConfig,
    ) -> LstResult<()> {
        if from == to {
            return Ok(());
        }

        let from_bal = self.balances.get(from).copied().unwrap_or(0);
        if from_bal < shares {
            return Err(LstError::InsufficientShares {
                have: from_bal,
                need: shares,
            });
        }

        *self.balances.entry(from.to_string()).or_insert(0) =
            from_bal.saturating_sub(shares);
        *self.balances.entry(to.to_string()).or_insert(0) += shares;

        self.apply_decoherence(config);

        debug!(
            from = %from,
            to = %to,
            shares = shares,
            "transferred"
        );

        Ok(())
    }

    // ── Queries ────────────────────────────────────────────────────────

    pub fn balance_of(&self, addr: &str) -> u128 {
        self.balances.get(addr).copied().unwrap_or(0)
    }

    pub fn shares_to_iona(&self, shares: u128) -> u64 {
        let rate = self.exchange_rate();
        (shares.saturating_mul(rate) / RATE_SCALING_FACTOR) as u64
    }

    pub fn iona_to_shares(&self, iona: u64) -> u128 {
        let rate = self.exchange_rate();
        (iona as u128).saturating_mul(RATE_SCALING_FACTOR) / rate.max(1)
    }

    pub fn pending_withdrawal_count(&self) -> usize {
        self.pending_withdrawals.len()
    }

    pub fn pending_withdrawal_total(&self) -> u64 {
        self.pending_withdrawals.iter().map(|(_, amt, _)| amt).sum()
    }

    pub fn stats(&self) -> LstStats {
        LstStats {
            total_staked: self.total_staked,
            total_shares: self.total_shares,
            exchange_rate: self.exchange_rate(),
            exchange_rate_f64: self.exchange_rate_f64(),
            total_holders: self.balances.len(),
            pending_withdrawals: self.pending_withdrawals.len(),
            total_rewards: self.total_rewards_distributed,
            coherence: self.coherence,
            entanglement_entropy: self.entanglement_entropy,
        }
    }

    // ── Internal ──────────────────────────────────────────────────────

    fn apply_decoherence(&mut self, config: &LstConfig) {
        self.coherence = (self.coherence * (1.0 - config.operation_decoherence))
            .max(0.0);
        self.entanglement_entropy =
            -self.coherence * self.coherence.ln().max(0.0);
    }
}

// -----------------------------------------------------------------------------
// LST Statistics
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LstStats {
    pub total_staked: u64,
    pub total_shares: u128,
    pub exchange_rate: u128,
    pub exchange_rate_f64: f64,
    pub total_holders: usize,
    pub pending_withdrawals: usize,
    pub total_rewards: u64,
    pub coherence: f64,
    pub entanglement_entropy: f64,
}

// -----------------------------------------------------------------------------
// LstManager — Thread‑safe, persistent
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct LstManager {
    pool: Arc<Mutex<LstPool>>,
    config: Arc<LstConfig>,
    path: Option<PathBuf>,
}

impl LstManager {
    /// Create a new manager with configuration.
    pub fn new(config: LstConfig) -> Result<Self, LstError> {
        config.validate().map_err(LstError::Config)?;
        Ok(Self {
            pool: Arc::new(Mutex::new(LstPool::default())),
            config: Arc::new(config),
            path: None,
        })
    }

    /// Create a manager with persistence.
    pub fn with_persistence(data_dir: &str, config: LstConfig) -> Result<Self, LstError> {
        config.validate().map_err(LstError::Config)?;
        let path = PathBuf::from(data_dir).join("lst_pool.json");
        let pool = if path.exists() {
            load_state(&path, &config)?
        } else {
            LstPool::default()
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let manager = Self {
            pool: Arc::new(Mutex::new(pool)),
            config: Arc::new(config),
            path: Some(path),
        };
        if let Some(p) = &manager.path {
            let pool = manager.pool.lock();
            if manager.config.persist_state {
                let _ = save_state(p, &pool, &manager.config);
            }
        }
        Ok(manager)
    }

    pub fn stake(&self, staker: &str, iona_amount: u64) -> LstResult<u128> {
        let mut pool = self.pool.lock();
        let result = pool.stake(staker, iona_amount, &self.config);
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_state(path, &pool, &self.config);
            }
        }
        result
    }

    pub fn request_unstake(
        &self,
        staker: &str,
        shares: u128,
        current_height: u64,
        unbonding_blocks: Option<u64>,
    ) -> LstResult<u64> {
        let unbonding = unbonding_blocks.unwrap_or(self.config.default_unbonding_blocks);
        let mut pool = self.pool.lock();
        let result = pool.request_unstake(staker, shares, current_height, unbonding, &self.config);
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_state(path, &pool, &self.config);
            }
        }
        result
    }

    pub fn process_withdrawals(&self, current_height: u64) -> Vec<(String, u64)> {
        let mut pool = self.pool.lock();
        let result = pool.process_withdrawals(current_height, &self.config);
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_state(path, &pool, &self.config);
            }
        }
        result
    }

    pub fn add_rewards(&self, reward_iona: u64) {
        let mut pool = self.pool.lock();
        pool.add_rewards(reward_iona, &self.config);
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_state(path, &pool, &self.config);
            }
        }
    }

    pub fn transfer(&self, from: &str, to: &str, shares: u128) -> LstResult<()> {
        let mut pool = self.pool.lock();
        let result = pool.transfer(from, to, shares, &self.config);
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_state(path, &pool, &self.config);
            }
        }
        result
    }

    pub fn balance_of(&self, addr: &str) -> u128 {
        self.pool.lock().balance_of(addr)
    }

    pub fn shares_to_iona(&self, shares: u128) -> u64 {
        self.pool.lock().shares_to_iona(shares)
    }

    pub fn iona_to_shares(&self, iona: u64) -> u128 {
        self.pool.lock().iona_to_shares(iona)
    }

    pub fn exchange_rate(&self) -> u128 {
        self.pool.lock().exchange_rate()
    }

    pub fn exchange_rate_f64(&self) -> f64 {
        self.pool.lock().exchange_rate_f64()
    }

    pub fn stats(&self) -> LstStats {
        self.pool.lock().stats()
    }

    pub fn flush(&self) -> LstResult<()> {
        if let Some(path) = &self.path {
            let pool = self.pool.lock();
            save_state(path, &pool, &self.config)?;
        }
        Ok(())
    }

    pub fn config(&self) -> &LstConfig {
        &self.config
    }

    pub fn pool(&self) -> LstPool {
        self.pool.lock().clone()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config() -> LstConfig {
        let mut cfg = LstConfig::default();
        cfg.persist_state = true;
        cfg.min_coherence = 0.5;
        cfg
    }

    #[test]
    fn test_stake_and_unstake_roundtrip() {
        let cfg = test_config();
        let manager = LstManager::new(cfg).unwrap();

        let shares = manager.stake("alice", 1_000_000).unwrap();
        assert!(shares > 0);
        assert_eq!(manager.balance_of("alice"), shares);

        manager.add_rewards(100_000);

        let iona_back = manager
            .request_unstake("alice", shares, 0, Some(1))
            .unwrap();
        assert!(iona_back >= 1_000_000);

        let released = manager.process_withdrawals(1);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].0, "alice");
    }

    #[test]
    fn test_exchange_rate_grows_with_rewards() {
        let cfg = test_config();
        let manager = LstManager::new(cfg).unwrap();

        manager.stake("alice", 1_000_000).unwrap();
        let rate_before = manager.exchange_rate();
        manager.add_rewards(100_000);
        let rate_after = manager.exchange_rate();

        assert!(rate_after > rate_before);
    }

    #[test]
    fn test_transfer() {
        let cfg = test_config();
        let manager = LstManager::new(cfg).unwrap();

        let shares = manager.stake("alice", 1_000_000).unwrap();
        manager.transfer("alice", "bob", shares / 2).unwrap();

        assert_eq!(manager.balance_of("alice"), shares / 2);
        assert_eq!(manager.balance_of("bob"), shares / 2);
    }

    #[test]
    fn test_min_stake() {
        let cfg = test_config();
        let manager = LstManager::new(cfg).unwrap();

        let result = manager.stake("alice", 1);
        assert!(matches!(result, Err(LstError::AmountTooSmall { .. })));
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cfg = test_config();

        {
            let manager = LstManager::with_persistence(path, cfg.clone()).unwrap();
            manager.stake("alice", 1_000_000).unwrap();
            manager.add_rewards(50_000);
            manager.flush().unwrap();
        }

        {
            let manager = LstManager::with_persistence(path, cfg).unwrap();
            let stats = manager.stats();
            assert_eq!(stats.total_staked, 1_050_000);
            assert_eq!(stats.total_holders, 1);
        }
    }

    #[test]
    fn test_stats() {
        let cfg = test_config();
        let manager = LstManager::new(cfg).unwrap();

        manager.stake("alice", 1_000_000).unwrap();
        manager.add_rewards(50_000);

        let stats = manager.stats();
        assert!(stats.total_staked > 0);
        assert!(stats.total_shares > 0);
        assert_eq!(stats.total_holders, 1);
        assert!(stats.coherence < 1.0);
    }

    #[test]
    fn test_conversion_functions() {
        let cfg = test_config();
        let manager = LstManager::new(cfg).unwrap();

        manager.stake("alice", 1_000_000).unwrap();
        let shares = manager.balance_of("alice");
        let iona_val = manager.shares_to_iona(shares);
        assert!(iona_val >= 1_000_000);

        let shares_val = manager.iona_to_shares(1_000_000);
        assert!(shares_val > 0);
    }

    #[test]
    fn test_unbonding_blocks() {
        let cfg = test_config();
        let manager = LstManager::new(cfg).unwrap();

        let shares = manager.stake("alice", 1_000_000).unwrap();
        manager.request_unstake("alice", shares, 100, Some(100)).unwrap();

        let released = manager.process_withdrawals(150);
        assert!(released.is_empty());

        let released = manager.process_withdrawals(250);
        assert_eq!(released.len(), 1);
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = LstConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.min_stake = 0;
        assert!(cfg.validate().is_err());

        cfg.min_stake = 1000;
        cfg.tunneling_coefficient = 1.5;
        assert!(cfg.validate().is_err());

        cfg.tunneling_coefficient = 0.5;
        cfg.operation_decoherence = -0.1;
        assert!(cfg.validate().is_err());
    }
}
