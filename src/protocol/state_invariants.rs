//! State transition invariants.
//!
//! Enforces formal invariants that must hold across every state transition
//! (block execution).  These are the "always-on" safety checks that run
//! regardless of whether a protocol upgrade is in progress.
//!
//! # Invariants
//!
//! | ID   | Name                    | Description                                           |
//! |------|-------------------------|-------------------------------------------------------|
//! | ST-1 | Balance non-negative    | No account balance may become negative (u64 underflow)|
//! | ST-2 | Nonce monotonic         | Account nonces never decrease                         |
//! | ST-3 | Supply conservation     | total_supply_after == total_supply_before + minted - slashed - burned |
//! | ST-4 | State root determinism  | Same inputs always produce the same state root         |
//! | ST-5 | Height monotonic        | Block height strictly increases                       |
//! | ST-6 | Timestamp monotonic     | Block timestamp never decreases                       |
//! | ST-7 | Tx uniqueness           | No duplicate tx_hash within the same block            |
//! | ST-8 | Gas accounting          | Sum of per-tx gas == block header gas_used             |
//! | ST-9 | Tx root match           | Computed tx_root matches block header                  |
//! | ST-10| Receipts root match     | Computed receipts_root matches block header            |
//! | ST-11| State root match        | Computed state_root matches block header               |
//!
//! # Example
//!
//! ```
//! use iona::protocol::state_invariants::{StateInvariantChecker, InvariantConfig};
//! use iona::types::Block;
//!
//! let config = InvariantConfig::default();
//! let checker = StateInvariantChecker::new(config);
//! let report = checker.check_block(&block, 1, 1000, &[], &state);
//! assert!(report.all_passed);
//! ```

use crate::types::{tx_hash, Block, Hash32, Height, Receipt, tx_root, receipts_root};
use crate::execution::KvState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum supply tolerance (1 unit) for integer arithmetic.
pub const MAX_SUPPLY_TOLERANCE: u64 = 1;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during state invariant checks.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StateInvariantError {
    #[error("ST-1 violation: account {account} has balance {balance} (expected non‑negative)")]
    BalanceNegative { account: String, balance: u64 },

    #[error("ST-2 violation: nonce for {account} decreased from {old} to {new}")]
    NonceDecreased { account: String, old: u64, new: u64 },

    #[error("ST-3 violation: supply not conserved. before={before} + minted={minted} - slashed={slashed} - burned={burned} = {expected}, got {actual}, diff={diff}")]
    SupplyMismatch {
        before: u128,
        minted: u64,
        slashed: u64,
        burned: u64,
        expected: u128,
        actual: u128,
        diff: i128,
    },

    #[error("ST-4 violation: state root not deterministic: {r1} vs {r2}")]
    RootNonDeterministic { r1: String, r2: String },

    #[error("ST-5 violation: height did not increase: prev={prev}, new={new}")]
    HeightNotMonotonic { prev: Height, new: Height },

    #[error("ST-6 violation: timestamp decreased from {prev} to {new}")]
    TimestampDecreased { prev: u64, new: u64 },

    #[error("ST-7 violation: duplicate transaction hash {hash} in block at height {height}")]
    DuplicateTxHash { hash: String, height: Height },

    #[error("ST-8 violation: header gas_used={header} but sum receipts={receipts}")]
    GasMismatch { header: u64, receipts: u64 },

    #[error("ST-9 violation: tx_root mismatch: header={header}, computed={computed}")]
    TxRootMismatch { header: String, computed: String },

    #[error("ST-10 violation: receipts_root mismatch: header={header}, computed={computed}")]
    ReceiptsRootMismatch { header: String, computed: String },

    #[error("ST-11 violation: state_root mismatch: header={header}, computed={computed}")]
    StateRootMismatch { header: String, computed: String },
}

pub type StateInvariantResult<T> = Result<T, StateInvariantError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for which invariants to check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantConfig {
    pub enable_st1: bool,
    pub enable_st2: bool,
    pub enable_st3: bool,
    pub enable_st4: bool,
    pub enable_st5: bool,
    pub enable_st6: bool,
    pub enable_st7: bool,
    pub enable_st8: bool,
    pub enable_st9: bool,
    pub enable_st10: bool,
    pub enable_st11: bool,
    /// Maximum supply tolerance (default 1).
    pub supply_tolerance: u64,
}

impl Default for InvariantConfig {
    fn default() -> Self {
        Self {
            enable_st1: true,
            enable_st2: true,
            enable_st3: true,
            enable_st4: true,
            enable_st5: true,
            enable_st6: true,
            enable_st7: true,
            enable_st8: true,
            enable_st9: true,
            enable_st10: true,
            enable_st11: true,
            supply_tolerance: MAX_SUPPLY_TOLERANCE,
        }
    }
}

impl InvariantConfig {
    /// Create a config that only checks block-level invariants (no state snapshots).
    pub fn block_only() -> Self {
        Self {
            enable_st1: false,
            enable_st2: false,
            enable_st3: false,
            enable_st4: false,
            enable_st5: true,
            enable_st6: true,
            enable_st7: true,
            enable_st8: true,
            enable_st9: true,
            enable_st10: true,
            enable_st11: true,
            supply_tolerance: MAX_SUPPLY_TOLERANCE,
        }
    }

    /// Create a config that only checks state-level invariants (requires snapshots).
    pub fn state_only() -> Self {
        Self {
            enable_st1: true,
            enable_st2: true,
            enable_st3: true,
            enable_st4: true,
            enable_st5: false,
            enable_st6: false,
            enable_st7: false,
            enable_st8: false,
            enable_st9: false,
            enable_st10: false,
            enable_st11: false,
            supply_tolerance: MAX_SUPPLY_TOLERANCE,
        }
    }

    /// Create a fast config (only critical checks).
    pub fn fast() -> Self {
        Self {
            enable_st1: true,
            enable_st2: true,
            enable_st3: true,
            enable_st4: true,
            enable_st5: true,
            enable_st6: false,
            enable_st7: false,
            enable_st8: false,
            enable_st9: false,
            enable_st10: false,
            enable_st11: false,
            supply_tolerance: MAX_SUPPLY_TOLERANCE,
        }
    }

    /// Create a config with all checks disabled (for performance).
    pub fn disabled() -> Self {
        Self {
            enable_st1: false,
            enable_st2: false,
            enable_st3: false,
            enable_st4: false,
            enable_st5: false,
            enable_st6: false,
            enable_st7: false,
            enable_st8: false,
            enable_st9: false,
            enable_st10: false,
            enable_st11: false,
            supply_tolerance: MAX_SUPPLY_TOLERANCE,
        }
    }
}

// -----------------------------------------------------------------------------
// Result types
// -----------------------------------------------------------------------------

/// Result of a single invariant check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantCheck {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub detail: String,
    pub duration_ms: u64,
}

impl InvariantCheck {
    /// Create a new check result.
    pub fn new(id: &str, name: &str, passed: bool, detail: &str, duration_ms: u64) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            passed,
            detail: detail.to_string(),
            duration_ms,
        }
    }

    /// Create a success check.
    pub fn success(id: &str, name: &str, detail: &str, duration_ms: u64) -> Self {
        Self::new(id, name, true, detail, duration_ms)
    }

    /// Create a failure check.
    pub fn failure(id: &str, name: &str, detail: &str, duration_ms: u64) -> Self {
        Self::new(id, name, false, detail, duration_ms)
    }
}

/// Report from running invariant checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantReport {
    pub checks: Vec<InvariantCheck>,
    pub all_passed: bool,
    pub total_duration_ms: u64,
}

impl InvariantReport {
    /// Create a new report from checks and duration.
    pub fn new(checks: Vec<InvariantCheck>, duration: std::time::Duration) -> Self {
        let all_passed = checks.iter().all(|c| c.passed);
        let total_duration_ms = duration.as_millis() as u64;
        Self {
            checks,
            all_passed,
            total_duration_ms,
        }
    }

    /// Get the list of failed checks.
    pub fn failures(&self) -> Vec<&InvariantCheck> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }

    /// Get the list of passed checks.
    pub fn successes(&self) -> Vec<&InvariantCheck> {
        self.checks.iter().filter(|c| c.passed).collect()
    }
}

impl std::fmt::Display for InvariantReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "State Transition Invariants: {} ({} checks, {}ms)",
            if self.all_passed { "ALL PASSED" } else { "VIOLATIONS DETECTED" },
            self.checks.len(),
            self.total_duration_ms
        )?;
        for c in &self.checks {
            let mark = if c.passed { "✓" } else { "✗" };
            writeln!(f, "  [{}] {}: {} [{}ms]", mark, c.id, c.detail, c.duration_ms)?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Supply delta
// -----------------------------------------------------------------------------

/// Parameters for supply conservation check.
#[derive(Debug, Clone, Default)]
pub struct SupplyDelta {
    pub minted: u64,
    pub slashed: u64,
    pub burned_delta: u64,
}

// -----------------------------------------------------------------------------
// Individual check functions
// -----------------------------------------------------------------------------

/// ST-1: Verify no account has a negative balance (impossible with u64, but guards
/// against saturating_sub masking logic bugs).
pub fn check_balances_non_negative(balances: &BTreeMap<String, u64>) -> StateInvariantResult<()> {
    for (account, &balance) in balances {
        // With u64, this is always true, but we check for MAX (potential overflow).
        if balance == u64::MAX {
            return Err(StateInvariantError::BalanceNegative {
                account: account.clone(),
                balance,
            });
        }
    }
    debug!(count = balances.len(), "ST-1 passed");
    Ok(())
}

/// ST-2: Verify nonces only increase.
pub fn check_nonces_monotonic(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
) -> StateInvariantResult<()> {
    for (account, &new_nonce) in after {
        let old_nonce = before.get(account).copied().unwrap_or(0);
        if new_nonce < old_nonce {
            return Err(StateInvariantError::NonceDecreased {
                account: account.clone(),
                old: old_nonce,
                new: new_nonce,
            });
        }
    }
    debug!(before_len = before.len(), after_len = after.len(), "ST-2 passed");
    Ok(())
}

/// ST-3: Check supply conservation.
pub fn check_supply_conservation(
    balances_before: &BTreeMap<String, u64>,
    balances_after: &BTreeMap<String, u64>,
    staked_before: u64,
    staked_after: u64,
    delta: &SupplyDelta,
    tolerance: u64,
) -> StateInvariantResult<()> {
    let sum_before: u128 =
        balances_before.values().map(|&v| v as u128).sum::<u128>() + staked_before as u128;
    let sum_after: u128 =
        balances_after.values().map(|&v| v as u128).sum::<u128>() + staked_after as u128;

    let expected = sum_before
        .saturating_add(delta.minted as u128)
        .saturating_sub(delta.slashed as u128)
        .saturating_sub(delta.burned_delta as u128);

    let diff = if sum_after >= expected {
        sum_after - expected
    } else {
        expected - sum_after
    };

    if diff > tolerance as u128 {
        let diff_signed = (sum_after as i128) - (expected as i128);
        return Err(StateInvariantError::SupplyMismatch {
            before: sum_before,
            minted: delta.minted,
            slashed: delta.slashed,
            burned: delta.burned_delta,
            expected,
            actual: sum_after,
            diff: diff_signed,
        });
    }
    debug!(
        sum_before,
        sum_after,
        minted = delta.minted,
        slashed = delta.slashed,
        burned = delta.burned_delta,
        "ST-3 passed"
    );
    Ok(())
}

/// ST-4: State root determinism.
pub fn check_state_root_determinism(state: &KvState) -> StateInvariantResult<Hash32> {
    let r1 = state.root();
    let r2 = state.root();
    if r1 != r2 {
        return Err(StateInvariantError::RootNonDeterministic {
            r1: hex::encode(r1.0),
            r2: hex::encode(r2.0),
        });
    }
    debug!("ST-4 passed (state root deterministic)");
    Ok(r1)
}

/// ST-5: Height monotonic.
pub fn check_height_monotonic(prev_height: Height, new_height: Height) -> StateInvariantResult<()> {
    if new_height <= prev_height {
        return Err(StateInvariantError::HeightNotMonotonic {
            prev: prev_height,
            new: new_height,
        });
    }
    debug!(prev = prev_height, new = new_height, "ST-5 passed");
    Ok(())
}

/// ST-6: Timestamp monotonic.
pub fn check_timestamp_monotonic(prev_timestamp: u64, new_timestamp: u64) -> StateInvariantResult<()> {
    if new_timestamp < prev_timestamp {
        return Err(StateInvariantError::TimestampDecreased {
            prev: prev_timestamp,
            new: new_timestamp,
        });
    }
    debug!(prev = prev_timestamp, new = new_timestamp, "ST-6 passed");
    Ok(())
}

/// ST-7: Tx uniqueness.
pub fn check_tx_uniqueness(block: &Block) -> StateInvariantResult<()> {
    let mut seen = std::collections::HashSet::new();
    for tx in &block.txs {
        let h = tx_hash(tx);
        let h_hex = hex::encode(h.0);
        if !seen.insert(h) {
            return Err(StateInvariantError::DuplicateTxHash {
                hash: h_hex,
                height: block.header.height,
            });
        }
    }
    debug!(height = block.header.height, txs = block.txs.len(), "ST-7 passed");
    Ok(())
}

/// ST-8: Gas accounting.
pub fn check_gas_accounting(header_gas_used: u64, receipts: &[Receipt]) -> StateInvariantResult<()> {
    let sum: u64 = receipts.iter().map(|r| r.gas_used).sum();
    if sum != header_gas_used {
        return Err(StateInvariantError::GasMismatch {
            header: header_gas_used,
            receipts: sum,
        });
    }
    debug!(header_gas_used, sum, receipts_len = receipts.len(), "ST-8 passed");
    Ok(())
}

/// ST-9: Tx root matches header.
pub fn check_tx_root(block: &Block) -> StateInvariantResult<()> {
    let computed = tx_root(&block.txs);
    if computed != block.header.tx_root {
        return Err(StateInvariantError::TxRootMismatch {
            header: hex::encode(block.header.tx_root.0),
            computed: hex::encode(computed.0),
        });
    }
    debug!("ST-9 passed (tx_root matches)");
    Ok(())
}

/// ST-10: Receipts root matches header.
pub fn check_receipts_root(block: &Block) -> StateInvariantResult<()> {
    let computed = receipts_root(&block.receipts);
    if computed != block.header.receipts_root {
        return Err(StateInvariantError::ReceiptsRootMismatch {
            header: hex::encode(block.header.receipts_root.0),
            computed: hex::encode(computed.0),
        });
    }
    debug!("ST-10 passed (receipts_root matches)");
    Ok(())
}

/// ST-11: State root matches header.
pub fn check_state_root(state: &KvState, block: &Block) -> StateInvariantResult<()> {
    let computed = state.root();
    if computed != block.header.state_root {
        return Err(StateInvariantError::StateRootMismatch {
            header: hex::encode(block.header.state_root.0),
            computed: hex::encode(computed.0),
        });
    }
    debug!("ST-11 passed (state_root matches)");
    Ok(())
}

// -----------------------------------------------------------------------------
// Checker struct
// -----------------------------------------------------------------------------

/// Main checker for state invariants.
#[derive(Debug, Clone)]
pub struct StateInvariantChecker {
    config: InvariantConfig,
}

impl StateInvariantChecker {
    /// Create a new checker with the given configuration.
    pub fn new(config: InvariantConfig) -> Self {
        Self { config }
    }

    /// Create a checker with default configuration.
    pub fn default() -> Self {
        Self::new(InvariantConfig::default())
    }

    /// Run block-level invariants (ST-5 through ST-11).
    pub fn check_block(
        &self,
        block: &Block,
        prev_height: Height,
        prev_timestamp: u64,
        receipts: &[Receipt],
        state: &KvState,
    ) -> InvariantReport {
        let start = Instant::now();
        let mut checks = Vec::new();

        if self.config.enable_st5 {
            let c_start = Instant::now();
            let r = check_height_monotonic(prev_height, block.header.height);
            checks.push(InvariantCheck::new(
                "ST-5",
                "Height monotonic",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        if self.config.enable_st6 {
            let c_start = Instant::now();
            let r = check_timestamp_monotonic(prev_timestamp, block.header.timestamp);
            checks.push(InvariantCheck::new(
                "ST-6",
                "Timestamp monotonic",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        if self.config.enable_st7 {
            let c_start = Instant::now();
            let r = check_tx_uniqueness(block);
            checks.push(InvariantCheck::new(
                "ST-7",
                "Tx uniqueness",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        if self.config.enable_st8 {
            let c_start = Instant::now();
            let r = check_gas_accounting(block.header.gas_used, receipts);
            checks.push(InvariantCheck::new(
                "ST-8",
                "Gas accounting",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        if self.config.enable_st9 {
            let c_start = Instant::now();
            let r = check_tx_root(block);
            checks.push(InvariantCheck::new(
                "ST-9",
                "Tx root match",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        if self.config.enable_st10 {
            let c_start = Instant::now();
            let r = check_receipts_root(block);
            checks.push(InvariantCheck::new(
                "ST-10",
                "Receipts root match",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        if self.config.enable_st11 {
            let c_start = Instant::now();
            let r = check_state_root(state, block);
            checks.push(InvariantCheck::new(
                "ST-11",
                "State root match",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        InvariantReport::new(checks, start.elapsed())
    }

    /// Run state-level invariants (ST-1 through ST-4).
    pub fn check_state(
        &self,
        balances_before: &BTreeMap<String, u64>,
        balances_after: &BTreeMap<String, u64>,
        nonces_before: &BTreeMap<String, u64>,
        nonces_after: &BTreeMap<String, u64>,
        staked_before: u64,
        staked_after: u64,
        delta: &SupplyDelta,
        state: &KvState,
    ) -> InvariantReport {
        let start = Instant::now();
        let mut checks = Vec::new();

        if self.config.enable_st1 {
            let c_start = Instant::now();
            let r = check_balances_non_negative(balances_after);
            checks.push(InvariantCheck::new(
                "ST-1",
                "Balance non‑negative",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        if self.config.enable_st2 {
            let c_start = Instant::now();
            let r = check_nonces_monotonic(nonces_before, nonces_after);
            checks.push(InvariantCheck::new(
                "ST-2",
                "Nonce monotonic",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        if self.config.enable_st3 {
            let c_start = Instant::now();
            let r = check_supply_conservation(
                balances_before,
                balances_after,
                staked_before,
                staked_after,
                delta,
                self.config.supply_tolerance,
            );
            checks.push(InvariantCheck::new(
                "ST-3",
                "Supply conservation",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        if self.config.enable_st4 {
            let c_start = Instant::now();
            let r = check_state_root_determinism(state);
            checks.push(InvariantCheck::new(
                "ST-4",
                "State root determinism",
                r.is_ok(),
                &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                c_start.elapsed().as_millis() as u64,
            ));
        }

        InvariantReport::new(checks, start.elapsed())
    }

    /// Run all invariants (both block and state).
    pub fn check_all(
        &self,
        block: &Block,
        prev_height: Height,
        prev_timestamp: u64,
        receipts: &[Receipt],
        state: &KvState,
        balances_before: &BTreeMap<String, u64>,
        balances_after: &BTreeMap<String, u64>,
        nonces_before: &BTreeMap<String, u64>,
        nonces_after: &BTreeMap<String, u64>,
        staked_before: u64,
        staked_after: u64,
        delta: &SupplyDelta,
    ) -> InvariantReport {
        let start = Instant::now();
        let mut checks = Vec::new();

        // Block checks.
        let block_report = self.check_block(block, prev_height, prev_timestamp, receipts, state);
        checks.extend(block_report.checks);

        // State checks.
        let state_report = self.check_state(
            balances_before,
            balances_after,
            nonces_before,
            nonces_after,
            staked_before,
            staked_after,
            delta,
            state,
        );
        checks.extend(state_report.checks);

        let all_passed = checks.iter().all(|c| c.passed);
        let total_duration_ms = start.elapsed().as_millis() as u64;
        if all_passed {
            info!("All state invariants passed");
        } else {
            let failed: Vec<_> = checks.iter().filter(|c| !c.passed).map(|c| c.id.clone()).collect();
            warn!(failed = ?failed, "State invariants failed");
        }

        InvariantReport {
            checks,
            all_passed,
            total_duration_ms,
        }
    }
}

// -----------------------------------------------------------------------------
// Standalone convenience functions (backward compatibility)
// -----------------------------------------------------------------------------

/// Run block-level invariants (legacy function).
pub fn check_block_invariants(
    block: &Block,
    prev_height: Height,
    prev_timestamp: u64,
    receipts: &[Receipt],
) -> InvariantReport {
    let checker = StateInvariantChecker::default();
    // For this legacy function, we don't have a state object, so we skip ST-11.
    // We'll use a dummy state.
    let dummy_state = KvState::default();
    checker.check_block(block, prev_height, prev_timestamp, receipts, &dummy_state)
}

/// Run all state invariants (legacy function).
pub fn check_all_state_invariants(
    balances_before: &BTreeMap<String, u64>,
    balances_after: &BTreeMap<String, u64>,
    nonces_before: &BTreeMap<String, u64>,
    nonces_after: &BTreeMap<String, u64>,
    staked_before: u64,
    staked_after: u64,
    delta: &SupplyDelta,
    state: &KvState,
    block: &Block,
    prev_height: Height,
    prev_timestamp: u64,
    receipts: &[Receipt],
) -> InvariantReport {
    let checker = StateInvariantChecker::default();
    checker.check_all(
        block,
        prev_height,
        prev_timestamp,
        receipts,
        state,
        balances_before,
        balances_after,
        nonces_before,
        nonces_after,
        staked_before,
        staked_after,
        delta,
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, BlockHeader, Hash32, Receipt};

    #[test]
    fn test_balances_non_negative_ok() {
        let mut b = BTreeMap::new();
        b.insert("alice".into(), 1000u64);
        b.insert("bob".into(), 0u64);
        assert!(check_balances_non_negative(&b).is_ok());
    }

    #[test]
    fn test_balances_overflow_warning() {
        let mut b = BTreeMap::new();
        b.insert("alice".into(), u64::MAX);
        let err = check_balances_non_negative(&b).unwrap_err();
        assert!(matches!(err, StateInvariantError::BalanceNegative { .. }));
    }

    #[test]
    fn test_nonces_monotonic_ok() {
        let mut before = BTreeMap::new();
        before.insert("alice".into(), 5u64);
        let mut after = BTreeMap::new();
        after.insert("alice".into(), 6u64);
        after.insert("bob".into(), 1u64);
        assert!(check_nonces_monotonic(&before, &after).is_ok());
    }

    #[test]
    fn test_nonces_monotonic_violation() {
        let mut before = BTreeMap::new();
        before.insert("alice".into(), 10u64);
        let mut after = BTreeMap::new();
        after.insert("alice".into(), 5u64);
        let err = check_nonces_monotonic(&before, &after).unwrap_err();
        assert!(matches!(err, StateInvariantError::NonceDecreased { .. }));
    }

    #[test]
    fn test_supply_conservation_ok() {
        let mut before = BTreeMap::new();
        before.insert("alice".into(), 1000u64);

        let mut after = BTreeMap::new();
        after.insert("alice".into(), 1010u64);

        let delta = SupplyDelta {
            minted: 10,
            slashed: 0,
            burned_delta: 0,
        };
        assert!(check_supply_conservation(&before, &after, 0, 0, &delta, 1).is_ok());
    }

    #[test]
    fn test_supply_conservation_violation() {
        let mut before = BTreeMap::new();
        before.insert("alice".into(), 1000u64);

        let mut after = BTreeMap::new();
        after.insert("alice".into(), 2000u64);

        let delta = SupplyDelta::default();
        let err = check_supply_conservation(&before, &after, 0, 0, &delta, 1).unwrap_err();
        assert!(matches!(err, StateInvariantError::SupplyMismatch { .. }));
    }

    #[test]
    fn test_state_root_determinism() {
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1000);
        state.kv.insert("k".into(), "v".into());
        assert!(check_state_root_determinism(&state).is_ok());
    }

    #[test]
    fn test_height_monotonic_ok() {
        assert!(check_height_monotonic(5, 6).is_ok());
        assert!(check_height_monotonic(0, 1).is_ok());
    }

    #[test]
    fn test_height_monotonic_violation() {
        let err = check_height_monotonic(5, 5).unwrap_err();
        assert!(matches!(err, StateInvariantError::HeightNotMonotonic { prev: 5, new: 5 }));
    }

    #[test]
    fn test_timestamp_monotonic_ok() {
        assert!(check_timestamp_monotonic(100, 100).is_ok());
        assert!(check_timestamp_monotonic(100, 200).is_ok());
    }

    #[test]
    fn test_timestamp_monotonic_violation() {
        let err = check_timestamp_monotonic(200, 100).unwrap_err();
        assert!(matches!(err, StateInvariantError::TimestampDecreased { prev: 200, new: 100 }));
    }

    #[test]
    fn test_gas_accounting_ok() {
        let receipts = vec![
            Receipt::default_with_gas(21000),
            Receipt::default_with_gas(42000),
        ];
        assert!(check_gas_accounting(63000, &receipts).is_ok());
    }

    #[test]
    fn test_gas_accounting_violation() {
        let receipts = vec![Receipt::default_with_gas(21000)];
        let err = check_gas_accounting(99999, &receipts).unwrap_err();
        assert!(matches!(err, StateInvariantError::GasMismatch { header: 99999, receipts: 21000 }));
    }

    #[test]
    fn test_checker_block() {
        let block = Block {
            header: BlockHeader {
                height: 2,
                round: 0,
                prev: Hash32::zero(),
                proposer_pk: vec![0u8; 32],
                tx_root: Hash32::zero(),
                receipts_root: Hash32::zero(),
                state_root: Hash32::zero(),
                base_fee_per_gas: 1,
                gas_used: 0,
                intrinsic_gas_used: 0,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                chain_id: 6126151,
                timestamp: 2000,
                protocol_version: 1,
            },
            txs: vec![],
            receipts: vec![],
        };
        let checker = StateInvariantChecker::default();
        let state = KvState::default();
        let report = checker.check_block(&block, 1, 1000, &[], &state);
        assert!(report.all_passed, "report: {report}");
        assert_eq!(report.checks.len(), 7); // ST-5 through ST-11
    }

    #[test]
    fn test_checker_state() {
        let mut before = BTreeMap::new();
        before.insert("alice".into(), 1000);
        let mut after = BTreeMap::new();
        after.insert("alice".into(), 1010);
        let nonces_before = BTreeMap::new();
        let nonces_after = BTreeMap::new();
        let delta = SupplyDelta { minted: 10, ..Default::default() };
        let state = KvState::default();
        let checker = StateInvariantChecker::default();
        let report = checker.check_state(
            &before, &after,
            &nonces_before, &nonces_after,
            0, 0,
            &delta,
            &state,
        );
        assert!(report.all_passed, "report: {report}");
        assert_eq!(report.checks.len(), 4); // ST-1 through ST-4
    }

    #[test]
    fn test_checker_all() {
        let block = Block {
            header: BlockHeader {
                height: 2,
                round: 0,
                prev: Hash32::zero(),
                proposer_pk: vec![0u8; 32],
                tx_root: Hash32::zero(),
                receipts_root: Hash32::zero(),
                state_root: Hash32::zero(),
                base_fee_per_gas: 1,
                gas_used: 0,
                intrinsic_gas_used: 0,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                chain_id: 6126151,
                timestamp: 2000,
                protocol_version: 1,
            },
            txs: vec![],
            receipts: vec![],
        };
        let mut before = BTreeMap::new();
        before.insert("alice".into(), 1000);
        let mut after = BTreeMap::new();
        after.insert("alice".into(), 1010);
        let nonces_before = BTreeMap::new();
        let nonces_after = BTreeMap::new();
        let delta = SupplyDelta { minted: 10, ..Default::default() };
        let state = KvState::default();
        let checker = StateInvariantChecker::default();
        let report = checker.check_all(
            &block, 1, 1000, &[], &state,
            &before, &after,
            &nonces_before, &nonces_after,
            0, 0,
            &delta,
        );
        assert!(report.all_passed, "report: {report}");
        assert_eq!(report.checks.len(), 11);
    }

    #[test]
    fn test_report_display() {
        let checks = vec![
            InvariantCheck::success("ST-1", "Test", "ok", 1),
            InvariantCheck::failure("ST-2", "Test", "failed", 2),
        ];
        let report = InvariantReport::new(checks, std::time::Duration::from_millis(3));
        let s = format!("{}", report);
        assert!(s.contains("VIOLATIONS DETECTED"));
        assert!(s.contains("✓"));
        assert!(s.contains("✗"));
    }

    #[test]
    fn test_config_fast() {
        let config = InvariantConfig::fast();
        assert!(config.enable_st1);
        assert!(config.enable_st2);
        assert!(config.enable_st3);
        assert!(config.enable_st4);
        assert!(config.enable_st5);
        assert!(!config.enable_st6);
        assert!(!config.enable_st7);
        assert!(!config.enable_st8);
        assert!(!config.enable_st9);
        assert!(!config.enable_st10);
        assert!(!config.enable_st11);
    }

    #[test]
    fn test_config_block_only() {
        let config = InvariantConfig::block_only();
        assert!(!config.enable_st1);
        assert!(!config.enable_st2);
        assert!(!config.enable_st3);
        assert!(!config.enable_st4);
        assert!(config.enable_st5);
        assert!(config.enable_st6);
        assert!(config.enable_st7);
        assert!(config.enable_st8);
        assert!(config.enable_st9);
        assert!(config.enable_st10);
        assert!(config.enable_st11);
    }
}
