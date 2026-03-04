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

use crate::types::{Block, Hash32, Height, Receipt, tx_hash};
use std::collections::BTreeMap;

// ─── ST-1: Balance non-negative ─────────────────────────────────────────────

/// Verify no account has a negative balance (impossible with u64, but guards
/// against saturating_sub masking logic bugs).
pub fn check_balances_non_negative(balances: &BTreeMap<String, u64>) -> Result<(), String> {
    // With u64 this is structurally guaranteed; this check exists as a
    // documentation anchor and for potential future i128 migration.
    for (addr, &bal) in balances {
        if bal == u64::MAX {
            return Err(format!(
                "ST-1 WARNING: account {addr} has MAX balance ({bal}), likely overflow"
            ));
        }
    }
    Ok(())
}

// ─── ST-2: Nonce monotonic ──────────────────────────────────────────────────

/// Verify that nonces only increase between two snapshots.
pub fn check_nonces_monotonic(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
) -> Result<(), String> {
    for (addr, &new_nonce) in after {
        let old_nonce = before.get(addr).copied().unwrap_or(0);
        if new_nonce < old_nonce {
            return Err(format!(
                "ST-2 VIOLATION: nonce for {addr} decreased from {old_nonce} to {new_nonce}"
            ));
        }
    }
    Ok(())
}

// ─── ST-3: Supply conservation ──────────────────────────────────────────────

/// Parameters for supply conservation check.
#[derive(Debug, Clone)]
pub struct SupplyDelta {
    pub minted: u64,
    pub slashed: u64,
    pub burned_delta: u64,
}

/// Check that total token supply is conserved across a state transition.
pub fn check_supply_conservation(
    balances_before: &BTreeMap<String, u64>,
    balances_after: &BTreeMap<String, u64>,
    staked_before: u64,
    staked_after: u64,
    delta: &SupplyDelta,
) -> Result<(), String> {
    let sum_before: u128 = balances_before.values().map(|&v| v as u128).sum::<u128>()
        + staked_before as u128;
    let sum_after: u128 = balances_after.values().map(|&v| v as u128).sum::<u128>()
        + staked_after as u128;

    let expected = sum_before
        .saturating_add(delta.minted as u128)
        .saturating_sub(delta.slashed as u128)
        .saturating_sub(delta.burned_delta as u128);

    if sum_after != expected {
        return Err(format!(
            "ST-3 VIOLATION: supply not conserved. before={sum_before} + minted={} \
             - slashed={} - burned={} = expected {expected}, got {sum_after} (diff={})",
            delta.minted, delta.slashed, delta.burned_delta,
            (sum_after as i128) - (expected as i128)
        ));
    }
    Ok(())
}

// ─── ST-4: State root determinism ───────────────────────────────────────────

/// Verify that computing the state root twice yields the same result.
pub fn check_state_root_determinism(
    state: &crate::execution::KvState,
) -> Result<Hash32, String> {
    let r1 = state.root();
    let r2 = state.root();
    if r1 != r2 {
        return Err(format!(
            "ST-4 VIOLATION: state root not deterministic: {} vs {}",
            hex::encode(r1.0),
            hex::encode(r2.0),
        ));
    }
    Ok(r1)
}

// ─── ST-5: Height monotonic ─────────────────────────────────────────────────

/// Verify that the new block height strictly follows the previous height.
pub fn check_height_monotonic(
    prev_height: Height,
    new_height: Height,
) -> Result<(), String> {
    if new_height <= prev_height {
        return Err(format!(
            "ST-5 VIOLATION: height did not increase: prev={prev_height}, new={new_height}"
        ));
    }
    Ok(())
}

// ─── ST-6: Timestamp monotonic ──────────────────────────────────────────────

/// Verify that the block timestamp does not decrease.
pub fn check_timestamp_monotonic(
    prev_timestamp: u64,
    new_timestamp: u64,
) -> Result<(), String> {
    if new_timestamp < prev_timestamp {
        return Err(format!(
            "ST-6 VIOLATION: timestamp decreased from {prev_timestamp} to {new_timestamp}"
        ));
    }
    Ok(())
}

// ─── ST-7: Tx uniqueness ────────────────────────────────────────────────────

/// Verify that no two transactions in the block share the same hash.
pub fn check_tx_uniqueness(block: &Block) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for tx in &block.txs {
        let h = tx_hash(tx);
        let h_hex = hex::encode(h.0);
        if !seen.insert(h) {
            return Err(format!(
                "ST-7 VIOLATION: duplicate tx_hash {} in block at height {}",
                h_hex,
                block.header.height,
            ));
        }
    }
    Ok(())
}

// ─── ST-8: Gas accounting ───────────────────────────────────────────────────

/// Verify that the sum of per-tx gas matches the block header's gas_used.
pub fn check_gas_accounting(
    header_gas_used: u64,
    receipts: &[Receipt],
) -> Result<(), String> {
    let sum: u64 = receipts.iter().map(|r| r.gas_used).sum();
    if sum != header_gas_used {
        return Err(format!(
            "ST-8 VIOLATION: header gas_used={header_gas_used} but sum(receipt.gas_used)={sum}"
        ));
    }
    Ok(())
}

// ─── Aggregate check ────────────────────────────────────────────────────────

/// Result of running all state transition invariant checks.
#[derive(Debug, Clone)]
pub struct InvariantReport {
    pub checks: Vec<InvariantCheck>,
    pub all_passed: bool,
}

#[derive(Debug, Clone)]
pub struct InvariantCheck {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl std::fmt::Display for InvariantReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "State Transition Invariants: {}",
            if self.all_passed { "ALL PASSED" } else { "VIOLATIONS DETECTED" })?;
        for c in &self.checks {
            let mark = if c.passed { "OK" } else { "FAIL" };
            writeln!(f, "  [{mark}] {}: {} — {}", c.id, c.name, c.detail)?;
        }
        Ok(())
    }
}

/// Run a subset of invariants that can be checked with minimal context.
pub fn check_block_invariants(
    block: &Block,
    prev_height: Height,
    prev_timestamp: u64,
    receipts: &[Receipt],
) -> InvariantReport {
    let mut checks = Vec::new();

    // ST-5: Height monotonic
    let h = check_height_monotonic(prev_height, block.header.height);
    checks.push(InvariantCheck {
        id: "ST-5".into(),
        name: "Height monotonic".into(),
        passed: h.is_ok(),
        detail: h.err().unwrap_or_else(|| "height strictly increasing".into()),
    });

    // ST-6: Timestamp monotonic
    let t = check_timestamp_monotonic(prev_timestamp, block.header.timestamp);
    checks.push(InvariantCheck {
        id: "ST-6".into(),
        name: "Timestamp monotonic".into(),
        passed: t.is_ok(),
        detail: t.err().unwrap_or_else(|| "timestamp non-decreasing".into()),
    });

    // ST-7: Tx uniqueness
    let u = check_tx_uniqueness(block);
    checks.push(InvariantCheck {
        id: "ST-7".into(),
        name: "Tx uniqueness".into(),
        passed: u.is_ok(),
        detail: u.err().unwrap_or_else(|| format!("{} unique txs", block.txs.len())),
    });

    // ST-8: Gas accounting
    let g = check_gas_accounting(block.header.gas_used, receipts);
    checks.push(InvariantCheck {
        id: "ST-8".into(),
        name: "Gas accounting".into(),
        passed: g.is_ok(),
        detail: g.err().unwrap_or_else(|| format!("gas_used={}", block.header.gas_used)),
    });

    let all_passed = checks.iter().all(|c| c.passed);
    InvariantReport { checks, all_passed }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(check_balances_non_negative(&b).is_err());
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
        assert!(check_nonces_monotonic(&before, &after).is_err());
    }

    #[test]
    fn test_supply_conservation_ok() {
        let mut before = BTreeMap::new();
        before.insert("alice".into(), 1000u64);
        before.insert("bob".into(), 500u64);

        let mut after = BTreeMap::new();
        after.insert("alice".into(), 990u64);
        after.insert("bob".into(), 500u64);

        let delta = SupplyDelta { minted: 0, slashed: 0, burned_delta: 10 };
        assert!(check_supply_conservation(&before, &after, 0, 0, &delta).is_ok());
    }

    #[test]
    fn test_supply_conservation_with_minting() {
        let mut before = BTreeMap::new();
        before.insert("alice".into(), 1000u64);

        let mut after = BTreeMap::new();
        after.insert("alice".into(), 1100u64);

        let delta = SupplyDelta { minted: 100, slashed: 0, burned_delta: 0 };
        assert!(check_supply_conservation(&before, &after, 0, 0, &delta).is_ok());
    }

    #[test]
    fn test_supply_conservation_violation() {
        let mut before = BTreeMap::new();
        before.insert("alice".into(), 1000u64);

        let mut after = BTreeMap::new();
        after.insert("alice".into(), 2000u64); // appeared from nowhere

        let delta = SupplyDelta { minted: 0, slashed: 0, burned_delta: 0 };
        assert!(check_supply_conservation(&before, &after, 0, 0, &delta).is_err());
    }

    #[test]
    fn test_state_root_determinism() {
        let mut state = crate::execution::KvState::default();
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
        assert!(check_height_monotonic(5, 5).is_err());
        assert!(check_height_monotonic(5, 4).is_err());
    }

    #[test]
    fn test_timestamp_monotonic_ok() {
        assert!(check_timestamp_monotonic(100, 100).is_ok());
        assert!(check_timestamp_monotonic(100, 200).is_ok());
    }

    #[test]
    fn test_timestamp_monotonic_violation() {
        assert!(check_timestamp_monotonic(200, 100).is_err());
    }

    #[test]
    fn test_gas_accounting_ok() {
        let receipts = vec![
            Receipt {
                tx_hash: Hash32::zero(),
                success: true,
                gas_used: 21000,
                intrinsic_gas_used: 21000,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                effective_gas_price: 100,
                burned: 0,
                tip: 0,
                error: None,
                data: None,
            },
            Receipt {
                tx_hash: Hash32::zero(),
                success: true,
                gas_used: 42000,
                intrinsic_gas_used: 42000,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                effective_gas_price: 100,
                burned: 0,
                tip: 0,
                error: None,
                data: None,
            },
        ];
        assert!(check_gas_accounting(63000, &receipts).is_ok());
    }

    #[test]
    fn test_gas_accounting_violation() {
        let receipts = vec![
            Receipt {
                tx_hash: Hash32::zero(),
                success: true,
                gas_used: 21000,
                intrinsic_gas_used: 21000,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                effective_gas_price: 100,
                burned: 0,
                tip: 0,
                error: None,
                data: None,
            },
        ];
        assert!(check_gas_accounting(99999, &receipts).is_err());
    }

    #[test]
    fn test_block_invariants_report() {
        use crate::types::{Block, BlockHeader};

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
        };
        let report = check_block_invariants(&block, 1, 1000, &[]);
        assert!(report.all_passed, "report: {report}");
        assert_eq!(report.checks.len(), 4);
    }

    #[test]
    fn test_invariant_report_display() {
        let report = InvariantReport {
            checks: vec![
                InvariantCheck {
                    id: "ST-1".into(),
                    name: "Test".into(),
                    passed: true,
                    detail: "ok".into(),
                },
            ],
            all_passed: true,
        };
        let s = format!("{report}");
        assert!(s.contains("ALL PASSED"));
    }
}
