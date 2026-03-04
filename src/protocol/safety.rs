//! Safety invariant checks for protocol upgrades.
//!
//! These functions verify the formal safety properties defined in
//! `spec/upgrade/UPGRADE_SPEC.md` section 7.
//!
//! # Invariants checked
//!
//! - **S1 (No Split Finality)**: At most one finalized block per height.
//! - **S2 (Finality Monotonic)**: `finalized_height` never decreases.
//! - **S3 (Deterministic PV)**: All correct nodes agree on `PV(height)`.
//! - **S4 (State Compatibility)**: Old PV not applied after activation.
//! - **M2 (Value Conservation)**: Token supply is conserved across state transitions.

use crate::types::Height;

// ─── S1: No split finality ──────────────────────────────────────────────────

/// Verify that at most one block has been finalized at the given height.
///
/// `finalized_ids` is the set of distinct block IDs that have been finalized
/// for this height (should be 0 or 1).
pub fn check_no_split_finality(height: Height, finalized_count: usize) -> Result<(), String> {
    if finalized_count > 1 {
        return Err(format!(
            "SAFETY VIOLATION S1: {finalized_count} blocks finalized at height {height}; \
             expected at most 1"
        ));
    }
    Ok(())
}

// ─── S2: Finality monotonic ─────────────────────────────────────────────────

/// Verify that the new finalized height is >= the previous one.
pub fn check_finality_monotonic(
    prev_finalized: Height,
    new_finalized: Height,
) -> Result<(), String> {
    if new_finalized < prev_finalized {
        return Err(format!(
            "SAFETY VIOLATION S2: finalized_height decreased from {prev_finalized} to {new_finalized}"
        ));
    }
    Ok(())
}

// ─── S3: Deterministic PV ───────────────────────────────────────────────────

/// Verify that the locally computed PV matches the block's PV.
///
/// This check ensures that all correct nodes agree on which protocol version
/// applies at a given height.
pub fn check_deterministic_pv(
    height: Height,
    block_pv: u32,
    local_pv: u32,
    activations: &[crate::protocol::version::ProtocolActivation],
) -> Result<(), String> {
    // The block's PV must match what we compute locally for this height,
    // unless we're in a grace window.
    crate::protocol::version::validate_block_version(block_pv, height, activations)?;

    // Additionally, the block PV should match local computation exactly
    // (outside of grace windows).
    let expected = crate::protocol::version::version_for_height(height, activations);
    if block_pv != expected && block_pv != local_pv {
        return Err(format!(
            "SAFETY WARNING S3: block PV={block_pv} differs from local PV={local_pv} \
             at height {height} (expected PV={expected})"
        ));
    }
    Ok(())
}

// ─── S4: State compatibility ────────────────────────────────────────────────

/// Verify that after activation, we're not applying old-PV execution rules.
pub fn check_state_compat(
    height: Height,
    execution_pv: u32,
    activations: &[crate::protocol::version::ProtocolActivation],
) -> Result<(), String> {
    let expected = crate::protocol::version::version_for_height(height, activations);
    if execution_pv < expected {
        // Check grace window
        let in_grace = activations.iter().any(|a| {
            a.protocol_version == expected
                && a.activation_height
                    .map(|ah| height < ah + a.grace_blocks)
                    .unwrap_or(false)
        });
        if !in_grace {
            return Err(format!(
                "SAFETY VIOLATION S4: executing with PV={execution_pv} at height {height}, \
                 but PV={expected} is mandatory (grace window expired)"
            ));
        }
    }
    Ok(())
}

// ─── M2: Value conservation ─────────────────────────────────────────────────

/// Check that total token supply is conserved across a state transition.
///
/// `supply_before` = sum(balances) + sum(staked) before block execution.
/// `supply_after`  = sum(balances) + sum(staked) after block execution.
/// `minted`        = block rewards minted (epoch boundary).
/// `slashed`       = tokens destroyed by slashing.
/// `burned`        = tokens burned via EIP-1559 base fee.
///
/// Invariant: `supply_after == supply_before + minted - slashed - burned`
pub fn check_value_conservation(
    supply_before: u128,
    supply_after: u128,
    minted: u128,
    slashed: u128,
    burned: u128,
) -> Result<(), String> {
    let expected = supply_before
        .saturating_add(minted)
        .saturating_sub(slashed)
        .saturating_sub(burned);
    if supply_after != expected {
        return Err(format!(
            "SAFETY VIOLATION M2: value not conserved. \
             before={supply_before} + minted={minted} - slashed={slashed} - burned={burned} \
             = expected {expected}, got {supply_after} (diff={})",
            (supply_after as i128) - (expected as i128)
        ));
    }
    Ok(())
}

// ─── M3: Root equivalence ───────────────────────────────────────────────────

/// Verify that a format-only migration preserves the state root.
///
/// `root_before` and `root_after` are the Merkle state roots computed
/// before and after the migration.
pub fn check_root_equivalence(root_before: &[u8; 32], root_after: &[u8; 32]) -> Result<(), String> {
    if root_before != root_after {
        return Err(format!(
            "SAFETY VIOLATION M3: state root changed after format migration. \
             before={}, after={}",
            hex::encode(root_before),
            hex::encode(root_after),
        ));
    }
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_split_finality_ok() {
        assert!(check_no_split_finality(1, 0).is_ok());
        assert!(check_no_split_finality(1, 1).is_ok());
    }

    #[test]
    fn test_no_split_finality_violation() {
        assert!(check_no_split_finality(1, 2).is_err());
    }

    #[test]
    fn test_finality_monotonic_ok() {
        assert!(check_finality_monotonic(5, 5).is_ok());
        assert!(check_finality_monotonic(5, 6).is_ok());
    }

    #[test]
    fn test_finality_monotonic_violation() {
        assert!(check_finality_monotonic(5, 4).is_err());
    }

    #[test]
    fn test_value_conservation_ok() {
        // 1000 before + 10 minted - 0 slashed - 5 burned = 1005 after
        assert!(check_value_conservation(1000, 1005, 10, 0, 5).is_ok());
    }

    #[test]
    fn test_value_conservation_violation() {
        // 1000 before + 10 minted - 0 slashed - 0 burned = 1010 expected, got 1020
        assert!(check_value_conservation(1000, 1020, 10, 0, 0).is_err());
    }

    #[test]
    fn test_root_equivalence_ok() {
        let root = [42u8; 32];
        assert!(check_root_equivalence(&root, &root).is_ok());
    }

    #[test]
    fn test_root_equivalence_violation() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(check_root_equivalence(&a, &b).is_err());
    }

    #[test]
    fn test_state_compat_ok() {
        let activations = crate::protocol::version::default_activations();
        assert!(check_state_compat(100, 1, &activations).is_ok());
    }
}
