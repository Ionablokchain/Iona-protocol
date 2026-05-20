//! simulateValidation — full off-chain simulation before bundle inclusion.
use crate::evm::account_abstraction::UserOperation;
use crate::aa_full::entry_point::simulate_validation;

#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    #[error("AA10: sender not deployed and no initCode")]
    NoInitCode,
    #[error("AA21: didn't pay prefund")]
    InsufficientPrefund,
    #[error("AA24: signature error")]
    SignatureError,
    #[error("AA25: invalid account nonce")]
    InvalidNonce,
    #[error("AA33: reverted in paymaster validation")]
    PaymasterReverted,
}

pub fn simulate_all(op: &UserOperation, chain_id: u64) -> Result<(), SimulationError> {
    op.validate_basic().map_err(|_| SimulationError::InsufficientPrefund)?;
    let val = simulate_validation(op, chain_id);
    if val.sig_failed { return Err(SimulationError::SignatureError); }
    if val.prefund == 0 && op.max_fee_per_gas > 0 { return Err(SimulationError::InsufficientPrefund); }
    Ok(())
}
