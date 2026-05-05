//! VM transaction types for the IONA custom VM.
//!
//! This module defines the transaction formats for deploying and calling
//! contracts on the IONA native VM.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Type aliases
// -----------------------------------------------------------------------------

/// 32‑byte contract address (derived from sender + nonce via Blake3).
pub type ContractAddr = [u8; 32];

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when validating a VM transaction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VmTxError {
    #[error("gas limit must be > 0, got {0}")]
    ZeroGasLimit(u64),

    #[error("init code cannot be empty for deployment")]
    EmptyInitCode,

    #[error("sender address cannot be empty")]
    EmptySender,

    #[error("contract address cannot be all zeroes")]
    ZeroContractAddress,
}

pub type VmTxResult<T> = Result<T, VmTxError>;

// -----------------------------------------------------------------------------
// VM transaction enum
// -----------------------------------------------------------------------------

/// VM transaction types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VmTx {
    /// Deploy a new contract.
    Deploy {
        /// Sender address (derived from public key, hex string).
        sender: String,
        /// Initialisation bytecode (constructor).
        init_code: Vec<u8>,
        /// Gas limit for the deployment.
        gas_limit: u64,
    },
    /// Call an existing contract.
    Call {
        /// Sender address.
        sender: String,
        /// Contract address (32 bytes).
        contract: ContractAddr,
        /// Calldata (ABI‑encoded arguments).
        calldata: Vec<u8>,
        /// Gas limit for the call.
        gas_limit: u64,
    },
}

impl VmTx {
    /// Returns the sender address.
    pub fn sender(&self) -> &str {
        match self {
            VmTx::Deploy { sender, .. } => sender,
            VmTx::Call { sender, .. } => sender,
        }
    }

    /// Returns the gas limit.
    pub fn gas_limit(&self) -> u64 {
        match self {
            VmTx::Deploy { gas_limit, .. } => *gas_limit,
            VmTx::Call { gas_limit, .. } => *gas_limit,
        }
    }

    /// Returns `true` if this is a deployment transaction.
    pub fn is_deploy(&self) -> bool {
        matches!(self, VmTx::Deploy { .. })
    }

    /// Returns `true` if this is a call transaction.
    pub fn is_call(&self) -> bool {
        matches!(self, VmTx::Call { .. })
    }

    /// For deploy transactions: returns the init code.
    pub fn init_code(&self) -> Option<&[u8]> {
        match self {
            VmTx::Deploy { init_code, .. } => Some(init_code),
            VmTx::Call { .. } => None,
        }
    }

    /// For call transactions: returns the contract address.
    pub fn contract(&self) -> Option<&ContractAddr> {
        match self {
            VmTx::Call { contract, .. } => Some(contract),
            VmTx::Deploy { .. } => None,
        }
    }

    /// For call transactions: returns the calldata.
    pub fn calldata(&self) -> Option<&[u8]> {
        match self {
            VmTx::Call { calldata, .. } => Some(calldata),
            VmTx::Deploy { .. } => None,
        }
    }

    /// Validate the transaction.
    ///
    /// Checks:
    /// - Gas limit > 0
    /// - Sender not empty
    /// - For deploy: init code not empty
    /// - For call: contract address not all zeroes
    pub fn validate(&self) -> VmTxResult<()> {
        if self.gas_limit() == 0 {
            return Err(VmTxError::ZeroGasLimit(self.gas_limit()));
        }
        if self.sender().is_empty() {
            return Err(VmTxError::EmptySender);
        }
        match self {
            VmTx::Deploy { init_code, .. } => {
                if init_code.is_empty() {
                    return Err(VmTxError::EmptyInitCode);
                }
            }
            VmTx::Call { contract, .. } => {
                if contract.iter().all(|&b| b == 0) {
                    return Err(VmTxError::ZeroContractAddress);
                }
            }
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

    fn valid_deploy() -> VmTx {
        VmTx::Deploy {
            sender: "alice".into(),
            init_code: vec![0x60, 0x00, 0x00],
            gas_limit: 100_000,
        }
    }

    fn valid_call() -> VmTx {
        VmTx::Call {
            sender: "bob".into(),
            contract: [1u8; 32],
            calldata: vec![0x01, 0x02],
            gas_limit: 200_000,
        }
    }

    #[test]
    fn test_validate_ok() {
        assert!(valid_deploy().validate().is_ok());
        assert!(valid_call().validate().is_ok());
    }

    #[test]
    fn test_zero_gas_limit() {
        let mut tx = valid_deploy();
        if let VmTx::Deploy { gas_limit, .. } = &mut tx {
            *gas_limit = 0;
        }
        assert!(matches!(tx.validate(), Err(VmTxError::ZeroGasLimit(0))));
    }

    #[test]
    fn test_empty_sender() {
        let mut tx = valid_deploy();
        if let VmTx::Deploy { sender, .. } = &mut tx {
            sender.clear();
        }
        assert!(matches!(tx.validate(), Err(VmTxError::EmptySender)));
    }

    #[test]
    fn test_empty_init_code() {
        let mut tx = valid_deploy();
        if let VmTx::Deploy { init_code, .. } = &mut tx {
            init_code.clear();
        }
        assert!(matches!(tx.validate(), Err(VmTxError::EmptyInitCode)));
    }

    #[test]
    fn test_zero_contract_address() {
        let mut tx = valid_call();
        if let VmTx::Call { contract, .. } = &mut tx {
            *contract = [0u8; 32];
        }
        assert!(matches!(tx.validate(), Err(VmTxError::ZeroContractAddress)));
    }

    #[test]
    fn test_accessors() {
        let deploy = valid_deploy();
        assert_eq!(deploy.sender(), "alice");
        assert_eq!(deploy.gas_limit(), 100_000);
        assert!(deploy.is_deploy());
        assert!(!deploy.is_call());
        assert_eq!(deploy.init_code(), Some(&[0x60, 0x00, 0x00][..]));
        assert!(deploy.contract().is_none());
        assert!(deploy.calldata().is_none());

        let call = valid_call();
        assert_eq!(call.sender(), "bob");
        assert_eq!(call.gas_limit(), 200_000);
        assert!(call.is_call());
        assert!(!call.is_deploy());
        assert_eq!(call.contract(), Some(&[1u8; 32]));
        assert_eq!(call.calldata(), Some(&[0x01, 0x02][..]));
        assert!(call.init_code().is_none());
    }
}
