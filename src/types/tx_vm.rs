//! Custom VM transaction types for Iona.
//!
//! This module defines the structures for transactions that target Iona's
//! custom VM (not EVM). The custom VM supports two operations:
//! - `Deploy`: Deploy a new contract with initial code.
//! - `Call`: Call an existing contract with calldata.
//!
//! All types implement `serde` serialization and include methods for
//! validation and inspection.

use serde::{Deserialize, Serialize};

// ------------------------------
// Type aliases
// ------------------------------

/// 32-byte contract address (placeholder – may be derived from init_code or assigned).
pub type ContractAddr = [u8; 32];

// ------------------------------
// VM Transaction Enum
// ------------------------------

/// Represents a transaction targeting Iona's custom VM.
///
/// The custom VM supports:
/// - `Deploy`: Create a new contract by providing its initialization code.
/// - `Call`: Invoke an existing contract with calldata.
///
/// Both variants include a `sender` (account name) and `gas_limit`.
/// Optionally, a `value` field can be added if the VM supports transferring
/// native tokens during deployment or calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum VmTx {
    /// Deploy a new contract.
    #[serde(rename = "deploy")]
    Deploy {
        /// Sender account (human-readable name; in production this would be an address).
        sender: String,
        /// Initialization code for the contract (executed at deployment).
        init_code: Vec<u8>,
        /// Gas limit for the deployment.
        gas_limit: u64,
        /// Amount of native tokens to transfer to the new contract (optional).
        /// If not present, defaults to 0.
        #[serde(default)]
        value: u64,
    },

    /// Call an existing contract.
    #[serde(rename = "call")]
    Call {
        /// Sender account.
        sender: String,
        /// Address of the contract to call.
        contract: ContractAddr,
        /// Calldata (input to the contract function).
        calldata: Vec<u8>,
        /// Gas limit for the call.
        gas_limit: u64,
        /// Amount of native tokens to transfer to the contract (optional).
        #[serde(default)]
        value: u64,
    },
}

impl VmTx {
    /// Returns the sender account name.
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

    /// Returns the value (native tokens) attached to the transaction.
    pub fn value(&self) -> u64 {
        match self {
            VmTx::Deploy { value, .. } => *value,
            VmTx::Call { value, .. } => *value,
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

    /// Basic validity checks.
    ///
    /// - Gas limit must be positive.
    /// - For `Deploy`, init_code must not be empty (optional, but recommended).
    /// - For `Call`, calldata may be empty (valid for read-only calls).
    /// - Sender must not be empty.
    pub fn is_valid(&self) -> bool {
        if self.gas_limit() == 0 {
            return false;
        }
        if self.sender().is_empty() {
            return false;
        }
        match self {
            VmTx::Deploy { init_code, .. } => {
                if init_code.is_empty() {
                    // Deployment with empty init_code is possible? Usually not.
                    // Depending on VM semantics, you might allow it.
                    // We'll keep it optional – comment out if you want to require non-empty.
                    // return false;
                }
            }
            VmTx::Call { calldata, .. } => {
                // calldata can be empty (e.g., for a fallback function).
            }
        }
        true
    }

    /// Returns the type of the transaction as a static string.
    pub fn type_str(&self) -> &'static str {
        match self {
            VmTx::Deploy { .. } => "deploy",
            VmTx::Call { .. } => "call",
        }
    }
}

impl std::fmt::Display for VmTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmTx::Deploy { sender, gas_limit, value, .. } => {
                write!(f, "VmTx(deploy, sender={}, gas={}, value={})", sender, gas_limit, value)
            }
            VmTx::Call { sender, contract, gas_limit, value, .. } => {
                write!(f, "VmTx(call, sender={}, contract={:?}, gas={}, value={})",
                    sender, contract, gas_limit, value)
            }
        }
    }
}

// ------------------------------
// Default implementations (optional)
// ------------------------------

impl Default for VmTx {
    fn default() -> Self {
        VmTx::Deploy {
            sender: String::new(),
            init_code: Vec::new(),
            gas_limit: 0,
            value: 0,
        }
    }
}

// ------------------------------
// Tests
// ------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deploy_creation() {
        let tx = VmTx::Deploy {
            sender: "alice".to_string(),
            init_code: vec![0x00, 0x11, 0x22],
            gas_limit: 100_000,
            value: 0,
        };
        assert_eq!(tx.sender(), "alice");
        assert_eq!(tx.gas_limit(), 100_000);
        assert_eq!(tx.value(), 0);
        assert!(tx.is_deploy());
        assert!(!tx.is_call());
        assert!(tx.is_valid());
    }

    #[test]
    fn test_call_creation() {
        let contract = [0xaa; 32];
        let tx = VmTx::Call {
            sender: "bob".to_string(),
            contract,
            calldata: vec![0xde, 0xad, 0xbe, 0xef],
            gas_limit: 50_000,
            value: 1000,
        };
        assert_eq!(tx.sender(), "bob");
        assert_eq!(tx.gas_limit(), 50_000);
        assert_eq!(tx.value(), 1000);
        assert!(!tx.is_deploy());
        assert!(tx.is_call());
        assert!(tx.is_valid());
    }

    #[test]
    fn test_invalid_gas_limit() {
        let tx = VmTx::Deploy {
            sender: "alice".to_string(),
            init_code: vec![0x00],
            gas_limit: 0,
            value: 0,
        };
        assert!(!tx.is_valid());
    }

    #[test]
    fn test_invalid_sender_empty() {
        let tx = VmTx::Call {
            sender: "".to_string(),
            contract: [0; 32],
            calldata: vec![],
            gas_limit: 100,
            value: 0,
        };
        assert!(!tx.is_valid());
    }

    #[test]
    fn test_serde_roundtrip() {
        let tx = VmTx::Deploy {
            sender: "charlie".to_string(),
            init_code: vec![0x60, 0x80],
            gas_limit: 200_000,
            value: 42,
        };
        let serialized = serde_json::to_string(&tx).unwrap();
        let deserialized: VmTx = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, deserialized);

        // Check that JSON has the expected shape
        assert!(serialized.contains(r#""type":"deploy""#));
    }

    #[test]
    fn test_value_defaults_to_zero() {
        // When value is missing in JSON, it should default to 0.
        let json = r#"{"type":"deploy","data":{"sender":"dave","init_code":[1,2,3],"gas_limit":100}}"#;
        let tx: VmTx = serde_json::from_str(json).unwrap();
        assert_eq!(tx.value(), 0);
    }
}
