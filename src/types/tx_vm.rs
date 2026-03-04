use serde::{Deserialize, Serialize};

/// 32-byte contract address (placeholder).
pub type ContractAddr = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VmTx {
    Deploy {
        sender: String,
        init_code: Vec<u8>,
        gas_limit: u64,
    },
    Call {
        sender: String,
        contract: ContractAddr,
        calldata: Vec<u8>,
        gas_limit: u64,
    },
}
