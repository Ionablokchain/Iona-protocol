use serde::{Deserialize, Serialize};

/// 20-byte Ethereum address.
pub type Address20 = [u8; 20];

/// 32-byte hash.
pub type H256 = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListItem {
    pub address: Address20,
    pub storage_keys: Vec<H256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvmTx {
    Eip2930 {
        from: Address20,
        to: Option<Address20>,
        nonce: u64,
        gas_limit: u64,
        gas_price: u128,
        value: u128,
        data: Vec<u8>,
        access_list: Vec<AccessListItem>,
        chain_id: u64,
    },
    Legacy {
        from: Address20,
        to: Option<Address20>,     // None = contract creation
        nonce: u64,
        gas_limit: u64,
        gas_price: u128,
        value: u128,
        data: Vec<u8>,
        chain_id: u64,
    },
    Eip1559 {
        from: Address20,
        to: Option<Address20>,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        value: u128,
        data: Vec<u8>,
        access_list: Vec<AccessListItem>,
        chain_id: u64,
    },
}
