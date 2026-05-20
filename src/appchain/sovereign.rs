//! Sovereign appchain configuration.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppchainConfig {
    pub chain_id:      u64,
    pub name:          String,
    pub vm_type:       AppchainVm,
    pub gas_token:     String,
    pub block_time_ms: u64,
    pub max_validators: usize,
    pub genesis_root:  [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppchainVm { Evm, MoveVm, WasmVm, Custom(String) }

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SovereignChainRegistry {
    pub chains: Vec<AppchainConfig>,
}

impl SovereignChainRegistry {
    pub fn register(&mut self, config: AppchainConfig) {
        tracing::info!(chain_id = config.chain_id, name = %config.name, vm = ?config.vm_type, "Appchain registered");
        self.chains.push(config);
    }
    pub fn get(&self, chain_id: u64) -> Option<&AppchainConfig> {
        self.chains.iter().find(|c| c.chain_id == chain_id)
    }
}
