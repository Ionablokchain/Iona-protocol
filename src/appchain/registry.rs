//! Appchain registry — tracks all sovereign chains on IONA.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::appchain::sovereign::AppchainConfig;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AppchainRegistry {
    pub chains:     HashMap<u64, AppchainConfig>,
    pub chain_roots: HashMap<u64, [u8; 32]>,  // latest state root per chain
    pub cross_chain_txs: u64,
}

impl AppchainRegistry {
    pub fn register(&mut self, config: AppchainConfig) {
        let id = config.chain_id;
        self.chains.insert(id, config);
        self.chain_roots.insert(id, [0u8; 32]);
    }
    pub fn update_root(&mut self, chain_id: u64, root: [u8; 32]) {
        self.chain_roots.insert(chain_id, root);
    }
    pub fn active_chain_count(&self) -> usize { self.chains.len() }
}
