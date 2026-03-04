use revm::primitives::{AccountInfo, Address, Bytecode, B256, U256};
use revm::{Database, DatabaseCommit};
use std::collections::HashMap;

/// Minimal in-memory REVM DB for dev/testing.
/// For production, implement `Database` backed by your chain state (accounts + storage).
#[derive(Default)]
pub struct MemDb {
    pub accounts: HashMap<Address, AccountInfo>,
    pub code: HashMap<B256, Bytecode>,
    pub storage: HashMap<(Address, U256), U256>,
}

impl Database for MemDb {
    type Error = String;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).cloned())
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code.get(&code_hash).cloned().ok_or_else(|| "code not found".to_string())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(*self.storage.get(&(address, index)).unwrap_or(&U256::ZERO))
    }

    fn block_hash(&mut self, _number: U256) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

impl DatabaseCommit for MemDb {
    fn commit(&mut self, changes: revm::primitives::State) {
        // Simplistic commit implementation; REVM provides changes with accounts/storage/code.
        for (addr, acc) in changes {
			// `acc.info` is `AccountInfo` in newer REVM versions and `Option<AccountInfo>`
			// in older ones. We keep compatibility by using a small helper closure.
			#[allow(clippy::needless_option_as_deref)]
			{
				// Newer REVM (AccountInfo)
				//
				// This compiles because `AccountInfo` implements `Clone`.
				// If your REVM version uses `Option<AccountInfo>`, change the dependency
				// to REVM v9 (as in Cargo.toml) or adjust this block accordingly.
				self.accounts.insert(addr, acc.info.clone());
			}
            for (k, v) in acc.storage {
                self.storage.insert((addr, k), v.present_value);
            }
            if let Some(code) = acc.info.code.clone() {
                self.code.insert(code.hash_slow(), code);
            }
        }
    }
}
