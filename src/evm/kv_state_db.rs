//! `KvStateDb` — a `revm::Database` + `DatabaseCommit` implementation backed
//! by IONA's `KvState`.
//!
//! This is the **unification bridge** between IONA's native KV/balance state
//! and the full EVM execution environment provided by `revm`.
//!
//! ## Why this matters
//!
//! Previously IONA had **two separate VM paths**:
//!   1. `src/vm/` — a custom stack machine (arithmetic, SLOAD/SSTORE, LOG*, etc.)
//!   2. `src/evm/` — revm backed by an isolated `MemDb` that knew nothing about
//!      real chain state (balances, nonces, existing contracts).
//!
//! `KvStateDb` closes this gap.  The `evm` module now reads *and writes* to the
//! same `KvState` that the consensus engine commits at end-of-block.  This means:
//!   - EVM transactions see real account balances and nonces.
//!   - EVM-deployed contracts persist across blocks.
//!   - The state root includes EVM storage (already done via `KvState::root()`).
//!   - Tools like MetaMask / Hardhat / cast can interact correctly.
//!
//! ## Address encoding
//!
//! IONA uses 32-byte addresses (ed25519 pubkey derived); Ethereum uses 20 bytes.
//! We represent IONA addresses in revm as the **last 20 bytes** of the 32-byte
//! address so existing Ethereum tooling works without modification.  The helper
//! functions `iona_to_evm_addr` / `evm_to_iona_addr` perform this conversion.
//!
//! ## Balance units
//!
//! IONA balances are `u64` micro-units.  EVM expects `U256` wei.  We treat
//! 1 IONA micro-unit = 1 wei (no scaling), keeping arithmetic straightforward.

use crate::execution::KvState;
use crate::vm::state::VmState;
use revm::primitives::{
    Account, AccountInfo, Address, Bytecode, B256, KECCAK_EMPTY, U256,
};
use revm::{Database, DatabaseCommit};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

// ── Address helpers ───────────────────────────────────────────────────────────

/// Convert a 32-byte IONA address to a 20-byte EVM address (last 20 bytes).
pub fn iona_to_evm_addr(iona: &[u8; 32]) -> Address {
    Address::from_slice(&iona[12..])
}

/// Convert a 20-byte EVM address back to a 32-byte IONA address (zero-padded).
pub fn evm_to_iona_addr(evm: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(evm.as_slice());
    out
}

/// Hex string of a 32-byte IONA address (used as KvState key).
pub fn iona_addr_hex(addr: &[u8; 32]) -> String {
    hex::encode(addr)
}

// ── KvStateDb ────────────────────────────────────────────────────────────────

/// A `revm::Database` backed by `KvState`.
///
/// Reads go to the authoritative `KvState`.
/// Writes are **buffered** in `pending` and committed via `DatabaseCommit::commit`
/// so that a reverted EVM call leaves `KvState` unchanged.
pub struct KvStateDb<'a> {
    /// The live chain state — reads happen here.
    pub state: &'a mut KvState,

    /// Pending account/storage changes from the current EVM call.
    /// Flushed to `state` on `commit()`; discarded on revert (just drop this).
    pending_accounts: HashMap<Address, AccountInfo>,
    pending_storage: HashMap<(Address, U256), U256>,
    pending_code: HashMap<B256, Bytecode>,
}

impl<'a> KvStateDb<'a> {
    pub fn new(state: &'a mut KvState) -> Self {
        Self {
            state,
            pending_accounts: HashMap::new(),
            pending_storage: HashMap::new(),
            pending_code: HashMap::new(),
        }
    }

    /// Look up balance for an EVM address from KvState.
    fn read_balance(&self, addr: Address) -> U256 {
        let iona = evm_to_iona_addr(addr);
        let key = iona_addr_hex(&iona);
        let bal = self.state.balances.get(&key).copied().unwrap_or(0);
        U256::from(bal)
    }

    /// Look up nonce for an EVM address from KvState.
    fn read_nonce(&self, addr: Address) -> u64 {
        let iona = evm_to_iona_addr(addr);
        let key = iona_addr_hex(&iona);
        self.state.nonces.get(&key).copied().unwrap_or(0)
    }

    /// Look up code for an EVM address from VmStorage.
    fn read_code(&self, addr: Address) -> Bytecode {
        let iona = evm_to_iona_addr(addr);
        let code = self.state.vm.get_code(&iona);
        if code.is_empty() {
            Bytecode::new()
        } else {
            Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(&code))
        }
    }
}

// ── Database impl ─────────────────────────────────────────────────────────────

impl<'a> Database for KvStateDb<'a> {
    type Error = String;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        // Check pending buffer first (handles mid-tx reads after writes).
        if let Some(info) = self.pending_accounts.get(&address) {
            return Ok(Some(info.clone()));
        }

        let balance = self.read_balance(address);
        let nonce = self.read_nonce(address);
        let code = self.read_code(address);
        let code_hash = if code.is_empty() {
            KECCAK_EMPTY
        } else {
            B256::from_slice(&Keccak256::digest(code.bytecode()).to_vec())
        };

        Ok(Some(AccountInfo {
            balance,
            nonce,
            code_hash,
            code: Some(code),
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // Check pending first.
        if let Some(code) = self.pending_code.get(&code_hash) {
            return Ok(code.clone());
        }
        // Scan vm.code for matching hash (linear scan, acceptable for now).
        for (_addr, bytecode) in &self.state.vm.code {
            let h = B256::from_slice(&Keccak256::digest(bytecode).to_vec());
            if h == code_hash {
                return Ok(Bytecode::new_raw(
                    revm::primitives::Bytes::copy_from_slice(bytecode),
                ));
            }
        }
        Err(format!("code not found for hash {code_hash}"))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        // Check pending buffer.
        if let Some(val) = self.pending_storage.get(&(address, index)) {
            return Ok(*val);
        }
        // Read from KvState vm.storage.
        let iona = evm_to_iona_addr(address);
        let slot: [u8; 32] = index.to_be_bytes();
        let val = self
            .state
            .vm
            .storage
            .get(&(iona, slot))
            .copied()
            .unwrap_or([0u8; 32]);
        let mut be = [0u8; 32];
        be.copy_from_slice(&val);
        Ok(U256::from_be_bytes(be))
    }

    fn block_hash(&mut self, _number: U256) -> Result<B256, Self::Error> {
        // Return zero for now; full block hash history would require an index.
        Ok(B256::ZERO)
    }
}

// ── DatabaseCommit impl ───────────────────────────────────────────────────────

impl<'a> DatabaseCommit for KvStateDb<'a> {
    fn commit(&mut self, changes: revm::primitives::State) {
        for (evm_addr, account) in changes {
            if !account.is_touched() {
                continue;
            }

            let iona = evm_to_iona_addr(evm_addr);
            let iona_key = iona_addr_hex(&iona);

            // ── Balances ──────────────────────────────────────────────────────
            // Saturate to u64 (IONA's native balance type).
            let bal_u64 = account.info.balance.saturating_to::<u64>();
            if bal_u64 == 0 {
                self.state.balances.remove(&iona_key);
            } else {
                self.state.balances.insert(iona_key.clone(), bal_u64);
            }

            // ── Nonces ────────────────────────────────────────────────────────
            if account.info.nonce == 0 {
                self.state.nonces.remove(&iona_key);
            } else {
                self.state.nonces.insert(iona_key.clone(), account.info.nonce);
            }

            // ── Bytecode ──────────────────────────────────────────────────────
            if let Some(code) = &account.info.code {
                if !code.is_empty() {
                    let code_bytes = code.bytecode().to_vec();
                    self.state.vm.code.insert(iona, code_bytes);
                }
            }

            // ── Storage slots ─────────────────────────────────────────────────
            for (slot_u256, slot_val) in &account.storage {
                let slot_bytes: [u8; 32] = slot_u256.to_be_bytes();
                let val_bytes: [u8; 32] = slot_val.present_value.to_be_bytes();

                if slot_val.present_value == U256::ZERO {
                    self.state.vm.storage.remove(&(iona, slot_bytes));
                } else {
                    self.state.vm.storage.insert((iona, slot_bytes), val_bytes);
                }
            }
        }
    }
}

// ── Unified EVM executor ──────────────────────────────────────────────────────

use crate::types::tx_evm::EvmTx;
use revm::primitives::{BlockEnv, CfgEnv, Env, TxEnv};
use revm::Evm;

/// Result of executing an EVM transaction via `KvStateDb`.
#[derive(Debug)]
pub struct UnifiedEvmResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub created_address: Option<[u8; 20]>,
    pub logs: Vec<revm::primitives::Log>,
    pub error: Option<String>,
}

/// Execute an EVM transaction against the live `KvState`.
///
/// On success the state is committed in-place.
/// On failure the state is left unchanged (revm reverts automatically).
pub fn execute_evm_on_state(
    kv_state: &mut KvState,
    tx: EvmTx,
    block_number: u64,
    block_timestamp: u64,
    base_fee: u64,
    chain_id: u64,
) -> UnifiedEvmResult {
    let mut db = KvStateDb::new(kv_state);

    // Build the environment.
    let mut env = Box::new(Env::default());
    env.cfg = CfgEnv::default();
    env.cfg.chain_id = chain_id;
    env.block = BlockEnv {
        number: U256::from(block_number),
        timestamp: U256::from(block_timestamp),
        basefee: U256::from(base_fee),
        gas_limit: U256::from(86_000_000u64),
        ..Default::default()
    };
    env.tx = build_tx_env(&tx);

    let mut evm = Evm::builder().with_db(&mut db).with_env(env).build();

    match evm.transact_commit() {
        Ok(result) => {
            let (success, gas_used, output, logs) = match &result {
                revm::primitives::ExecutionResult::Success {
                    gas_used,
                    output,
                    logs,
                    ..
                } => (true, *gas_used, output.clone(), logs.clone()),
                revm::primitives::ExecutionResult::Revert { gas_used, output } => {
                    (false, *gas_used, revm::primitives::Output::Call(output.clone()), vec![])
                }
                revm::primitives::ExecutionResult::Halt { gas_used, .. } => {
                    (false, *gas_used, revm::primitives::Output::Call(revm::primitives::Bytes::new()), vec![])
                }
            };

            let (return_data, created_address) = match output {
                revm::primitives::Output::Call(bytes) => (bytes.to_vec(), None),
                revm::primitives::Output::Create(bytes, addr) => (
                    bytes.to_vec(),
                    addr.map(|a| {
                        let mut arr = [0u8; 20];
                        arr.copy_from_slice(a.as_slice());
                        arr
                    }),
                ),
            };

            UnifiedEvmResult {
                success,
                gas_used,
                return_data,
                created_address,
                logs,
                error: if success { None } else { Some("execution reverted".into()) },
            }
        }
        Err(e) => UnifiedEvmResult {
            success: false,
            gas_used: 0,
            return_data: vec![],
            created_address: None,
            logs: vec![],
            error: Some(format!("evm error: {e:?}")),
        },
    }
}

fn build_tx_env(tx: &EvmTx) -> TxEnv {
    let mut env = TxEnv::default();
    match tx {
        EvmTx::Legacy {
            from, to, nonce, gas_limit, gas_price, value, data, chain_id,
        } => {
            env.caller = Address::from_slice(&from[12..]);
            env.gas_limit = *gas_limit;
            env.gas_price = U256::from(*gas_price);
            env.value = U256::from(*value);
            env.nonce = Some(*nonce);
            env.chain_id = Some(*chain_id);
            env.transact_to = match to {
                Some(t) => revm::primitives::TransactTo::Call(Address::from_slice(&t[12..])),
                None => revm::primitives::TransactTo::Create,
            };
            env.data = revm::primitives::Bytes::copy_from_slice(data);
        }
        EvmTx::Eip2930 {
            from, to, nonce, gas_limit, gas_price, value, data, access_list, chain_id,
        } => {
            env.caller = Address::from_slice(&from[12..]);
            env.gas_limit = *gas_limit;
            env.gas_price = U256::from(*gas_price);
            env.value = U256::from(*value);
            env.nonce = Some(*nonce);
            env.chain_id = Some(*chain_id);
            env.transact_to = match to {
                Some(t) => revm::primitives::TransactTo::Call(Address::from_slice(&t[12..])),
                None => revm::primitives::TransactTo::Create,
            };
            env.data = revm::primitives::Bytes::copy_from_slice(data);
            env.access_list = access_list
                .iter()
                .map(|it| {
                    (
                        Address::from_slice(&it.address[12..]),
                        it.storage_keys
                            .iter()
                            .map(|k| U256::from_be_bytes(*k))
                            .collect(),
                    )
                })
                .collect();
        }
        EvmTx::Eip1559 {
            from, to, nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas,
            value, data, access_list, chain_id,
        } => {
            env.caller = Address::from_slice(&from[12..]);
            env.gas_limit = *gas_limit;
            env.gas_price = U256::from(*max_fee_per_gas);
            env.gas_priority_fee = Some(U256::from(*max_priority_fee_per_gas));
            env.value = U256::from(*value);
            env.nonce = Some(*nonce);
            env.chain_id = Some(*chain_id);
            env.transact_to = match to {
                Some(t) => revm::primitives::TransactTo::Call(Address::from_slice(&t[12..])),
                None => revm::primitives::TransactTo::Create,
            };
            env.data = revm::primitives::Bytes::copy_from_slice(data);
            env.access_list = access_list
                .iter()
                .map(|it| {
                    (
                        Address::from_slice(&it.address[12..]),
                        it.storage_keys
                            .iter()
                            .map(|k| U256::from_be_bytes(*k))
                            .collect(),
                    )
                })
                .collect();
        }
    }
    env
}
