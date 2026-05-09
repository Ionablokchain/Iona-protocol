//! EVM transaction executor using REVM.
//!
//! Provides `execute_evm_tx` to run an `EvmTx` against a `Database` that
//! implements `revm::Database` and `DatabaseCommit`.

use crate::types::tx_evm::{AccessListItem, EvmTx};
use revm::primitives::{Address, Bytes, Env, ExecutionResult, TxEnv, U256};
use revm::{DatabaseCommit, Evm};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during EVM transaction execution.
#[derive(Debug, Error)]
pub enum EvmExecutorError {
    #[error("REVM execution failed: {0}")]
    Revm(String),

    #[error("invalid address conversion: {0}")]
    InvalidAddress(String),

    #[error("invalid U256 value: {0}")]
    InvalidU256(String),

    #[error("gas limit overflow")]
    GasLimitOverflow,
}

pub type EvmExecutorResult<T> = Result<T, EvmExecutorError>;

// -----------------------------------------------------------------------------
// Output
// -----------------------------------------------------------------------------

/// Output of an EVM transaction execution.
#[derive(Debug)]
pub struct EvmExecOutput {
    pub logs: Vec<revm::primitives::Log>,
    pub created_address: Option<Address>,
    pub gas_used: u64,
    pub success: bool,
    pub return_data: Vec<u8>,
}

// -----------------------------------------------------------------------------
// Helper: convert 20‑byte array to REVM Address
// -----------------------------------------------------------------------------

fn to_addr(bytes: [u8; 20]) -> Address {
    Address::from_slice(&bytes)
}

// -----------------------------------------------------------------------------
// Transaction execution
// -----------------------------------------------------------------------------

/// Execute an EVM transaction against the given database.
///
/// # Arguments
/// * `db` – Mutable reference to a database implementing `Database` + `DatabaseCommit`.
/// * `env` – Execution environment (block context, chain config, etc.).
/// * `tx` – The transaction to execute.
///
/// # Returns
/// `Ok(EvmExecOutput)` on success (including reverts – check `success` field),
/// or `Err(EvmExecutorError)` if the EVM could not process the transaction.
pub fn execute_evm_tx<DB: revm::Database + DatabaseCommit>(
    db: &mut DB,
    env: Env,
    tx: EvmTx,
) -> EvmExecutorResult<EvmExecOutput>
where
    <DB as revm::Database>::Error: core::fmt::Debug,
{
    // Build EVM instance
    let mut evm = Evm::builder()
        .with_db(db)
        .with_env(Box::new(env))
        .build();

    // Build transaction environment
    let tx_env = build_tx_env(tx)?;
    evm.context.evm.env.tx = tx_env;

    // Execute and commit changes
    let result = evm
        .transact_commit()
        .map_err(|e| EvmExecutorError::Revm(format!("{:?}", e)))?;

    // Convert ExecutionResult to EvmExecOutput
    output_from_result(result)
}

// -----------------------------------------------------------------------------
// Helper: build TxEnv from EvmTx
// -----------------------------------------------------------------------------

fn build_tx_env(tx: EvmTx) -> EvmExecutorResult<TxEnv> {
    let mut tx_env = TxEnv::default();

    match tx {
        EvmTx::Eip2930 {
            from,
            to,
            nonce,
            gas_limit,
            gas_price,
            value,
            data,
            access_list,
            chain_id,
        } => {
            tx_env.caller = to_addr(from);
            tx_env.gas_limit = gas_limit;
            tx_env.gas_price = U256::from(gas_price);
            tx_env.value = U256::from(value);
            tx_env.nonce = Some(nonce);
            tx_env.chain_id = Some(chain_id);
            tx_env.transact_to = match to {
                Some(addr) => revm::primitives::TransactTo::Call(to_addr(addr)),
                None => revm::primitives::TransactTo::Create,
            };
            tx_env.data = Bytes::from(data);
            tx_env.access_list = access_list
                .into_iter()
                .map(convert_access_list_item)
                .collect();
        }

        EvmTx::Legacy {
            from,
            to,
            nonce,
            gas_limit,
            gas_price,
            value,
            data,
            chain_id,
        } => {
            tx_env.caller = to_addr(from);
            tx_env.gas_limit = gas_limit;
            tx_env.gas_price = U256::from(gas_price);
            tx_env.value = U256::from(value);
            tx_env.nonce = Some(nonce);
            tx_env.chain_id = Some(chain_id);
            tx_env.transact_to = match to {
                Some(addr) => revm::primitives::TransactTo::Call(to_addr(addr)),
                None => revm::primitives::TransactTo::Create,
            };
            tx_env.data = Bytes::from(data);
        }

        EvmTx::Eip1559 {
            from,
            to,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas: _,
            value,
            data,
            access_list,
            chain_id,
        } => {
            tx_env.caller = to_addr(from);
            tx_env.gas_limit = gas_limit;
            // Some REVM versions expose only `gas_price`; we use `max_fee_per_gas`.
            // For proper EIP‑1559 handling, the fee layer should compute the effective gas price.
            tx_env.gas_price = U256::from(max_fee_per_gas);
            tx_env.value = U256::from(value);
            tx_env.nonce = Some(nonce);
            tx_env.chain_id = Some(chain_id);
            tx_env.transact_to = match to {
                Some(addr) => revm::primitives::TransactTo::Call(to_addr(addr)),
                None => revm::primitives::TransactTo::Create,
            };
            tx_env.data = Bytes::from(data);
            tx_env.access_list = access_list
                .into_iter()
                .map(convert_access_list_item)
                .collect();
        }
    }

    Ok(tx_env)
}

/// Convert an `AccessListItem` into REVM's access list format.
fn convert_access_list_item(
    item: AccessListItem,
) -> (Address, Vec<U256>) {
    (
        to_addr(item.address),
        item.storage_keys.into_iter().map(U256::from_be_bytes).collect(),
    )
}

/// Convert REVM `ExecutionResult` into `EvmExecOutput`.
fn output_from_result(result: ExecutionResult) -> EvmExecutorResult<EvmExecOutput> {
    match result {
        ExecutionResult::Success {
            gas_used,
            logs,
            output,
            ..
        } => {
            let (return_data, created_address) = match output {
                revm::primitives::Output::Call(data) => (data.to_vec(), None),
                revm::primitives::Output::Create(data, addr) => (data.to_vec(), Some(addr)),
            };
            Ok(EvmExecOutput {
                logs,
                created_address,
                gas_used,
                success: true,
                return_data,
            })
        }
        ExecutionResult::Revert { gas_used, output } => Ok(EvmExecOutput {
            logs: vec![],
            created_address: None,
            gas_used,
            success: false,
            return_data: output.to_vec(),
        }),
        ExecutionResult::Halt { gas_used, .. } => Ok(EvmExecOutput {
            logs: vec![],
            created_address: None,
            gas_used,
            success: false,
            return_data: vec![],
        }),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::db::MemDb;
    use revm::primitives::{Address, Env, BlockEnv, CfgEnv};

    fn setup_env(chain_id: u64) -> Env {
        Env {
            cfg: CfgEnv::default(),
            block: BlockEnv {
                number: U256::from(1),
                coinbase: Address::new([0u8; 20]),
                timestamp: U256::from(123456),
                gas_limit: U256::from(30_000_000),
                basefee: U256::from(0),
                difficulty: U256::ZERO,
                prevrandao: None,
            },
            tx: TxEnv::default(),
        }
    }

    #[test]
    fn test_legacy_tx() -> EvmExecutorResult<()> {
        let mut db = MemDb::new();
        let from = [0xAB; 20];
        let to = [0xCD; 20];
        // Fund sender
        db.insert_account(Address::from_slice(&from), 0, U256::from(10_000_000_000_000_000u128));

        let tx = EvmTx::Legacy {
            from,
            to: Some(to),
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 10,
            value: 1_000,
            data: vec![],
            chain_id: 1,
        };

        let env = setup_env(1);
        let output = execute_evm_tx(&mut db, env, tx)?;
        // Simple transfer should succeed
        assert!(output.success);
        assert!(output.gas_used > 0);
        Ok(())
    }

    #[test]
    fn test_revert() -> EvmExecutorResult<()> {
        let mut db = MemDb::new();
        let from = [0xAB; 20];
        // Code that reverts: PUSH1 0x00 PUSH1 0x00 REVERT
        let revert_code = vec![0x60, 0x00, 0x60, 0x00, 0xFD];
        let code_hash = db.insert_code(revm::primitives::Bytecode::new_raw(Bytes::from(revert_code)));
        let contract_addr = Address::new([0xCC; 20]);
        db.accounts.insert(
            contract_addr,
            AccountInfo {
                nonce: 1,
                balance: U256::ZERO,
                code_hash,
                code: None,
            },
        );

        let tx = EvmTx::Legacy {
            from,
            to: Some(to_addr(contract_addr.as_fixed_bytes())),
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 10,
            value: 0,
            data: vec![],
            chain_id: 1,
        };

        let env = setup_env(1);
        let output = execute_evm_tx(&mut db, env, tx)?;
        assert!(!output.success);
        Ok(())
    }
}
