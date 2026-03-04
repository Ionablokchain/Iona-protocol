use crate::types::tx_evm::EvmTx;
use revm::primitives::{Address, Bytes, Env, ExecutionResult, TxEnv, U256};
use revm::{Evm, DatabaseCommit};

#[derive(Debug)]
pub struct EvmExecOutput {
    pub logs: Vec<revm::primitives::Log>,
    pub created_address: Option<revm::primitives::Address>,
    pub gas_used: u64,
    pub success: bool,
    pub return_data: Vec<u8>,
}

fn to_addr(a: [u8;20]) -> Address {
    Address::from_slice(&a)
}

pub fn execute_evm_tx<DB: revm::Database + DatabaseCommit>(
    db: &mut DB,
    env: Env,
    tx: EvmTx,
) -> Result<EvmExecOutput, String>
where
    <DB as revm::Database>::Error: core::fmt::Debug,
{
    // REVM v9 expects Env on the heap.
    let mut evm = Evm::builder().with_db(db).with_env(Box::new(env)).build();

    let mut tx_env = TxEnv::default();

    match tx {
        
        EvmTx::Eip2930 { from, to, nonce, gas_limit, gas_price, value, data, access_list, chain_id } => {
            tx_env.caller = to_addr(from);
            tx_env.gas_limit = gas_limit;
            tx_env.gas_price = U256::from(gas_price);
            tx_env.value = U256::from(value);
            tx_env.nonce = Some(nonce);
            tx_env.chain_id = Some(chain_id);
            tx_env.transact_to = match to {
                Some(t) => revm::primitives::TransactTo::Call(to_addr(t)),
                None => revm::primitives::TransactTo::Create,
            };
            tx_env.data = Bytes::from(data);
            tx_env.access_list = access_list
                .into_iter()
                .map(|it| (to_addr(it.address), it.storage_keys.into_iter().map(U256::from_be_bytes).collect()))
                .collect();
        }

        EvmTx::Legacy { from, to, nonce, gas_limit, gas_price, value, data, chain_id } => {
            tx_env.caller = to_addr(from);
            tx_env.gas_limit = gas_limit;
            tx_env.gas_price = U256::from(gas_price);
            tx_env.value = U256::from(value);
            tx_env.nonce = Some(nonce);
            tx_env.chain_id = Some(chain_id);
            tx_env.transact_to = match to {
                Some(t) => revm::primitives::TransactTo::Call(to_addr(t)),
                None => revm::primitives::TransactTo::Create,
            };
            tx_env.data = Bytes::from(data);
        }
        EvmTx::Eip1559 { from, to, nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas, value, data, access_list, chain_id } => {
            tx_env.caller = to_addr(from);
            tx_env.gas_limit = gas_limit;
	        // Some REVM versions expose only `gas_price` on TxEnv. Keep compatibility
	        // by translating EIP-1559 fields into an effective gas price.
	        //
	        // We conservatively use `max_fee_per_gas` here; callers that need more
	        // precise EIP-1559 accounting should implement it at the fee layer.
	        let _ = max_priority_fee_per_gas; // retained for forward-compat
	        tx_env.gas_price = U256::from(max_fee_per_gas);
            tx_env.value = U256::from(value);
            tx_env.nonce = Some(nonce);
            tx_env.chain_id = Some(chain_id);
            tx_env.transact_to = match to {
                Some(t) => revm::primitives::TransactTo::Call(to_addr(t)),
                None => revm::primitives::TransactTo::Create,
            };
            tx_env.data = Bytes::from(data);
            // Access list mapping (optional for full support)
            tx_env.access_list = access_list
                .into_iter()
                .map(|it| (to_addr(it.address), it.storage_keys.into_iter().map(U256::from_be_bytes).collect()))
                .collect();
        }
    }

    evm.context.evm.env.tx = tx_env;

    let res = evm.transact_commit().map_err(|e| format!("{:?}", e))?;
    Ok(match res {
        ExecutionResult::Success { gas_used, logs, output, .. } => EvmExecOutput {
            gas_used,
            success: true,
            logs: logs.clone(),
            created_address: match &output { revm::primitives::Output::Create(_, addr) => *addr, _ => None },
            return_data: match output {
                revm::primitives::Output::Call(out) => out.to_vec(),
                revm::primitives::Output::Create(out, _) => out.to_vec(),
            },
        },
        ExecutionResult::Revert { gas_used, output } => EvmExecOutput {
            logs: vec![],
            created_address: None,
            gas_used,
            success: false,
            return_data: output.to_vec(),
        },
        ExecutionResult::Halt { gas_used, .. } => EvmExecOutput {
            logs: vec![],
            created_address: None,
            gas_used,
            success: false,
            return_data: vec![],
        },
    })
}
