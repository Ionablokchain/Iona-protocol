use revm::primitives::{Address, BlockEnv, CfgEnv, Env, TxEnv, U256};

pub fn default_env(chain_id: u64) -> Env {
    let mut env = Env::default();
    env.cfg = CfgEnv::default();
    env.cfg.chain_id = chain_id;

    env.block = BlockEnv::default();
    env.block.number = U256::from(0);
    env.block.coinbase = Address::ZERO;
    env.block.timestamp = U256::from(0);
    env.block.basefee = U256::from(0);
    env.block.gas_limit = U256::from(30_000_000u64);

    env.tx = TxEnv::default();
    env
}
