pub mod db;
pub mod executor;
pub mod types;
pub mod executor_env;
/// Unified EVM executor backed by live KvState.
/// This replaces the isolated MemDb with real chain state (balances, nonces, contracts).
pub mod kv_state_db;
