# MEGA v5: Full EVM scaffold (REVM)

This upgrade pivots from a toy VM to a **full EVM-compatible execution layer** using `revm`.

## Why REVM?
- Mature, high-performance Rust EVM
- Used widely in research/clients
- Modular: you can bring your own DB/state backend

## What this package adds
- EVM transaction types (Legacy/EIP-1559)
- REVM execution pipeline (deploy/call) with gas + return data
- State adapter traits to connect your chain's KV/account state to REVM `Database`
- JSON-RPC OpenAPI skeleton for `eth_*` endpoints (minimal)

## What you still need to implement for a production EVM chain
- Account model (nonce, balance, code, storage) + trie / journaled DB
- Block env (coinbase, basefee, timestamp, chain_id)
- Receipt/log indexing + bloom
- Mempool rules and fee market (EIP-1559)
- Precompiles, fork rules selection, chain config
- State sync/indexer/explorer integration

This is the **correct direction** for competing: developers can deploy Solidity contracts and existing tooling works.
