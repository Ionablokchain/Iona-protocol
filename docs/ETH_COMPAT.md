# Ethereum compatibility (MEGA v5)

## Execution
- Uses REVM for EVM execution.
- Fork rules set via `SpecId` (currently `LATEST` in scaffold).

## RPC
To be tool-compatible, implement JSON-RPC methods:
- eth_chainId
- eth_blockNumber
- eth_getBalance
- eth_getCode
- eth_getStorageAt
- eth_call
- eth_sendRawTransaction
- eth_getTransactionReceipt
- eth_getLogs

This package adds an OpenAPI placeholder. For production, prefer JSON-RPC over HTTP with strict schema validation and rate limiting.
