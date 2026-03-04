# IONA v18 Fullnode+ — Added Modules

## Block fetch (request/response)
- libp2p request-response protocol `/iona/block/1.0.0`
- On missing proposal/commit block: node broadcasts BlockRequest to peers
- First response is stored in persistent block store (`data/blocks/*.bin`)

## Persistent block store
- Filesystem store keyed by block header hash
- Used both for proposals and for serving block requests

## WAL (extended)
- Inbound/Outbound bytes for consensus gossip
- Notes and step markers (step markers are available in WAL type; you can easily add writes in node loop)

## Evidence storage + anti-spam
- `evidence.jsonl` stores unique evidence
- Rate limit: 30 evidence/min/peer and 200 evidence/height

## Fee market + prioritized mempool
- Tx includes: from/nonce/max_fee_per_gas/max_priority_fee_per_gas/gas_limit/payload
- Base fee adjusts each block (simplified EIP-1559)
- Priority fee goes to proposer (credited in state balances)
- Mempool orders by tip-per-byte (reference heuristic)
