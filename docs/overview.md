# IONA v18 Fullnode — Integrated Features

## Implemented
- Tendermint-style BFT (proposal/prevote/precommit/commit)
- Round advance via timeouts
- Nil votes when missing/invalid proposal
- WAL replay of inbound messages
- Evidence: double-vote detection; gossiped evidence
- Slashing: demo ledger (5%)
- Execution: deterministic KV-state; state_root verification
- libp2p gossipsub + mdns discovery + peer scoring

## Known limitations (by design, for reference simplicity)
- No persistent block store (in-memory only)
- No block request/response (proposal assumes peers already have block)
- No real fee market / mempool prioritization
- No validator set updates / governance
