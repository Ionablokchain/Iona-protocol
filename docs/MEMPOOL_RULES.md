# Mempool rules (MEGA v7)

Competitive EVM chains need predictable mempool behavior:
- Per-sender nonce ordering
- Replacement rule: same nonce requires higher effective fee
- Eviction: lowest effective tip first under pressure
- Limits: max txs per sender, max total bytes, max per-peer submit rate
- Anti-DoS: reject huge calldata without sufficient fees

This package provides the spec; implement in your tx pool.
