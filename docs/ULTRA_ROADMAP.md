# ULTRA v2 package notes

This package adds:
- Length-prefixed request/response codec (caps memory usage).
- Aggressive timeouts and connection caps (configurable).
- Peer scoring scaffolding (ban/decay hooks).
- RPC auth scaffolding (API-key middleware template).
- Chaos harness scripts + load test templates.
- Monitoring additions and alert rules templates.

If any API differs due to upstream libp2p/axum minor changes, adjust the indicated
constructor signatures; the structure and intent stays the same.
