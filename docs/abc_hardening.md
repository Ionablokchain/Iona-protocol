# A+B+C hardening (v24.12.0)

This release adds:
- A) Sybil/eclipsing defense via diversity buckets (IP-prefix bucketing) + eclipse detection reseed.
- B) Gossipsub hardening: topic ACL + per-topic inbound caps + publish caps.
- C) State sync security: snapshot attestations can be bound to validator-set hash and epoch nonce.

## Config

See `config.toml` sections:
- `[network.diversity]`
- `[network.gossipsub]`
- `[network.state_sync_security]`

## Notes

- ASN bucketing is scaffold-only (requires external mapping). Use `ip16`/`ip24` for production today.
- Aggregated signatures are scaffolded behind a future `bls` feature flag; currently the attestation carries `N` individual signatures.
