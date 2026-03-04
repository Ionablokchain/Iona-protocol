# Threat model (high level)

## Assets
- validator signing keys
- chain state (blocks, receipts, WAL)
- node availability
- correctness of consensus / fork choice

## Adversaries
- malicious peers (spam/DoS, invalid messages)
- byzantine validators (double vote, equivocation)
- local attacker with filesystem access

## Main risks
- decode panics / crashes (mitigated by removing unwraps + fuzzing)
- unbounded memory/disk growth (mitigated by caps, pruning/rotation)
- P2P resource exhaustion (mitigated by size limits, timeouts, rate limits)
- key exfiltration (requires encrypted at rest + strict perms)

## Planned controls
- peer scoring/ban + per-peer rate limits
- fuzz targets for all codecs
- schema versioning + migrations for on-disk state
