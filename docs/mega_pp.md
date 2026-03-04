# Mega++ roadmap (v24.10.0)

This release starts the "Mega++" initiative:

## 1) Snapshot attestation (real, multi-validator)
- New RR message: `StateReq::Attest(SnapshotAttestRequest)` / `StateResp::Attest(SnapshotAttestResponse)`.
- Nodes that have a snapshot at `height` and matching `state_root_hex` will sign canonical bytes:
  `b"iona:snapshot_attest:v1" || height(le) || state_root(32)`.

Aggregation/threshold collection is implemented as an opt-in node routine (see `network.enable_snapshot_attestation`).

## 2) Delta chains
- New RR message: `StateReq::Index(StateIndexRequest)` / `StateResp::Index(StateIndexResponse)` to exchange:
  - available snapshot heights
  - delta edges (from_height -> to_height)
- State-sync can then compute a delta path `h1 -> h2 -> ... -> hn` and apply sequential deltas.

## 3) SLSA / signed provenance
- GitHub Actions workflow: `.github/workflows/slsa_provenance.yml` (starter template).
  Tune it to your release pipeline and artifact subjects.

