# Storage schema & migrations

On-disk data under `data_dir/` may evolve.

## Current files
- `keys.json` (demo only)
- `state.json` / `state_full.json`
- `stakes.json`
- `wal.jsonl`
- `blocks/` (block files + `index.json` + `tx_index.json`)
- `receipts/`

## Strategy
- introduce a `schema_version` file at `data_dir/schema_version`
- migrations run on startup when `schema_version < current`
- migrations must be idempotent and safe to re-run

## TODO
- add snapshot format versioning
- add block store index compaction + validation
