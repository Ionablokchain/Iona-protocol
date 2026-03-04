# IONA Protocol (v28.1)

IONA is a security-first, **deterministic settlement** research protocol focused on:

- Deterministic state transitions and **state root reproducibility**
- Replay-based execution verification (divergence detection)
- Upgrade safety simulation (ProtocolVersion transitions + schema migrations)
- Validator hardening and operational hygiene

> **Status:** Early-stage research prototype (not intended for production deployments).

---

## Key goals

- **Determinism-first execution:** identical results across nodes/environments
- **Replay as a primitive:** verify historical blocks/state roots
- **Upgrade safety before activation:** simulate and validate upgrade paths
- **Security discipline:** no secrets, no runtime data in the repository

---

## Quickstart (local)

```bash
cargo build --release
./scripts/run_3nodes_local.sh

# health check (example)
curl -s http://127.0.0.1:9001/health | jq .
```

## Quickstart (Docker)

```bash
# Prepare node configs under ./data/node{1,2,3}/config.toml (start from config/example.toml)
docker compose up --build
```

---

## Repository layout

- `src/` – core protocol implementation
- `api/` – RPC and external interfaces
- `config/` – configuration templates
- `deploy/` – deployment templates (**no secrets**)
- `docs/` – architecture, security model, research notes
- `tests/` – integration & determinism-related tests
- `fuzz/` – fuzzing targets
- `monitoring/` – ops dashboards and metrics

---

## Documentation

- Architecture: `docs/ARCHITECTURE.md`
- Security model: `docs/SECURITY_MODEL.md` and `docs/threat_model.md`
- Replay / determinism notes: `docs/overview.md`
- Upgrade notes: `docs/migrations.md` and `UPGRADE.md`
- Whitepaper: `docs/WHITEPAPER.md`
- Research objectives: `docs/RESEARCH_OBJECTIVES.md`

---

## Security

See `SECURITY.md`. Please **do not** include private keys, passwords, or runtime chain data in commits.

---

## License

Apache-2.0 (see `LICENSE`)
