# Iona Protocol

Iona is a blockchain protocol under active development, focused on deterministic execution, validator reliability, upgrade safety, and structured testnet deployment.

This repository is the active development line for the Iona protocol and contains the current implementation, supporting documentation, and validation work for protocol hardening and testnet readiness.

## Current Status

The project is currently focused on:

- build and RPC stabilization
- protocol upgrade safety
- deterministic validation workflows
- testnet preparation and deployment planning
- validator networking and recovery readiness

The immediate objective is to reach a clean, reproducible build and validate core protocol behavior in a controlled multi-node testnet environment.

## Current Priorities

The current engineering priorities are:

1. stabilize the build across RPC, storage, and protocol-support modules
2. validate protocol upgrade safety through simulation and migration checks
3. improve deterministic execution and reproducibility across environments
4. prepare and document controlled multi-validator testnet deployment
5. strengthen operational reliability around recovery, logging, and peer behavior

## Repository Direction

This repository is being prepared to demonstrate:

- protocol engineering maturity
- deterministic execution awareness
- upgrade safety planning
- structured validation workflows
- testnet deployment readiness

The current phase is centered on making the protocol easier to validate, safer to evolve, and more reproducible under controlled testing conditions.

## Testnet Readiness

The current testnet plan is focused on an initial controlled deployment with:

- validator nodes
- an RPC / observer node
- shared genesis validation
- reproducible deployment flow
- restart, sync, and recovery checks

The goal of the first testnet phase is to validate:

- block production
- peer connectivity
- node restart safety
- sync correctness
- operational consistency across nodes

See [`docs/testnet-plan.md`](docs/testnet-plan.md) for details.

## Upgrade Safety

Protocol upgrades are treated as a high-risk operation and are being approached with explicit validation requirements.

Upgrade-related work is focused on:

- version transition testing
- backward compatibility checks
- rollback validation
- schema migration validation
- deterministic post-upgrade state verification

See [`docs/upgrade.md`](docs/upgrade.md) for the current upgrade safety process.

## Project Documentation

Key project documents:

- [`docs/upgrade.md`](docs/upgrade.md) — protocol upgrade safety process
- [`docs/testnet-plan.md`](docs/testnet-plan.md) — initial testnet deployment plan
- [`docs/issue-map.md`](docs/issue-map.md) — issue grouping by engineering area
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — protocol and system architecture
- [`docs/TESTNET.md`](docs/TESTNET.md) — testnet-related notes and operational details

## Open Engineering Areas

Current open work includes:

- deterministic build verification
- state root reproducibility across environments
- validator peer scoring and isolation
- network partition simulation
- storage corruption detection and recovery
- structured logging improvements
- fuzz coverage expansion
- keystore hardening and environment isolation
- protocol upgrade simulation and rollback validation

See [`docs/issue-map.md`](docs/issue-map.md) for a structured overview.


## Development Note

This repository is under active development.  
Interfaces, internal modules, and validation tooling may continue to evolve as the protocol moves toward a more stable testnet phase.

The current emphasis is on correctness, safety, reproducibility, and deployment discipline rather than premature feature completeness.

## License

Apache-2.0 (see `LICENSE`)
