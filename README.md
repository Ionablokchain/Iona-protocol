# Iona Protocol

Iona is a blockchain protocol under active development, focused on deterministic execution, validator reliability, upgrade safety, and structured testnet deployment.

This repository contains the active implementation and supporting documentation for the current Iona development line.

## Overview

The current development phase is centered on protocol hardening and testnet readiness.

The main focus areas are:

- deterministic and reproducible execution
- validator networking and operational reliability
- upgrade safety and schema migration validation
- structured storage and recovery behavior
- controlled multi-node testnet deployment

The immediate goal is to reach a clean, reproducible build and validate core protocol behavior in a controlled validator testnet environment.

## Current Status

The project is currently focused on:

- build and RPC stabilization
- deterministic validation workflows
- protocol upgrade safety
- validator reliability and peer behavior
- recovery and storage safety
- testnet planning and deployment readiness

## Current Priorities

The current engineering priorities are:

1. stabilize the build across protocol-support modules
2. improve deterministic execution validation
3. validate upgrade safety through simulation and migration checks
4. prepare and document controlled multi-validator testnet deployment
5. strengthen operational reliability around restart, recovery, and peer behavior

## Repository Direction

This repository is being prepared to demonstrate:

- protocol engineering maturity
- deterministic execution awareness
- upgrade safety discipline
- structured validation workflows
- testnet deployment readiness

The current phase emphasizes correctness, reproducibility, safety, and operational clarity over premature feature expansion.

## Architecture

At a high level, Iona is organized around the following architectural areas:

- protocol core
- execution layer
- node runtime
- networking layer
- persistence layer
- RPC layer
- validation and safety tooling
- operational documentation and deployment guidance

The architecture is currently optimized for:

- deterministic state progression
- reliable validator operation
- safe protocol evolution
- repeatable deployment procedures
- controlled multi-node testing

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full architecture overview.

## Testnet

The current testnet direction is intentionally controlled and staged.

Initial target topology:

- 4 validator nodes
- 1 RPC / observer / seed node

The first testnet phase is intended to validate:

- peer connectivity
- block production
- restart and recovery safety
- sync correctness
- deployment reproducibility
- operational consistency across nodes

See:

- [`docs/testnet-plan.md`](docs/testnet-plan.md) — initial deployment plan
- [`docs/TESTNET.md`](docs/TESTNET.md) — operational testnet guide

## Upgrade Safety

Protocol upgrades are treated as a high-risk operation and are being approached with explicit validation requirements.

Upgrade-related work is focused on:

- version transition testing
- backward compatibility checks
- rollback validation
- schema migration validation
- deterministic post-upgrade state verification

See [`docs/upgrade.md`](docs/upgrade.md) for the current upgrade safety process.

## Roadmap

The current roadmap is focused on protocol stabilization, deterministic validation, upgrade safety, and controlled testnet rollout.

Main roadmap areas include:

- build and reproducibility
- core reliability
- networking and validator stability
- storage and recovery
- RPC and execution stabilization
- upgrade safety
- testnet readiness
- validation and testing
- documentation and operational clarity

See [`docs/roadmap.md`](docs/roadmap.md) for the full roadmap.

## Open Engineering Areas

Current engineering work includes:

- deterministic build verification
- state root reproducibility across environments
- validator peer scoring and isolation
- network partition simulation
- storage corruption detection and recovery
- structured logging framework
- fuzz coverage expansion
- keystore hardening and environment isolation
- protocol upgrade simulation and rollback validation

See [`docs/issue-map.md`](docs/issue-map.md) for grouped issue tracking.

## Project Documentation

Key project documents:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — protocol and system architecture
- [`docs/TESTNET.md`](docs/TESTNET.md) — operational testnet guide
- [`docs/testnet-plan.md`](docs/testnet-plan.md) — initial testnet deployment plan
- [`docs/upgrade.md`](docs/upgrade.md) — protocol upgrade safety process
- [`docs/roadmap.md`](docs/roadmap.md) — project roadmap
- [`docs/issue-map.md`](docs/issue-map.md) — grouped engineering work

## Development Note

This repository is under active development.

Interfaces, internal modules, and validation tooling may continue to evolve as the protocol moves toward a more stable multi-validator testnet phase.

The current emphasis is on:

- correctness
- reproducibility
- safety
- operational discipline
- controlled protocol evolution

## License

Apache-2.0 (see `LICENSE`)
