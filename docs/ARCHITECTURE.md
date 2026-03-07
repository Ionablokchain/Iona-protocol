# Iona Architecture

## Overview

Iona is a blockchain protocol under active development, designed around deterministic execution, validator reliability, upgrade safety, and controlled testnet deployment.

The architecture is currently optimized for:

- deterministic and reproducible state transitions
- safe validator-based network operation
- explicit upgrade validation before deployment
- structured storage, recovery, and operational testing
- staged testnet rollout with clear acceptance criteria

This document describes the current architectural direction of the protocol, the main system layers, and the validation model used to improve protocol safety and testnet readiness.

## Architectural Goals

The current architecture is designed to support the following goals:

### Deterministic Execution
The same input must produce the same resulting state across nodes and environments.

### Validator Reliability
Validator nodes must start cleanly, maintain connectivity, process state transitions consistently, and recover safely after restart.

### Upgrade Safety
Protocol evolution must be tested explicitly through version transition validation, rollback checks, and schema migration safety.

### Reproducible Validation
Core protocol behavior must be testable through deterministic replay, state comparison, and structured testnet checks.

### Deployment Discipline
Multi-node deployment must be consistent, documented, and repeatable across validator infrastructure.

## High-Level Architecture

At a high level, Iona is composed of the following layers:

1. **Protocol Core**
2. **Execution Layer**
3. **Node Runtime**
4. **Networking Layer**
5. **Persistence Layer**
6. **RPC Layer**
7. **Validation & Safety Layer**
8. **Operational Tooling**

Each layer contributes to protocol correctness, network stability, and readiness for structured testnet deployment.

## 1. Protocol Core

The protocol core defines the canonical state transition behavior of the system.

It is responsible for:

- block and state progression
- validator-driven chain advancement
- transaction inclusion rules
- execution ordering
- resulting state consistency

### Responsibilities
- apply canonical protocol rules
- define valid state transitions
- maintain consistent block progression
- ensure deterministic post-execution state

### Architectural Requirement
The protocol core must behave identically across validator nodes given the same input history and configuration.

## 2. Execution Layer

The execution layer handles transaction execution and state mutation.

This includes:

- transaction decoding
- execution environment setup
- transaction application
- gas accounting
- receipt and log generation
- execution result formatting

### Responsibilities
- decode supported transaction types
- construct the execution environment
- mutate state through execution
- produce receipts, logs, and execution outcomes

### Architectural Requirement
Execution must remain deterministic and reproducible across environments.

## 3. Node Runtime

The node runtime coordinates the active behavior of a running Iona node.

This layer is responsible for:

- startup and shutdown behavior
- loading configuration and chain state
- coordinating network participation
- exposing RPC interfaces
- managing persistence interactions
- supporting restart and recovery flows

### Responsibilities
- initialize node services
- maintain local chain state
- coordinate execution and persistence
- support validator or observer node roles

### Architectural Requirement
Nodes must restart safely and return to a valid operational state without introducing corruption or divergence.

## 4. Networking Layer

The networking layer is responsible for peer connectivity and validator communication.

It supports:

- node discovery
- peer establishment
- bootstrap and seed node flows
- peer stability and isolation
- resilience to partial network faults

### Responsibilities
- establish and maintain peer connections
- support validator-to-validator communication
- manage peer quality and isolation
- provide the basis for distributed block/state progression

### Current Focus
Networking maturity is currently tied to:

- validator peer scoring
- peer isolation
- partition simulation
- bootstrap stability
- multi-node connectivity under testnet conditions

## 5. Persistence Layer

The persistence layer stores the data required for chain continuity and operational recovery.

This includes:

- block data
- transaction records
- receipts and logs
- chain metadata
- local state required for restart and recovery

### Responsibilities
- persist protocol-relevant data safely
- support reload after node restart
- preserve consistency across runtime restarts
- support migration-aware storage validation

### Architectural Requirement
Persistence must be safe, inspectable, and resilient to corruption or incomplete migration scenarios.

## 6. RPC Layer

The RPC layer provides an external interface for chain inspection, transaction submission, and operational visibility.

Its current purpose is to support:

- chain status inspection
- transaction submission
- state queries
- block and receipt retrieval
- testnet diagnostics

### Responsibilities
- expose chain state to clients and operators
- support testnet-grade query functionality
- provide stable inspection endpoints
- reflect canonical chain state consistently

### Current Direction
The current RPC surface is focused on correctness and stabilization rather than complete feature parity.

## 7. Validation & Safety Layer

This is one of the most important layers in the current architecture.

The validation and safety layer exists to ensure that Iona remains testable, reproducible, and safe to evolve.

It includes work related to:

- deterministic build verification
- state root reproducibility
- protocol upgrade simulation
- rollback validation
- schema migration checks
- structured logging
- fuzz coverage expansion
- storage recovery validation

### Responsibilities
- detect nondeterministic behavior
- validate reproducibility across environments
- verify upgrade safety before deployment
- identify divergence points and failure conditions
- improve confidence before larger-scale rollout

### Architectural Requirement
Validation must be treated as a first-class engineering concern, not an afterthought.

## 8. Operational Tooling

Operational tooling supports deployment, observation, and repeatable test execution.

This includes:

- testnet planning
- node role mapping
- binary/genesis verification workflows
- structured operational documentation
- issue grouping and engineering planning

### Responsibilities
- make deployment repeatable
- make failures easier to diagnose
- support clear validator and observer roles
- provide operational evidence for testnet runs

## Execution Model

A simplified execution flow is:

1. a node starts from configured genesis and local persisted state
2. networking establishes peer connectivity
3. transactions enter through RPC or network propagation
4. transactions are decoded and prepared for execution
5. protocol rules are applied
6. state is updated
7. receipts, logs, and block metadata are generated
8. data is persisted
9. current state is exposed through RPC and observation tooling

This flow must remain deterministic across validator nodes.

## Storage Model

The storage model currently centers on:

- canonical chain state
- block metadata
- transaction records
- receipts and logs
- runtime persistence for restart and recovery
- migration-sensitive persisted structures

The main architectural requirement is not just persistence, but **safe persistence**:

- no silent corruption
- no unsafe partial migration
- no hidden divergence introduced by storage-layer inconsistencies
- no ambiguous rollback state

## Validator Model

The current architecture assumes validator-led network operation.

A validator node is expected to:

- run the selected release candidate build
- load the correct genesis
- maintain canonical state
- participate in block/state progression
- recover safely after restart
- remain consistent with the validator set

### Validator Priorities
- state consistency
- reliable restart behavior
- stable peer participation
- predictable execution behavior

## Observer / RPC Node Model

The architecture also distinguishes a non-validator operational role.

An observer or RPC node is useful for:

- chain visibility
- query access
- sync validation
- monitoring network state
- supporting bootstrap or seed behavior where appropriate

This separation improves testnet clarity and simplifies operational diagnostics.

## Testnet Architecture

The current testnet direction is intentionally staged and controlled.

### Initial Topology
- 4 validator nodes
- 1 RPC / observer / seed node

### Initial Purpose
The first testnet phase is intended to validate:

- peer connectivity
- block production
- deterministic state progression
- node restart and recovery
- sync behavior for joining or restarted nodes
- reproducible deployment flow

### Deployment Rules
- all nodes run the same selected build
- all nodes use the same genesis file
- chain ID is identical across nodes
- configuration is standardized
- deployment steps are documented and repeatable

See [`docs/testnet-plan.md`](testnet-plan.md) for the deployment plan.

## Upgrade Architecture

Protocol upgrades are treated as a dedicated architectural concern.

An upgrade is not considered safe simply because the new code builds or starts.  
It must be validated explicitly.

### Upgrade Validation Areas
- version transition testing
- backward compatibility checks
- rollback validation
- schema migration validation
- deterministic post-upgrade state verification

### Architectural Requirement
Supported upgrade paths must be reproducible, testable, and safe to evaluate before deployment.

See [`docs/upgrade.md`](upgrade.md) for the current upgrade safety process.

## Determinism Requirements

Determinism is a core architectural property.

The protocol should support validation through:

- deterministic build verification
- state root reproducibility across environments
- replay-based validation
- structured execution comparison
- divergence detection and reporting

This is especially important before larger-scale testnet expansion.

## Reliability Requirements

The architecture must also support operational reliability.

This includes:

- startup correctness
- restart safety
- storage recovery behavior
- stable validator participation
- observable runtime behavior through logs and status checks

Reliability work is closely tied to:

- storage corruption detection and recovery
- structured logging
- validator peer scoring and isolation
- network partition simulation

## Current Repository Workstreams

The repository currently maps to several architectural work areas.

### Build & Reproducibility
- deterministic build verification
- state root reproducibility across environments

### Networking & Validator Reliability
- validator peer scoring and isolation
- network partition simulation

### Reliability & Recovery
- storage corruption detection and recovery
- structured logging framework

### Security & Environment Control
- keystore hardening
- environment isolation

### Testing Quality
- fuzz coverage expansion

### Upgrade Safety
- protocol upgrade simulation
- rollback validation
- schema migration safety

See [`docs/issue-map.md`](issue-map.md) for grouped issue tracking.

## Current Architectural Priorities

The current priorities are:

1. stabilize the build across protocol-support modules
2. improve deterministic execution validation
3. strengthen networking and validator reliability
4. validate upgrade and migration safety
5. prepare a clean and repeatable multi-validator testnet rollout

## Scope of the Current Phase

At the current stage, the architecture is optimized for:

- correctness over premature feature expansion
- validation over interface breadth
- reproducibility over ad hoc operation
- safe protocol evolution over rapid unvalidated change
- testnet readiness over production-scale assumptions

## What Is Not Yet the Primary Goal

At this phase, the architecture is not primarily optimized for:

- full production-scale deployment
- maximum RPC completeness
- wide ecosystem integration
- aggressive feature expansion before validation maturity

The current focus is to build a solid and testable foundation.

## Success Criteria for the Current Phase

The current phase is considered successful when:

- the project builds cleanly and reproducibly
- validator nodes can run consistently in a controlled testnet
- state progression remains deterministic across environments
- upgrade paths can be simulated safely
- rollback and schema migration behavior are validated
- restart and sync behavior are documented and repeatable

## Related Documentation

- [`README.md`](../README.md) — repository overview and priorities
- [`docs/testnet-plan.md`](testnet-plan.md) — initial testnet deployment plan
- [`docs/upgrade.md`](upgrade.md) — upgrade safety process
- [`docs/issue-map.md`](issue-map.md) — grouped engineering work
- [`docs/TESTNET.md`](TESTNET.md) — operational testnet guide

## Status

This architecture should be considered active and evolving.

Some layers are already scaffolded or partially implemented, while others are still being stabilized. The immediate architectural objective is disciplined convergence toward:

- reproducible execution
- reliable validator operation
- safe upgrade workflows
- structured validation
- controlled testnet deployment
