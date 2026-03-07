# Iona Architecture

## Overview

Iona is a blockchain protocol under active development, designed around deterministic execution, validator reliability, upgrade safety, and structured operational testing.

The architecture is currently oriented toward four practical goals:

- deterministic and reproducible protocol execution
- safe validator-driven network operation
- controlled protocol evolution through upgrade validation
- repeatable testnet deployment and recovery procedures

This document describes the current architectural direction of the project, the main system components, and the validation layers required to move the protocol toward a stable multi-validator testnet phase.

## Design Goals

The system is being developed with the following architectural goals:

- **Deterministic execution**  
  The same input must produce the same resulting state across nodes and environments.

- **Operational reliability**  
  Nodes must start, connect, recover, and continue execution safely under normal operational conditions.

- **Upgrade safety**  
  Protocol evolution must be validated explicitly through version transition, rollback, and schema migration testing.

- **Structured validation**  
  The protocol should be testable through reproducible workflows, state comparison, and documented acceptance checks.

- **Deployment discipline**  
  The network should be deployable in controlled stages using consistent binaries, genesis files, and node configuration patterns.

## High-Level System Model

At a high level, Iona consists of the following layers:

1. **Protocol Core**  
   Core state transition logic, block processing, validator logic, and execution rules.

2. **Execution Layer**  
   EVM-oriented transaction execution and associated environment/state handling.

3. **Node Runtime**  
   Networking, validator participation, storage coordination, RPC serving, and operational lifecycle.

4. **Persistence Layer**  
   Chain data storage, receipts/logs persistence, state snapshots, and recovery support.

5. **Validation & Safety Layer**  
   Deterministic replay, state root reproducibility checks, upgrade simulation, rollback validation, and schema migration safety.

6. **Operational Tooling**  
   Testnet planning, deployment flow, node role separation, and observability-oriented documentation.

## Architectural Principles

The current architecture follows these principles:

- one canonical chain state per node
- explicit separation between runtime behavior and validation workflows
- deterministic state comparison as a first-class validation tool
- minimal operational assumptions during early testnet phases
- documentation-driven deployment and upgrade discipline

## Core Components

## 1. Protocol Core

The protocol core is responsible for:

- block/state progression
- validator-driven chain advancement
- transaction inclusion and processing
- canonical state updates
- state root consistency across execution environments

This layer defines the rules that all validator nodes are expected to follow.

### Responsibilities
- maintain canonical protocol state
- validate and apply transactions
- produce deterministic outputs
- maintain consistent block/state transitions

## 2. Execution Layer

The execution layer is responsible for transaction execution and state mutation under the configured protocol environment.

Current design direction includes:

- transaction decoding
- execution environment construction
- state application through a memory-backed or persistence-backed database
- result generation for receipts, logs, and block inclusion

### Responsibilities
- decode supported transaction types
- execute transactions deterministically
- return execution results, logs, gas usage, and status
- integrate with state and receipt generation

## 3. RPC Layer

The RPC layer exposes protocol and execution state to clients and operational tooling.

Its current role is to provide a practical interface for:

- chain inspection
- transaction submission
- balance and state queries
- block and receipt retrieval
- operational checks during testnet deployment

### Responsibilities
- expose a stable query surface for development and testnet use
- support core transaction and block queries
- return chain state in a consistent and inspectable format
- support limited Ethereum-style JSON-RPC compatibility where relevant

### Current Direction
The current RPC work is focused on stabilization rather than full feature completeness.  
The priority is to support the methods required for controlled testing, execution validation, and operational visibility.

## 4. Networking Layer

The networking layer is responsible for:

- peer connectivity
- validator communication
- node discovery/bootstrap flow
- resilience under disconnects or partial partitioning
- peer quality management

### Responsibilities
- establish and maintain peer connections
- support validator communication across nodes
- isolate unstable or low-quality peers when necessary
- provide a foundation for testnet-scale network behavior

### Current Direction
Networking maturity is currently tied to:

- validator peer scoring
- partition simulation
- connectivity stability
- bootstrap/seed node planning

These areas are especially important for multi-validator testnet readiness.

## 5. Validator Runtime

Validator nodes are the core execution participants in the network.

A validator node is expected to:

- join the network using a consistent genesis and build
- maintain canonical state
- participate in chain progression
- recover safely after restart
- remain consistent with other validators

### Responsibilities
- run the active protocol implementation
- maintain local chain state and persistence
- participate in block lifecycle
- recover and resynchronize after restarts or temporary faults

## 6. Persistence Layer

The persistence layer provides the storage foundation for:

- chain data
- block and receipt persistence
- logs and indexed query support
- snapshots or stored state required for validation workflows
- restart and recovery operations

### Responsibilities
- persist chain state safely
- store receipts and logs consistently
- support reload after restart
- support validation-oriented data comparison where needed

### Current Direction
The persistence layer is also tied to:

- storage corruption detection
- recovery flows
- schema migration safety
- upgrade-oriented data validation

## 7. Validation & Safety Layer

This is one of the most important architectural areas for Iona.

The validation layer exists to ensure that protocol behavior remains safe, reproducible, and testable as the codebase evolves.

It includes work related to:

- deterministic build verification
- state root reproducibility across environments
- structured logging for diagnosis and reproducibility
- upgrade simulation and rollback validation
- schema migration validation
- fuzz coverage and failure discovery

### Responsibilities
- detect nondeterministic behavior
- compare state progression across runs or environments
- validate upgrade behavior before deployment
- identify divergence points and failure conditions
- improve confidence before larger testnet rollout

## Execution Flow

A simplified execution flow is:

1. a node starts from configured genesis and local persisted state
2. the networking layer establishes peer connectivity
3. transactions enter the system through RPC or peer propagation
4. transactions are decoded and prepared for execution
5. the protocol core applies state transitions
6. execution results produce updated state, receipts, and logs
7. updated chain data is persisted
8. RPC and observer components expose current chain state

This flow must remain deterministic and stable across validator nodes.

## Storage and State Model

The storage model is currently centered around:

- canonical chain state
- block metadata
- transaction records
- receipts and logs
- validator-relevant runtime state
- persisted data required for restart and recovery

Architecturally, the important requirement is not only persistence, but **safe persistence**:

- no silent corruption
- no partial migration ambiguity
- no unsafe rollback behavior
- no divergence introduced by storage-layer inconsistencies

## Upgrade Architecture

Protocol upgrades are treated as a dedicated architectural concern.

Upgrades are not considered safe merely because code compiles or starts successfully.  
They must be validated through explicit simulation and comparison workflows.

### Upgrade validation requirements
- version transition testing
- backward compatibility checks
- rollback safety validation
- schema migration verification
- deterministic post-upgrade state comparison

### Architectural goal
Upgrades should be testable as controlled transitions from one supported protocol version to another, with clear success/failure criteria and explicit divergence detection.

See [`docs/upgrade.md`](upgrade.md) for the formal upgrade safety process.

## Testnet Architecture

The current testnet direction is intentionally controlled and staged.

### Initial topology
- 4 validator nodes
- 1 RPC / observer / seed node

### Architectural purpose of the initial testnet
- validate multi-node operation
- confirm peer connectivity
- validate block production and state progression
- test restart and recovery
- verify sync behavior for joining nodes
- prepare for larger-scale staged rollout

### Testnet assumptions
- all nodes run the same release candidate build
- all nodes use the same genesis file
- configuration is standardized
- deployment steps are documented and reproducible

See [`docs/testnet-plan.md`](testnet-plan.md) for the deployment and validation plan.

## Operational Separation of Roles

The architecture distinguishes between node roles even in an early testnet phase.

### Validator nodes
Responsible for:
- chain participation
- state progression
- consensus-related behavior
- validator lifecycle stability

### RPC / observer node
Responsible for:
- query access
- network observation
- chain health inspection
- sync/bootstrap support where appropriate

This separation improves test visibility and reduces operational ambiguity during deployment and recovery testing.

## Repository Architecture Areas

The repository currently reflects several architectural workstreams:

### Build & Determinism
- deterministic build verification
- state root reproducibility across environments

### Networking & Validator Reliability
- validator peer scoring and isolation
- network partition simulation

### Reliability & Recovery
- storage corruption detection and recovery
- structured logging framework

### Security & Isolation
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

The most important priorities right now are:

1. stabilize the build across RPC, storage, and protocol-support modules
2. improve deterministic validation of state progression
3. implement upgrade safety workflows
4. strengthen networking and validator reliability
5. prepare a controlled, repeatable testnet rollout

## What This Architecture Is Optimized For

At the current stage, the architecture is optimized for:

- correctness over premature complexity
- validation over feature breadth
- operational clarity over hidden automation
- reproducibility over ad hoc deployment
- safety-oriented protocol evolution

## What Is Not Yet the Primary Goal

At this phase, the architecture is **not** primarily optimized for:

- full production-scale network deployment
- maximum RPC surface completeness
- broad ecosystem integration
- aggressive feature expansion before validation layers are in place

The current emphasis is on building a stable base for safe protocol iteration and structured network testing.

## Success Criteria for the Current Phase

The current architectural phase is considered successful when:

- the project builds cleanly and reproducibly
- validator nodes can run consistently in a controlled testnet
- chain execution remains deterministic across environments
- upgrade paths can be simulated safely
- rollback and schema migration behavior are validated
- recovery and sync behavior are documented and repeatable

## Related Documentation

- [`README.md`](../README.md) — repository overview and current priorities
- [`docs/upgrade.md`](upgrade.md) — protocol upgrade safety process
- [`docs/testnet-plan.md`](testnet-plan.md) — initial testnet deployment plan
- [`docs/issue-map.md`](issue-map.md) — issue grouping by engineering area
- [`docs/TESTNET.md`](TESTNET.md) — operational testnet notes

## Status

This architecture should be considered **active and evolving**.

Some components are already scaffolded or partially implemented, while others are still being stabilized or expanded.  
The immediate goal is not architectural sprawl, but disciplined convergence toward:

- reproducible execution
- reliable validator operation
- safe upgrade workflows
- controlled testnet deployment
