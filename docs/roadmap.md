# Iona Roadmap

## Overview

This roadmap describes the current development direction of the Iona protocol and the major workstreams required to move the project toward a stable, validated, and reproducible multi-validator testnet phase.

The roadmap is intentionally focused on protocol correctness, deterministic behavior, upgrade safety, and operational reliability rather than premature feature breadth.

## Roadmap Principles

The current roadmap is guided by the following principles:

- correctness before expansion
- determinism before scale
- validation before deployment
- documented operational flow before automation-heavy rollout
- upgrade safety before protocol iteration at higher speed

## Current Phase

The project is currently in a protocol hardening and testnet readiness phase.

The main objective of this phase is to achieve:

- clean and reproducible build behavior
- stable validator operation
- deterministic state progression
- documented and repeatable testnet deployment
- explicit upgrade safety validation
- stronger operational confidence before larger-scale rollout

## Roadmap Structure

The roadmap is divided into the following workstreams:

1. Build & Reproducibility
2. Core Reliability
3. Networking & Validator Stability
4. Storage & Recovery
5. RPC & Execution Stabilization
6. Upgrade Safety
7. Testnet Readiness
8. Validation & Testing
9. Documentation & Operational Clarity

---

## 1. Build & Reproducibility

### Goal
Ensure the project builds cleanly and reproducibly across supported environments.

### Why it matters
A non-reproducible or unstable build introduces ambiguity into every later phase, including validator deployment, state validation, and testnet operations.

### Current Focus
- deterministic build verification
- dependency/API compatibility cleanup
- stabilization of protocol-support modules
- reduction of build ambiguity across environments

### Target Outcomes
- clean and repeatable build flow
- consistent binary generation
- reduced version drift across modules
- improved confidence in deployment artifacts

---

## 2. Core Reliability

### Goal
Strengthen the protocol core so that state progression remains safe and consistent under normal operating conditions.

### Why it matters
The protocol core defines canonical behavior. If it is unstable, no higher-level validation work is trustworthy.

### Current Focus
- deterministic state transition behavior
- state root reproducibility across environments
- reduction of divergence risk
- validation of execution consistency

### Target Outcomes
- consistent canonical state across nodes
- predictable block/state progression
- improved confidence in protocol correctness

---

## 3. Networking & Validator Stability

### Goal
Improve the reliability of multi-node communication and validator participation.

### Why it matters
A blockchain protocol is not only a local execution engine. It must behave consistently across nodes under real networking conditions.

### Current Focus
- validator peer scoring and isolation
- network partition simulation
- stable connectivity during testnet operation
- improved validator network behavior

### Target Outcomes
- better peer quality management
- stronger resilience under temporary network instability
- improved validator participation reliability
- fewer connectivity-related operational ambiguities

---

## 4. Storage & Recovery

### Goal
Improve safety around persistence, restart behavior, and recovery workflows.

### Why it matters
Storage failures and unsafe restarts can invalidate testnet results even when execution logic is otherwise correct.

### Current Focus
- storage corruption detection and recovery
- restart safety
- chain data persistence consistency
- safer handling of persisted protocol state

### Target Outcomes
- restart-safe node behavior
- better corruption detection
- more reliable state recovery
- improved persistence confidence before larger rollout

---

## 5. RPC & Execution Stabilization

### Goal
Stabilize execution-facing and inspection-facing interfaces required for development and testnet validation.

### Why it matters
The project needs a reliable RPC and execution surface to support transaction submission, inspection, diagnostics, and controlled testing.

### Current Focus
- RPC stabilization
- transaction decoding cleanup
- execution-path consistency
- receipt/log/block query reliability

### Target Outcomes
- stable query behavior for core methods
- more reliable transaction submission flow
- improved observability during testing
- a practical RPC surface for controlled testnet use

---

## 6. Upgrade Safety

### Goal
Make protocol upgrades explicitly testable before deployment.

### Why it matters
Protocol upgrades are one of the highest-risk lifecycle events in any blockchain system. Upgrade safety must be validated, not assumed.

### Current Focus
- protocol upgrade simulation
- version transition testing
- rollback validation
- schema migration validation
- backward compatibility checks

### Target Outcomes
- reproducible upgrade validation workflow
- safer protocol evolution
- lower upgrade-related divergence risk
- documented upgrade approval criteria

See [`docs/upgrade.md`](upgrade.md) for the current upgrade safety process.

---

## 7. Testnet Readiness

### Goal
Launch and validate a controlled multi-validator testnet.

### Why it matters
A structured testnet is the first realistic environment where the protocol can prove operational consistency beyond local execution.

### Current Focus
- node role definition
- genesis discipline
- binary consistency
- peer connectivity checks
- block production validation
- restart and sync validation
- documented rollout flow

### Initial Target
- 4 validator nodes
- 1 RPC / observer / seed node

### Target Outcomes
- reproducible deployment process
- stable validator network behavior
- operational evidence for chain progression and recovery
- stronger readiness for future scaling

See [`docs/testnet-plan.md`](testnet-plan.md) and [`docs/TESTNET.md`](TESTNET.md) for details.

---

## 8. Validation & Testing

### Goal
Increase confidence in protocol behavior through structured validation workflows.

### Why it matters
Confidence should come from explicit validation, not only from ad hoc manual testing.

### Current Focus
- deterministic build verification
- state root reproducibility
- fuzz coverage expansion
- replay-oriented validation preparation
- divergence detection workflows

### Target Outcomes
- stronger failure discovery
- better determinism validation
- clearer diagnosis of protocol inconsistencies
- safer iteration on core logic

---

## 9. Documentation & Operational Clarity

### Goal
Keep the repository understandable, reviewable, and operationally coherent.

### Why it matters
Clear documentation improves engineering discipline, grant evaluation clarity, and deployment reliability.

### Current Focus
- repository status clarity
- architecture documentation
- testnet process documentation
- issue grouping and roadmap clarity
- upgrade process documentation

### Target Outcomes
- better evaluator readability
- clearer contributor direction
- stronger operational discipline
- improved grant-readiness and repository maturity

---

# Priority Levels

## P0 — Immediate Priorities
These items are directly relevant to protocol stabilization and testnet readiness.

- stabilize the build across core protocol-support modules
- resolve high-impact compatibility issues in RPC, storage, and execution-related modules
- improve deterministic validation of state progression
- complete core documentation needed for repository coherence
- prepare testnet deployment flow and validator role clarity

## P1 — Near-Term Priorities
These items strengthen protocol safety and operational confidence after the base is stabilized.

- implement upgrade simulation environment
- validate rollback and schema migration behavior
- improve structured logging and debugging clarity
- strengthen storage recovery behavior
- improve network fault simulation and validator reliability testing

## P2 — Medium-Term Priorities
These items expand confidence and operational sophistication after the initial testnet phase is stable.

- expand validator count
- improve deployment automation
- improve observability and metrics
- strengthen replay-based validation workflows
- broaden failure-mode testing under more realistic distributed conditions

---

# Milestones

## Milestone 1 — Repository Stabilization
### Objective
Reduce build ambiguity and align major modules with the current dependency and runtime environment.

### Success Criteria
- project builds cleanly or is significantly closer to clean reproducibility
- core documentation is aligned and coherent
- repository structure clearly reflects current priorities

---

## Milestone 2 — Determinism & Safety Baseline
### Objective
Strengthen reproducibility and reduce the risk of hidden divergence.

### Success Criteria
- deterministic validation workflows are improved
- state reproducibility work is active and documented
- upgrade safety direction is defined and documented

---

## Milestone 3 — Controlled Testnet Launch
### Objective
Launch a multi-node testnet with clear operational controls and validation checks.

### Success Criteria
- validator nodes start and connect correctly
- block production is stable
- restart and sync behavior are validated
- observer/RPC visibility is functional
- testnet process is documented and repeatable

---

## Milestone 4 — Upgrade Validation Readiness
### Objective
Support explicit protocol upgrade testing before broader protocol evolution.

### Success Criteria
- upgrade simulation environment exists
- rollback behavior is tested
- schema migration validation is implemented
- upgrade safety workflow is documented and usable

---

## Milestone 5 — Expanded Operational Confidence
### Objective
Move from basic network operation toward stronger resilience, observability, and structured validation.

### Success Criteria
- fault simulation is broader
- recovery workflows are stronger
- logging and visibility are improved
- the protocol is ready for a more serious staged expansion

---

# Current Roadmap Mapping to Open Work

The roadmap currently aligns with the following repository work areas:

## Build & Reproducibility
- deterministic build verification
- state root reproducibility across environments

## Networking & Validator Stability
- validator peer scoring and isolation
- network partition simulation

## Reliability & Recovery
- storage corruption detection and recovery
- structured logging framework

## Security & Environment Control
- keystore hardening and environment isolation

## Testing Quality
- fuzz coverage expansion

## Upgrade Safety
- protocol upgrade simulation
- rollback validation
- schema migration safety

See [`docs/issue-map.md`](issue-map.md) for grouped issue tracking.

---

# What Success Looks Like

The current roadmap phase is considered successful when:

- the repository reflects a coherent engineering direction
- the build process is stable enough to support reproducible deployment
- validator behavior can be validated in a controlled multi-node environment
- deterministic execution concerns are being actively addressed
- upgrade safety is documented and testable
- restart, recovery, and sync behavior are operationally understood

---

# What Is Deliberately Not Prioritized Yet

At this stage, the roadmap is not primarily focused on:

- full production-scale rollout
- maximum feature surface expansion
- broad ecosystem integration before protocol stabilization
- complete RPC parity before core validation maturity
- aggressive scaling before determinism and recovery confidence improve

The goal of the current phase is to build a safe foundation.

---

# Related Documentation

- [`README.md`](../README.md) — repository overview and current priorities
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — architectural direction
- [`docs/TESTNET.md`](TESTNET.md) — operational testnet guide
- [`docs/testnet-plan.md`](testnet-plan.md) — initial testnet deployment plan
- [`docs/upgrade.md`](upgrade.md) — upgrade safety process
- [`docs/issue-map.md`](issue-map.md) — grouped engineering work

---

# Status

This roadmap should be considered active and evolving.

It is intended to guide the current phase of protocol hardening, testnet preparation, and upgrade safety work while keeping the project focused on validation, reproducibility, and operational discipline.
