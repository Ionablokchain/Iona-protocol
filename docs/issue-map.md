# Issue Map

## Overview

This document groups the main engineering issues of the Iona protocol into architectural and operational workstreams.

Its purpose is to make the repository easier to understand, review, and maintain by showing how current issue work maps to protocol priorities such as determinism, validator reliability, upgrade safety, recovery, and testnet readiness.

This document should be treated as a high-level engineering index rather than a strict project board.

## Purpose

The issue map helps clarify:

- which areas of the protocol are currently being hardened
- how open issues relate to architectural priorities
- which workstreams support testnet readiness
- which workstreams improve protocol safety and reproducibility
- how repository activity maps to real engineering goals

## Current Engineering Workstreams

The current repository work is organized into the following categories:

1. Build & Reproducibility
2. Networking & Validator Stability
3. Reliability & Recovery
4. Security & Environment Isolation
5. Validation & Testing Quality
6. Upgrade Safety
7. Testnet Readiness
8. Documentation & Repository Clarity

---

## 1. Build & Reproducibility

### Goal
Ensure the protocol can be built consistently and validated across environments without hidden variation.

### Why it matters
Reproducible builds and reproducible state progression are the foundation for reliable validator deployment, deterministic testing, and trustworthy upgrade validation.

### Related Issues
- **#10 — Deterministic Build Verification**
- **#3 — State Root Reproducibility Across Environments**

### Focus Areas
- deterministic build behavior
- environment consistency
- repeatable binary generation
- state root comparison across systems
- divergence detection

### Expected Outcome
This workstream should reduce ambiguity between local builds, testnet deployment artifacts, and cross-environment execution results.

---

## 2. Networking & Validator Stability

### Goal
Strengthen validator communication and improve network behavior under real multi-node conditions.

### Why it matters
A blockchain node is not useful in isolation. Validator stability depends on healthy peer connectivity, peer quality management, and resilience to network faults.

### Related Issues
- **#4 — Validator Peer Scoring & Isolation**
- **#9 — Network Partition Simulation**

### Focus Areas
- peer quality scoring
- isolation of unstable or malicious peers
- recovery from degraded connectivity
- partition and reconnect behavior
- multi-validator stability under fault scenarios

### Expected Outcome
This workstream should improve network resilience and reduce validator instability caused by peer-level issues.

---

## 3. Reliability & Recovery

### Goal
Improve storage safety, operational visibility, and node recovery behavior.

### Why it matters
Even correct protocol logic can fail operationally if storage is corrupted, recovery is unsafe, or diagnostics are too weak to explain failures.

### Related Issues
- **#6 — Storage Corruption Detection & Recovery**
- **#5 — Structured Logging Framework**

### Focus Areas
- corruption detection
- recovery workflows
- persistence inspection
- restart diagnostics
- structured logging for runtime and failure analysis

### Expected Outcome
This workstream should make node recovery safer and operational failures easier to diagnose and reproduce.

---

## 4. Security & Environment Isolation

### Goal
Reduce operational security risks around key handling and execution environment boundaries.

### Why it matters
Validator security is not only about protocol logic. It also depends on how secrets, keystores, and runtime isolation are handled operationally.

### Related Issues
- **#7 — Keystore Hardening & Environment Isolation**

### Focus Areas
- keystore handling
- secret exposure reduction
- safer environment boundaries
- operational separation of sensitive components

### Expected Outcome
This workstream should improve the security posture of validator and operator workflows.

---

## 5. Validation & Testing Quality

### Goal
Increase confidence in protocol behavior through stronger test coverage and failure discovery.

### Why it matters
Validation quality determines how early bugs, edge cases, and nondeterministic behavior are detected.

### Related Issues
- **#8 — Fuzz Coverage Expansion**

### Focus Areas
- edge-case discovery
- broader execution-path coverage
- failure-oriented testing
- protocol robustness under unexpected input

### Expected Outcome
This workstream should improve bug discovery and reduce the chance that critical edge cases survive into testnet operation.

---

## 6. Upgrade Safety

### Goal
Make protocol upgrades explicitly testable before deployment.

### Why it matters
Protocol upgrades are one of the highest-risk lifecycle events in a blockchain system. Safe upgrades require more than build success; they require controlled validation of transitions, rollback, and state migration behavior.

### Planned Work
- protocol upgrade simulation
- rollback validation
- backward compatibility checks
- schema migration validation
- deterministic post-upgrade state comparison

### Related Documentation
- [`docs/upgrade.md`](upgrade.md)

### Expected Outcome
This workstream should provide a reproducible framework for testing version transitions before testnet or mainnet deployment.

---

## 7. Testnet Readiness

### Goal
Prepare the repository and operational process for a controlled multi-validator testnet.

### Why it matters
A meaningful testnet requires more than node startup. It requires consistent binaries, shared genesis, stable connectivity, recovery validation, and documented acceptance checks.

### Supported By
This workstream depends on progress in:

- build reproducibility
- validator networking stability
- storage and recovery
- logging and operational visibility
- upgrade safety
- deterministic validation

### Related Documentation
- [`docs/testnet-plan.md`](testnet-plan.md)
- [`docs/TESTNET.md`](TESTNET.md)

### Expected Outcome
This workstream should lead to a repeatable and well-documented multi-node testnet deployment.

---

## 8. Documentation & Repository Clarity

### Goal
Keep the repository understandable, professionally structured, and aligned with the current engineering direction.

### Why it matters
Good documentation helps contributors, evaluators, and reviewers understand what the protocol is doing, what is being hardened, and why each issue matters.

### Related Documentation
- [`README.md`](../README.md)
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
- [`docs/roadmap.md`](roadmap.md)
- [`docs/upgrade.md`](upgrade.md)
- [`docs/testnet-plan.md`](testnet-plan.md)
- [`docs/TESTNET.md`](TESTNET.md)

### Focus Areas
- architectural clarity
- roadmap clarity
- operational clarity
- issue grouping and reviewability
- alignment between code direction and repository presentation

### Expected Outcome
This workstream should make the repository easier to review and more credible for grants, collaborators, and technical evaluators.

---

# Cross-Workstream Relationships

Several issue groups support more than one objective.

## Determinism ↔ Testnet Readiness
- deterministic build verification
- state root reproducibility

These are essential for trustworthy validator deployment and state comparison.

## Networking ↔ Reliability
- peer scoring and isolation
- partition simulation
- structured logging

These improve both distributed stability and post-failure diagnosis.

## Storage ↔ Upgrade Safety
- corruption detection and recovery
- schema migration validation
- rollback validation

These are necessary for safe protocol evolution and restart safety.

## Validation ↔ Upgrade Confidence
- fuzz coverage
- deterministic state comparison
- version transition testing

These improve confidence before protocol upgrades are approved.

---

# Current Priority Mapping

## P0 — Immediate Repository Priorities
These are the work areas most directly tied to stabilization and testnet readiness.

- deterministic build verification
- state root reproducibility
- validator peer scoring and isolation
- storage corruption detection and recovery
- structured logging
- core repository documentation alignment

## P1 — Near-Term Priorities
These strengthen protocol safety and validation maturity after base stabilization.

- network partition simulation
- fuzz coverage expansion
- keystore hardening and environment isolation
- protocol upgrade simulation
- rollback validation
- schema migration validation

## P2 — Next Expansion Priorities
These become more important as the initial controlled testnet becomes stable.

- broader replay validation
- larger validator topology testing
- stronger observability and metrics
- staged upgrade testing in live testnet environments

---

# Issue Map and Roadmap Alignment

This issue map aligns directly with the main roadmap areas described in [`docs/roadmap.md`](roadmap.md):

- Build & Reproducibility
- Core Reliability
- Networking & Validator Stability
- Storage & Recovery
- RPC & Execution Stabilization
- Upgrade Safety
- Testnet Readiness
- Validation & Testing
- Documentation & Operational Clarity

The purpose of this alignment is to ensure that repository issue activity reflects a coherent engineering direction rather than disconnected tasks.

---

# Current Open Issues

## Build & Reproducibility
- #10 Deterministic Build Verification
- #3 State Root Reproducibility Across Environments

## Networking & Validator Stability
- #4 Validator Peer Scoring & Isolation
- #9 Network Partition Simulation

## Reliability & Recovery
- #6 Storage Corruption Detection & Recovery
- #5 Structured Logging Framework

## Security & Environment Isolation
- #7 Keystore Hardening & Environment Isolation

## Validation & Testing Quality
- #8 Fuzz Coverage Expansion

## Planned / Emerging Upgrade Safety Work
- Protocol Upgrade Simulation & Rollback Validation
- Backward Compatibility Checks
- Schema Migration Validation

---

# How to Use This Document

This document can be used to:

- understand where an issue belongs architecturally
- identify which issues support testnet readiness
- explain repository direction to reviewers and evaluators
- keep future issue creation aligned with existing workstreams
- avoid duplicated or disconnected engineering tasks

When new issues are added, they should ideally be grouped into one of the workstreams above.

---

# Related Documentation

- [`README.md`](../README.md) — repository overview and priorities
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — architectural direction
- [`docs/roadmap.md`](roadmap.md) — project roadmap
- [`docs/upgrade.md`](upgrade.md) — upgrade safety process
- [`docs/testnet-plan.md`](testnet-plan.md) — initial testnet deployment plan
- [`docs/TESTNET.md`](TESTNET.md) — operational testnet guide

---

# Status

This issue map is active and should evolve with the repository.

As new engineering work is introduced, this document should be updated so that the repository continues to reflect a clear, structured, and reviewable protocol development process.
