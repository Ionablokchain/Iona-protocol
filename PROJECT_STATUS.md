# Project Status

## Overview
Iona is currently focused on protocol stabilization, upgrade safety, and testnet readiness.

The immediate objective is to reach a clean and reproducible build, validate upgrade paths safely, and prepare a controlled multi-validator testnet environment.

## Completed
- initial protocol architecture and module structure
- RPC surface scaffolding
- persistence and chain storage foundations
- protocol upgrade safety documentation in `docs/upgrade.md`

## In Progress
- RPC and build stabilization
- upgrade simulation environment
- schema migration validation
- testnet deployment preparation
- validator infrastructure setup

## Current Priorities
1. Stabilize the build across RPC, storage, and upgrade-related modules
2. Implement upgrade simulation for version transitions and rollback safety
3. Validate schema migrations and state consistency
4. Finalize testnet deployment flow for validator nodes
5. Improve deterministic validation for protocol execution

## Next Milestones
- clean `cargo check` / build stabilization
- upgrade simulation environment implemented
- rollback and migration validation tests added
- testnet plan finalized
- multi-validator testnet launched

## Planned Technical Work
- upgrade simulation runner
- deterministic replay validation
- schema migration checks
- rollback safety tests
- testnet deployment automation
- validator health and network validation

## Success Criteria
The current phase is considered successful when:
- the project builds cleanly
- protocol upgrade paths can be simulated safely
- schema migrations are validated
- rollback behavior is tested
- a controlled testnet can be deployed and verified

## Repository Direction
The repository is being prepared to demonstrate:
- protocol engineering maturity
- upgrade safety awareness
- reproducible validation workflows
- readiness for structured testnet deployment
