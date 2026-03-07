# Protocol Upgrade Safety

## Purpose
This document defines the upgrade safety process for Iona protocol changes.

Its purpose is to ensure that protocol upgrades can be executed safely without state divergence, broken compatibility, failed migrations, or unrecoverable rollback scenarios.

## Goals
The upgrade process must validate:

- protocol version transitions
- backward compatibility across supported upgrade paths
- rollback safety after failed upgrades
- schema migration correctness for persisted state
- deterministic post-upgrade execution

## Upgrade Risks
Protocol upgrades may introduce:

- state divergence between nodes
- incompatible state schema changes
- failed startup after migration
- inconsistent execution across versions
- corrupted or partially migrated persisted state

These risks must be detected before testnet or mainnet deployment.

## Upgrade Validation Strategy
Upgrade safety is validated through a dedicated simulation environment.

Each upgrade scenario should:

1. load a pre-upgrade state snapshot
2. start execution under the source protocol version
3. trigger the target protocol version upgrade
4. continue execution after upgrade
5. compare resulting state against expected output
6. verify that no divergence occurred

## Required Validation Areas

### 1. Version Transition Testing
Validate upgrades from one protocol version to another.

Checks should confirm:

- upgrade activation occurs at the correct boundary
- post-upgrade execution continues successfully
- state root remains deterministic
- block/state progression remains valid

### 2. Backward Compatibility Checks
Validate compatibility across supported mixed-version paths.

Checks should confirm:

- new versions can process pre-upgrade state correctly
- old versions fail safely when encountering unsupported upgraded state
- no silent incompatibility exists across supported upgrade boundaries

### 3. Upgrade Rollback Testing
Validate rollback safety for failed upgrade attempts.

Checks should confirm:

- failed upgrades do not leave corrupted state
- rollback restores a usable pre-upgrade state
- rollback does not introduce divergence
- restart after rollback is stable

### 4. Schema Migration Validation
Validate all persisted state migrations.

Checks should confirm:

- old persisted data can be upgraded successfully
- migrated schema is internally consistent
- required fields are preserved correctly
- invalid or partial migrations are detected explicitly

## Simulation Requirements
The upgrade simulation environment should support:

- versioned upgrade scenarios
- pre-upgrade state snapshots
- post-upgrade state comparison
- rollback scenario execution
- schema migration checks
- deterministic replay after upgrade
- failure reporting with divergence points

## Validation Output
Each simulation run should produce:

- source version
- target version
- snapshot identifier
- upgrade result
- rollback result, if applicable
- state root comparison result
- migration validation result
- divergence or failure reason, if any

## Upgrade Acceptance Criteria
An upgrade is considered safe only if:

- the simulated upgrade path succeeds without state divergence
- backward compatibility checks pass for supported upgrade paths
- rollback scenarios are validated successfully
- schema migrations complete successfully
- post-upgrade execution remains deterministic

## Operational Upgrade Flow
Recommended upgrade flow:

1. define upgrade scope and version target
2. prepare migration logic and schema changes
3. prepare pre-upgrade test fixtures and snapshots
4. run upgrade simulation scenarios
5. run rollback validation scenarios
6. verify state consistency and deterministic execution
7. review logs and failure reports
8. approve deployment only after successful validation

## Failure Policy
An upgrade must not be approved if any of the following occurs:

- state divergence
- failed schema migration
- invalid rollback behavior
- inconsistent execution after upgrade
- missing or incomplete validation evidence

## Deliverables
The upgrade safety framework should include:

- upgrade simulation runner
- versioned upgrade scenarios
- rollback validation scenarios
- schema migration validation tests
- deterministic state comparison
- documented upgrade safety procedure

## Status
Planned initial scope:

- local upgrade simulation
- version transition testing
- rollback validation
- schema migration checks
- documentation of upgrade safety process

Future scope:

- multi-node upgrade simulation
- staged testnet upgrade validation
- automated upgrade compatibility matrix
