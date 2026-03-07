# Testnet Plan

## Purpose
This document defines the deployment plan for the Iona testnet.

The goal is to launch a controlled multi-node environment that validates network stability, block production, node recovery, upgrade readiness, and operational consistency before larger-scale rollout.

## Objectives
The testnet should demonstrate:

- stable multi-validator operation
- correct block production
- peer connectivity across nodes
- deterministic state progression
- restart and recovery safety
- sync correctness for newly joined nodes
- operational readiness for future scaling

## Initial Topology
Planned initial deployment:

- 4 validator nodes
- 1 RPC / observer / seed node

Example roles:
- `val1`
- `val2`
- `val3`
- `val4`
- `rpc1`

This setup is intended as the first controlled testnet stage before expanding toward a larger validator configuration.

## Infrastructure Requirements
Each node should have:

- fixed hostname
- static public IP
- deployed Iona binary from the same commit
- identical genesis file
- node-specific configuration
- systemd service for process management
- open required P2P and RPC ports
- persistent storage for chain data and logs

## Deployment Principles
The testnet must follow these principles:

- all nodes run the same release candidate build
- genesis is generated once and distributed identically
- configuration is standardized across nodes
- only node identity, ports, and peer lists differ per node
- deployment should be reproducible and documented

## Testnet Preparation
Before launch, the following must be completed:

1. freeze the release candidate commit
2. build the binary from the selected commit
3. generate a single genesis file
4. verify genesis hash across all nodes
5. prepare node configuration files
6. configure systemd services
7. verify firewall and network rules
8. define peer and bootnode topology

## Node Roles
### Validator Nodes
Validator nodes are responsible for:

- participating in consensus
- producing and validating blocks
- maintaining canonical chain state
- recovering safely after restart

### RPC / Observer Node
The RPC node is responsible for:

- exposing query endpoints
- serving as an observer for chain health
- supporting sync and connectivity checks
- acting as a stable bootstrap/seed node if needed

## Launch Strategy
The launch should happen in stages:

### Stage 1
Start:
- `rpc1`
- `val1`

Validate:
- process starts correctly
- ports are listening
- logs show expected initialization

### Stage 2
Add:
- `val2`
- `val3`

Validate:
- peer discovery works
- nodes connect correctly
- block production begins or continues normally

### Stage 3
Add:
- `val4`

Validate:
- all validators remain connected
- chain height progresses correctly
- no unexpected divergence or persistent errors appear

## Validation Areas
The testnet must validate the following:

### 1. Genesis Consistency
Checks:
- identical genesis hash on all nodes
- identical chain ID on all nodes
- consistent validator set initialization

### 2. Peer Connectivity
Checks:
- nodes discover and maintain peers
- seed/bootstrap flow works
- reconnect behavior is stable after temporary disconnects

### 3. Block Production
Checks:
- block height increases consistently
- validators remain active
- no repeated block production failures occur

### 4. Restart and Recovery
Checks:
- stopped nodes restart cleanly
- restarted nodes rejoin the network
- no state corruption occurs after restart

### 5. Sync Validation
Checks:
- a clean node can join and sync
- synced state matches network state
- no divergence appears during catch-up

### 6. RPC Validation
Checks:
- status endpoints respond correctly
- block and transaction queries succeed
- observer node reflects current network state

## Acceptance Criteria
The initial testnet stage is considered successful if:

- all nodes start successfully
- genesis is identical across nodes
- peer connectivity is stable
- blocks are produced consistently
- validator restart does not corrupt state
- a joining node can sync correctly
- RPC access works on the observer node
- no state divergence is observed during the test run

## Operational Checks
During testnet execution, monitor:

- node process health
- block height
- peer count
- restart behavior
- sync progress
- logs for repeated errors
- disk and memory usage

## Risks
Key operational risks include:

- inconsistent genesis files
- mismatched binaries between nodes
- incorrect peer configuration
- firewall or port issues
- restart-related corruption
- hidden divergence during sync or upgrade scenarios

## Next Steps
After the initial testnet is validated:

- expand validator count
- improve deployment automation
- add deterministic replay validation
- add upgrade simulation testing
- introduce more structured monitoring and reporting

## Deliverables
This phase should produce:

- a running controlled testnet
- validated multi-node deployment flow
- documented node roles and topology
- test evidence for block production, recovery, and sync
- operational notes for future scaling
