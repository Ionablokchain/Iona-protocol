# IONA Testnet Topology

## Overview

```
                    ┌─────────────────────────────────┐
                    │         IONA BFT Testnet         │
                    └─────────────────────────────────┘

    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │   val2   │◄──►│   val3   │◄──►│   val4   │
    │ Producer │    │ Producer │    │ Producer │
    │ seed=2   │    │ seed=3   │    │ seed=4   │
    │ :30334   │    │ :30335   │    │ :30336   │
    │ rpc:9002 │    │ rpc:9003 │    │ rpc:9004 │
    └────┬─────┘    └────┬─────┘    └────┬─────┘
         │               │               │
         └───────┬───────┴───────┬───────┘
                 │               │
           ┌─────┴────┐   ┌─────┴────┐
           │   val1   │   │   rpc    │
           │ Follower │   │ Public   │
           │ seed=1   │   │ seed=100 │
           │ :30333   │   │ :30337   │
           │ rpc:9001 │   │ rpc:9000 │
           └──────────┘   └──────────┘
                                │
                          ┌─────┴─────┐
                          │  Reverse  │
                          │  Proxy    │
                          │ (nginx)   │
                          └─────┬─────┘
                                │
                          ┌─────┴─────┐
                          │  Public   │
                          │  Users    │
                          └───────────┘
```

## Node Roles

| Node | Seed | Role       | P2P Port | RPC Port | RPC Bind       | Produces Blocks |
|------|------|------------|----------|----------|----------------|-----------------|
| val2 |  2   | Producer   | 30334    | 9002     | 127.0.0.1      | Yes             |
| val3 |  3   | Producer   | 30335    | 9003     | 127.0.0.1      | Yes             |
| val4 |  4   | Producer   | 30336    | 9004     | 127.0.0.1      | Yes             |
| val1 |  1   | Follower   | 30333    | 9001     | 127.0.0.1      | No              |
| rpc  | 100  | RPC/Public | 30337    | 9000     | 0.0.0.0        | No              |

## BFT Quorum

- **Total validators**: 3 (val2, val3, val4)
- **Quorum** (2f+1): 2 out of 3
- **Fault tolerance**: 1 validator can be offline
- **Consensus**: requires at least 2 producers to advance

## Peer Connections

Each node connects to specific peers (never to itself):

| Node | Connects to                        |
|------|------------------------------------|
| val2 | val3, val4, val1                   |
| val3 | val2, val4, val1                   |
| val4 | val2, val3, val1                   |
| val1 | val2, val3, val4 (all producers)   |
| rpc  | val2, val3, val4 (producers only)  |

### Anti-Eclipse Protection

For production deployment:
- Place producers in **different IP ranges** (different providers/subnets)
- Minimum 3 distinct peer IPs required
- The `distinct_peers_min = 3` config enforces this

## Port Allocation

### Production (multi-machine)

| Port  | Protocol | Usage                          |
|-------|----------|--------------------------------|
| 30333 | TCP      | val1 P2P                       |
| 30334 | TCP      | val2 P2P                       |
| 30335 | TCP      | val3 P2P                       |
| 30336 | TCP      | val4 P2P                       |
| 30337 | TCP      | rpc P2P                        |
| 9001  | HTTP     | val1 RPC (local only)          |
| 9002  | HTTP     | val2 RPC (local only)          |
| 9003  | HTTP     | val3 RPC (local only)          |
| 9004  | HTTP     | val4 RPC (local only)          |
| 9000  | HTTP     | rpc RPC (public via proxy)     |

### Local Development (single machine)

| Port  | Protocol | Usage                          |
|-------|----------|--------------------------------|
| 7001  | TCP      | val1 P2P                       |
| 7002  | TCP      | val2 P2P                       |
| 7003  | TCP      | val3 P2P                       |
| 7004  | TCP      | val4 P2P                       |
| 7005  | TCP      | rpc P2P                        |
| 9001  | HTTP     | val1 RPC                       |
| 9002  | HTTP     | val2 RPC                       |
| 9003  | HTTP     | val3 RPC                       |
| 9004  | HTTP     | val4 RPC                       |
| 9000  | HTTP     | rpc RPC                        |

## Firewall Rules (Production)

```bash
# On each validator machine:
# Allow P2P from other validators
ufw allow from <VAL2_IP> to any port 30334 proto tcp
ufw allow from <VAL3_IP> to any port 30335 proto tcp
ufw allow from <VAL4_IP> to any port 30336 proto tcp

# On RPC machine:
# Allow P2P from validators
ufw allow from <VAL2_IP> to any port 30337 proto tcp
ufw allow from <VAL3_IP> to any port 30337 proto tcp
ufw allow from <VAL4_IP> to any port 30337 proto tcp
# Allow HTTP from reverse proxy only
ufw allow from <PROXY_IP> to any port 9000 proto tcp

# Block all other inbound (default deny)
ufw default deny incoming
ufw enable
```

## Directory Structure

```
/var/lib/iona/
├── val1/
│   ├── keys.json        # Node identity (NEVER delete unless --full reset)
│   ├── blocks/           # Block storage
│   ├── wal/              # Write-ahead log
│   ├── snapshots/        # State snapshots
│   ├── state_full.json   # Current state
│   └── config.toml       # (symlink to /etc/iona/val1.toml)
├── val2/
│   └── ...
├── val3/
│   └── ...
├── val4/
│   └── ...
└── rpc/
    └── ...
```

## Startup Order

**Critical**: producers must start before followers.

```
1. val2 (producer)   ─┐
2. val3 (producer)    ├── Wait for quorum (height advancing)
3. val4 (producer)   ─┘
4. val1 (follower)   ─── Syncs from producers
5. rpc  (public)     ─── Syncs from producers
```

Use `deploy/scripts/startup_order.sh` to automate this.

## Shutdown Order

Reverse of startup:

```
1. rpc  (public)     ─── Stop first (drain connections)
2. val1 (follower)   ─── Stop follower
3. val4 (producer)   ─┐
4. val3 (producer)    ├── Stop producers (consensus stops)
5. val2 (producer)   ─┘
```
