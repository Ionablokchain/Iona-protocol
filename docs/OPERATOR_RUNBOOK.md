# IONA Node Operator Runbook

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Monitoring](#monitoring)
5. [Alerting Rules](#alerting-rules)
6. [Troubleshooting](#troubleshooting)
7. [Backup & Recovery](#backup--recovery)
8. [Upgrades](#upgrades)
9. [Security](#security)
10. [Performance Tuning](#performance-tuning)

---

## Quick Start

```bash
# Build from source
cargo build --release --locked --bin iona-node

# Run with default config
./target/release/iona-node --data-dir ./data --listen 0.0.0.0:7001

# Run with encrypted keystore
export IONA_KEYSTORE_PASSWORD="your-strong-password"
./target/release/iona-node --data-dir ./data --keystore encrypted
```

## Installation

### Prerequisites

- Rust toolchain 1.85.0 (see `rust-toolchain.toml`)
- Linux (recommended), macOS, or Windows
- Minimum 4 GB RAM, 50 GB SSD
- Recommended: 8+ GB RAM, NVMe SSD

### Build

```bash
# Clone and build
git clone <repo-url> && cd iona
cargo build --release --locked --bin iona-node

# Verify build
./target/release/iona-node --version
```

### Directory Structure

```
data/
  schema.json          # Schema version metadata
  node_meta.json       # Protocol version tracking
  state_full.json      # Full node state
  stakes.json          # Stake ledger
  keys.json            # Node keys (plaintext, dev only)
  keys.enc             # Encrypted keystore (production)
  audit.log            # Audit trail (JSON-lines)
  blocks/              # Block storage (one JSON per block)
  receipts/            # Transaction receipts
  wal/                 # Write-ahead log segments
  snapshots/           # State snapshots
  evidence.jsonl       # Slashing evidence
```

## Configuration

### Key Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--data-dir` | `./data` | Data directory path |
| `--listen` | `0.0.0.0:7001` | P2P listen address |
| `--rpc-port` | `8080` | HTTP RPC port |
| `--peers` | none | Static peer addresses |
| `--keystore` | `plain` | Key storage mode (`plain`/`encrypted`) |
| `--log-level` | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `IONA_KEYSTORE_PASSWORD` | Password for encrypted keystore |
| `IONA_DATA_DIR` | Override data directory |
| `IONA_LOG_LEVEL` | Override log level |
| `RUST_LOG` | Rust logging filter |

### Config File (`config.toml`)

```toml
[node]
data_dir = "/var/lib/iona"
log_level = "info"

[network]
listen = "0.0.0.0:7001"
static_peers = ["/ip4/1.2.3.4/tcp/7001"]
max_connections = 50
enable_mdns = false

[consensus]
# Protocol activation schedule (for planned upgrades)
# protocol_activations = { "2" = 2000000 }

[rpc]
port = 8080
bind = "127.0.0.1"

[keystore]
mode = "encrypted"  # "plain" for dev, "encrypted" for production
password_env = "IONA_KEYSTORE_PASSWORD"
```

## Monitoring

### Prometheus Metrics

The node exposes Prometheus metrics at `GET /metrics` on the RPC port.

#### Key Metrics to Monitor

**Consensus & Finality:**
| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|-----------------|
| `finality_latency_ms` | histogram | Time to finality | > 2000ms |
| `finality_height` | gauge | Latest finalized height | stale > 60s |
| `finality_certificates` | counter | Finality certs issued | decreasing rate |
| `blocks_produced` | counter | Blocks produced | 0 for > 30s |
| `consensus_round` | gauge | Current consensus round | stuck > 60s |

**Network:**
| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|-----------------|
| `peers_connected` | gauge | Connected peers | < 2 |
| `p2p_rate_limited` | counter | Rate-limited requests | spike > 100/min |
| `p2p_peers_banned` | counter | Banned peers | spike > 5/hour |
| `p2p_peers_quarantined` | counter | Quarantined peers | spike > 10/hour |

**Mempool:**
| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|-----------------|
| `mempool_size` | gauge | Pending transactions | > 10000 |
| `mempool_bytes` | gauge | Mempool size in bytes | > 100MB |

**Storage & Migrations:**
| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|-----------------|
| `migration_running` | gauge | Active migrations | stuck > 1hr |
| `migration_completed` | counter | Completed migrations | - |
| `migration_errors` | counter | Failed migrations | > 0 |
| `snapshots_created` | counter | Snapshots created | - |

**Protocol:**
| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|-----------------|
| `protocol_version` | gauge | Current protocol version | mismatch across nodes |
| `schema_version` | gauge | Current schema version | mismatch |

### Grafana Dashboard

Recommended panels:

1. **Overview**: Block height, finality height, peer count, mempool size
2. **Consensus**: Finality latency histogram, rounds per block, blocks/min
3. **Network**: Peers connected, rate limiting events, bandwidth
4. **Storage**: Disk usage, migration progress, snapshot count
5. **Alerts**: Active alerts timeline

### Health Check

```bash
# Basic health check
curl http://localhost:8080/health

# Detailed status
curl http://localhost:8080/status

# Prometheus metrics
curl http://localhost:8080/metrics
```

## Alerting Rules

### Critical (Page Immediately)

```yaml
# Node stopped producing blocks
- alert: NodeNotProducing
  expr: rate(blocks_produced[5m]) == 0
  for: 2m
  severity: critical

# Finality stalled
- alert: FinalityStalled
  expr: changes(finality_height[5m]) == 0
  for: 5m
  severity: critical

# No peers
- alert: NoPeers
  expr: peers_connected == 0
  for: 1m
  severity: critical

# Migration error
- alert: MigrationFailed
  expr: increase(migration_errors[5m]) > 0
  severity: critical
```

### Warning

```yaml
# High finality latency
- alert: HighFinalityLatency
  expr: histogram_quantile(0.95, finality_latency_ms) > 2000
  for: 5m
  severity: warning

# Low peer count
- alert: LowPeerCount
  expr: peers_connected < 3
  for: 5m
  severity: warning

# Large mempool
- alert: MempoolBacklog
  expr: mempool_size > 5000
  for: 10m
  severity: warning

# High rate limiting
- alert: HighRateLimiting
  expr: rate(p2p_rate_limited[5m]) > 20
  for: 5m
  severity: warning
```

## Troubleshooting

### Node Won't Start

1. **Check schema version**: `cat data/schema.json`
   - If schema version is newer than binary: upgrade the binary
   - If corrupted: restore from backup

2. **Check disk space**: `df -h`
   - Minimum 10% free space required
   - Clean old snapshots if needed

3. **Check permissions**:
   ```bash
   ls -la data/
   # keys.enc and keys.json should be 0600
   ```

4. **Check keystore password**:
   ```bash
   echo $IONA_KEYSTORE_PASSWORD  # should not be empty if keystore=encrypted
   ```

### Node Falling Behind

1. **Check peer count**: `curl localhost:8080/metrics | grep peers_connected`
   - If 0: check firewall, static peers config
   - If low: add more static peers

2. **Check block production**: `curl localhost:8080/metrics | grep blocks_produced`
   - If 0: check consensus logs for errors

3. **Check finality**: `curl localhost:8080/metrics | grep finality_height`
   - If stalled: check if majority of validators are online

4. **Check for high latency**:
   ```bash
   curl localhost:8080/metrics | grep finality_latency_ms
   ```

### Migration Issues

1. **Check migration status**:
   ```bash
   cat data/schema.json
   # Look at migration_log for last successful step
   ```

2. **Resume interrupted migration**:
   - The node will automatically resume from the last checkpoint
   - Check `schema.json` for the current version

3. **Migration stuck**:
   - Check `migration_running` metric
   - Check logs for errors
   - If background migration: it runs without blocking the node

### Network Issues

1. **Peer connection failures**:
   ```bash
   # Check if port is open
   ss -tlnp | grep 7001
   
   # Check firewall
   sudo ufw status
   ```

2. **Rate limiting**:
   ```bash
   curl localhost:8080/metrics | grep rate_limited
   # High values indicate potential DoS or misconfigured peers
   ```

3. **Peer banning**:
   ```bash
   curl localhost:8080/metrics | grep peers_banned
   # Check quarantine file
   cat data/quarantine.json
   ```

### Audit Trail

Review critical events:
```bash
# Recent events
tail -100 data/audit.log | jq .

# Filter by category
cat data/audit.log | jq 'select(.category == "consensus")'

# Filter by level
cat data/audit.log | jq 'select(.level == "critical")'

# Key operations
cat data/audit.log | jq 'select(.category == "key")'
```

## Backup & Recovery

### Snapshot Export

```bash
# Export current state to snapshot
# The snapshot includes: state, stakes, schema, node metadata
# Format: JSON with zstd compression and blake3 integrity hash
```

### Snapshot Import

```bash
# Stop the node first
# Import snapshot (creates backups of existing files automatically)
# Restart the node
```

### Regular Backups

Recommended backup schedule:
- **State**: Every 1000 blocks or hourly
- **Keys**: Once (store securely offline)
- **Config**: After every change

Files to backup:
```
data/state_full.json    # Node state
data/stakes.json        # Stake ledger
data/keys.enc           # Encrypted keys (CRITICAL)
data/schema.json        # Schema metadata
data/node_meta.json     # Protocol metadata
config.toml             # Node configuration
```

### Disaster Recovery

1. **Stop the node**
2. **Restore from backup**:
   ```bash
   cp backup/state_full.json data/
   cp backup/stakes.json data/
   cp backup/schema.json data/
   cp backup/keys.enc data/
   ```
3. **Verify schema version**: `cat data/schema.json`
4. **Start the node** - it will:
   - Run any needed migrations
   - Sync missing blocks from peers
   - Resume consensus participation

## Upgrades

### Minor Upgrade (Rolling, No Downtime)

1. **Read UPGRADE.md** for the specific version
2. **Build new binary**: `cargo build --release --locked --bin iona-node`
3. **Run checklist**: `./scripts/check.sh`
4. **Stop node gracefully** (SIGTERM)
5. **Replace binary**
6. **Start node** - migrations run automatically
7. **Verify**: Check `/health`, peer count, block height

### Major Upgrade (Protocol Activation)

1. **Read UPGRADE.md** carefully - note activation height
2. **Upgrade binary BEFORE activation height**
3. **The node supports both old and new protocol**
4. **At activation height**: automatic transition
5. **Monitor**: Check `protocol_version` metric
6. **No rollback after activation** without pre-activation snapshot

### Rollback

- **Before activation**: Stop node, downgrade binary, restart
- **After activation**: Restore from pre-activation snapshot only
- **Always keep pre-upgrade snapshots**

## Security

### Key Management

- **Production**: Always use `--keystore encrypted`
- **Password**: Use strong password (32+ chars), store in secrets manager
- **Backup**: Keep offline backup of encrypted keystore
- **HSM/KMS**: For high-value validators, use HSM or cloud KMS
  - Supported: PKCS#11, AWS KMS, Azure Key Vault, GCP Cloud KMS
  - See `config.toml` key_backend section

### Network Security

- **Firewall**: Allow only P2P port (7001) publicly
- **RPC**: Bind to localhost (127.0.0.1) or use reverse proxy
- **TLS**: Use reverse proxy (nginx/caddy) for HTTPS on RPC
- **Rate limiting**: Built-in per-protocol and global rate limits
- **Peer banning**: Automatic for misbehaving peers

### File Permissions

```bash
chmod 600 data/keys.enc data/keys.json
chmod 700 data/
```

### Audit

- Audit trail logs all critical operations to `audit.log`
- Categories: key, consensus, migration, network, admin, startup, shutdown
- Review regularly for suspicious activity
- Forward to SIEM for centralized monitoring

## Performance Tuning

### Hardware Recommendations

| Component | Minimum | Recommended | High Performance |
|-----------|---------|-------------|------------------|
| CPU | 4 cores | 8 cores | 16+ cores |
| RAM | 4 GB | 8 GB | 32+ GB |
| Disk | 50 GB SSD | 200 GB NVMe | 1 TB NVMe |
| Network | 100 Mbps | 1 Gbps | 10 Gbps |

### Tuning Parameters

- **Max connections**: Increase for better network connectivity
- **Gossipsub heartbeat**: 100ms default for fast propagation
- **Mempool size**: Adjust based on transaction volume
- **Parallel execution**: Automatically uses available CPU cores

### Disk I/O

- Use NVMe SSD for best performance
- State writes are atomic (write-to-tmp then rename)
- WAL uses segmented files for efficient append
- Snapshots use zstd compression (3:1 typical ratio)
