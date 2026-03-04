# IONA Public Testnet Documentation

**Version:** 28.0.0  
**Launch Date:** 2026-03-01T12:00:00Z  
**Chain Name:** `iona-testnet-1`  
**Chain ID:** `6126151`  
**Genesis SHA-256:** `8e9b9a028f8afeb0d6332096212d77cb59c97738544bed87137b2c8c901b0255`

---

## Network Summary

| Parameter | Value |
|-----------|-------|
| **Chain ID** | `6126151` |
| **Chain Name** | `iona-testnet-1` |
| **Launch Time** | `2026-03-01T12:00:00Z` (Unix: `1772308800`) |
| **Genesis Hash** | `8e9b9a02...901b0255` |
| **Producers** | val2 (seed=2), val3 (seed=3), val4 (seed=4) |
| **Follower** | val1 (seed=1) -- indexer, internal API |
| **RPC** | rpc (seed=100) -- public endpoint, faucet |
| **Bootnodes** | `/ip4/10.0.1.2/tcp/30334/p2p/val2`, `/ip4/10.0.1.3/tcp/30335/p2p/val3` |
| **RPC URL** | `https://rpc.iona-testnet.example.com` (behind nginx proxy) |
| **Faucet** | `https://rpc.iona-testnet.example.com/faucet` (rate-limited) |
| **Explorer** | `https://explorer.iona-testnet.example.com` (val1 backend) |
| **Block Time** | ~100-300ms (sub-second finality) |
| **Gas Target** | 43,000,000 (EIP-1559) |
| **Max TX/block** | 4,096 |

---

## Topology

```
                    Internet
                       |
              [nginx reverse proxy]
              TLS + rate limiting
                       |
                  [rpc node]
                  seed=100, port=30337
                  RPC: 0.0.0.0:9000
                  faucet=true
                       |
         +-------------+-------------+
         |             |             |
    [val2]        [val3]        [val4]
    seed=2        seed=3        seed=4
    BOOTNODE      BOOTNODE      producer
    port=30334    port=30335    port=30336
         |             |             |
         +------+------+------+-----+
                |
           [val1]
           seed=1
           follower/indexer
           port=30333
           RPC: 127.0.0.1:9001
```

**Bootnodes:** val2 and val3 are designated bootnodes.
**All non-bootnode nodes** (val1, val4, rpc) connect through these bootnodes.
**No node bootstraps from itself.**

---

## Quick Start

### 1. Build

```bash
cd iona_v27
cargo build --release --locked --bin iona-node
```

### 2. Local 5-Node Testnet

```bash
./deploy/scripts/run_5nodes_local.sh
```

### 3. Verify

```bash
curl http://127.0.0.1:9000/health
curl http://127.0.0.1:9000/status
curl -s http://127.0.0.1:9000/status | jq '.height'
```

---

## Joining the Public Testnet

### 1. Get Genesis

```bash
curl -O https://rpc.iona-testnet.example.com/genesis.json
sha256sum genesis.json
# Expected: 8e9b9a028f8afeb0d6332096212d77cb59c97738544bed87137b2c8c901b0255
```

### 2. Configure Your Node

```toml
[node]
data_dir  = "/var/lib/iona/my_node"
seed      = 42
chain_id  = 6126151
log_level = "info"
keystore  = "encrypted"

[consensus]
propose_timeout_ms   = 300
prevote_timeout_ms   = 200
precommit_timeout_ms = 200
max_txs_per_block    = 4096
gas_target           = 43000000
fast_quorum          = true
initial_base_fee     = 1
stake_each           = 1000
simple_producer      = false

[network]
listen = "/ip4/0.0.0.0/tcp/30333"
peers  = []
bootnodes = [
  "/ip4/10.0.1.2/tcp/30334/p2p/val2",
  "/ip4/10.0.1.3/tcp/30335/p2p/val3",
]
enable_mdns = false
enable_kad  = true
enable_p2p_state_sync = true

[rpc]
listen        = "127.0.0.1:9001"
enable_faucet = false

[storage]
enable_snapshots = true
snapshot_every_n_blocks = 500
snapshot_keep = 10
```

### 3. Start

```bash
RUST_LOG=info ./target/release/iona-node --config /var/lib/iona/my_node/config.toml
```

---

## Firewall Configuration

### UFW Rules

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 30334/tcp comment "IONA bootnode val2"
sudo ufw allow 30335/tcp comment "IONA bootnode val3"
sudo ufw allow from 10.0.1.0/24 to any port 30333 comment "val1 P2P"
sudo ufw allow from 10.0.1.0/24 to any port 30336 comment "val4 P2P"
sudo ufw allow from 10.0.1.0/24 to any port 30337 comment "rpc P2P"
sudo ufw allow 443/tcp comment "HTTPS nginx"
sudo ufw allow 80/tcp comment "HTTP redirect"
sudo ufw enable
```

---

## RPC Hardening (nginx)

See `deploy/nginx/rpc.conf` for the full configuration.

| Endpoint | Limit | Burst |
|----------|-------|-------|
| `/` (JSON-RPC) | 10 req/s | 20 |
| `/faucet` | 1 req/min | 3 |
| `/health` | 30 req/s | 50 |
| `/metrics` | Blocked from public | Internal only |

---

## Faucet

Enabled only on the RPC node. Protected by nginx rate limiting (1 req/min/IP).

```bash
curl -X POST https://rpc.iona-testnet.example.com/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "0xYOUR_ADDRESS", "amount": 1000}'
```

Rules: max 10,000 tokens/request, max 100,000 tokens/address/day.

---

## Soak Test Procedures

| Phase | Duration | Script |
|-------|----------|--------|
| Stability | 24h | `./deploy/scripts/run_5nodes_local.sh` + `healthcheck.sh --watch` |
| Restart resilience | 24h | `./deploy/scripts/soak_restart.sh --duration 24h --interval 300` |
| Network partition | 4h | `./deploy/scripts/soak_partition.sh --duration 4h` |
| RPC load | 4h | `./deploy/scripts/soak_rpc_load.sh --duration 4h --rps 100` |

### Success Criteria

| Metric | Threshold |
|--------|-----------|
| Uptime | > 99.9% over 72h |
| Block production | Zero gaps > 5s |
| Finality time | p99 < 1s |
| Memory growth | < 10% over 24h |
| Restart recovery | < 10s |
| RPC p99 latency | < 500ms at 100 req/s |

---

## Monitoring

```bash
./deploy/scripts/healthcheck.sh          # one-shot
./deploy/scripts/healthcheck.sh --watch  # continuous
./deploy/scripts/healthcheck.sh --json   # JSON output
```

### Prometheus

```yaml
scrape_configs:
  - job_name: 'iona-testnet'
    scrape_interval: 5s
    static_configs:
      - targets: ['10.0.1.1:9001','10.0.1.2:9002','10.0.1.3:9003','10.0.1.4:9004','10.0.1.5:9000']
        labels:
          chain: 'iona-testnet-1'
          chain_id: '6126151'
```

---

## Testnet Reset

```bash
pkill -f "iona-node" || true
./deploy/scripts/dev_reset.sh
./deploy/scripts/run_5nodes_local.sh
```

---

## Troubleshooting

### Nodes Not Connecting
```bash
for port in 30333 30334 30335 30336 30337; do
  nc -z 10.0.1.1 $port && echo "Port $port: OK" || echo "Port $port: CLOSED"
done
```

### Genesis Mismatch
```bash
sha256sum /var/lib/iona/*/genesis.json
# All must match: 8e9b9a028f8afeb0d6332096212d77cb59c97738544bed87137b2c8c901b0255
```

---

## Scripts Reference

| Script | Description |
|--------|-------------|
| `deploy/scripts/run_5nodes_local.sh` | Launch 5-node local testnet |
| `deploy/scripts/healthcheck.sh` | Node health monitoring |
| `deploy/scripts/atomic_deploy.sh` | Zero-downtime binary upgrade |
| `deploy/scripts/soak_restart.sh` | Soak test: random restarts |
| `deploy/scripts/soak_partition.sh` | Soak test: network partitions |
| `deploy/scripts/soak_rpc_load.sh` | Soak test: RPC load |
