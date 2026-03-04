# IONA Testnet Firewall Configuration

**Chain:** iona-testnet-1 (chain_id=6126151)

## Network Topology

| Node | Role | IP | P2P Port | RPC Port | Public? |
|------|------|-----|----------|----------|---------|
| val1 | Follower/Indexer | 10.0.1.1 | 30333 | 9001 (localhost) | No |
| val2 | Producer + Bootnode | 10.0.1.2 | 30334 | 9002 (localhost) | P2P only |
| val3 | Producer + Bootnode | 10.0.1.3 | 30335 | 9003 (localhost) | P2P only |
| val4 | Producer | 10.0.1.4 | 30336 | 9004 (localhost) | No |
| rpc  | RPC + Faucet | 10.0.1.5 | 30337 | 9000 (via nginx) | HTTPS only |

## Port Ranges

### P2P Ports (30333-30337)

- **Bootnodes (val2: 30334, val3: 30335):** Open to the internet for peer discovery
- **Non-bootnodes (val1: 30333, val4: 30336, rpc: 30337):** Open only to internal subnet (10.0.1.0/24)

### RPC Ports (9000-9004)

- **Public RPC (rpc: 9000):** Accessible only via nginx reverse proxy (ports 80/443)
- **Internal RPC (val1-4: 9001-9004):** Bound to localhost, not accessible externally

### Other Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 22 | TCP | SSH (always open) |
| 80 | TCP | HTTP (nginx, redirects to HTTPS) |
| 443 | TCP | HTTPS (nginx reverse proxy) |
| 9090 | TCP | Prometheus (internal only) |

## Setup

### Bootnode machines (val2, val3)

```bash
sudo ./deploy/firewall/setup_ufw.sh --bootnode
```

### RPC machine

```bash
sudo ./deploy/firewall/setup_ufw.sh --rpc
```

### Internal machines (val1, val4)

```bash
sudo ./deploy/firewall/setup_ufw.sh
```

## Verification

```bash
# Check firewall status
sudo ufw status verbose

# Test P2P connectivity
nc -z 10.0.1.2 30334 && echo "val2 bootnode: OK"
nc -z 10.0.1.3 30335 && echo "val3 bootnode: OK"

# Test RPC via nginx
curl -k https://rpc.iona-testnet.example.com/health

# Verify internal ports are NOT accessible externally
# (should fail from outside the subnet)
nc -z 10.0.1.1 30333  # Should fail from outside
nc -z 10.0.1.5 9000   # Should fail (use nginx instead)
```
