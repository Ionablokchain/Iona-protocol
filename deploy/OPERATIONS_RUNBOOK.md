# IONA Operations Runbook

> Version: 27.1.2 | Last updated: 2025-01

## Table of Contents

1. [Quick Reference](#1-quick-reference)
2. [Startup Procedure](#2-startup-procedure)
3. [Verification Commands](#3-verification-commands)
4. [Upgrade Procedure](#4-upgrade-procedure)
5. [Reset Policy](#5-reset-policy)
6. [Troubleshooting](#6-troubleshooting)
7. [Monitoring](#7-monitoring)
8. [Emergency Procedures](#8-emergency-procedures)

---

## 1. Quick Reference

### Node Addresses

| Node | Role     | P2P          | RPC                  |
|------|----------|--------------|----------------------|
| val2 | Producer | :30334       | http://127.0.0.1:9002|
| val3 | Producer | :30335       | http://127.0.0.1:9003|
| val4 | Producer | :30336       | http://127.0.0.1:9004|
| val1 | Follower | :30333       | http://127.0.0.1:9001|
| rpc  | Public   | :30337       | http://0.0.0.0:9000  |

### Service Names

```
iona-val1  iona-val2  iona-val3  iona-val4  iona-rpc
```

### Critical Paths

```
Binary:    /usr/local/bin/iona-node
Configs:   /etc/iona/{val1,val2,val3,val4,rpc}.toml
Data:      /var/lib/iona/{val1,val2,val3,val4,rpc}/
Genesis:   /etc/iona/genesis.json
Keys:      /var/lib/iona/<node>/keys.json
```

---

## 2. Startup Procedure

### 2.1 Full Network Start (from cold)

**Use the automated script:**

```bash
./deploy/scripts/startup_order.sh
```

**Manual procedure** (if script unavailable):

```bash
# Phase 1: Start ALL producers (need 2/3 quorum)
sudo systemctl start iona-val2
sleep 2
sudo systemctl start iona-val3
sleep 2
sudo systemctl start iona-val4

# Phase 2: Wait for consensus (height advancing)
# Check every 5s until height increases:
watch -n5 'curl -s http://127.0.0.1:9002/health | python3 -m json.tool'

# Phase 3: Start follower (after consensus is active)
sudo systemctl start iona-val1

# Phase 4: Start RPC (last)
sudo systemctl start iona-rpc
```

### 2.2 Single Node Restart

```bash
sudo systemctl restart iona-val3
# Wait 10s, then verify:
curl -s http://127.0.0.1:9003/health
```

### 2.3 Why This Order Matters

- Producers must form **quorum** (2 of 3) before blocks can be produced
- If followers start first, they'll timeout waiting for blocks
- RPC depends on synced state from producers

---

## 3. Verification Commands

### The 3 Standard Checks (run after every operation)

```bash
# 1. Peers — each producer should see ≥2 peers
curl -s http://127.0.0.1:9002/health | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'Peers: {d.get(\"peers\",\"?\")}')"

# 2. Consensus height — should be increasing
curl -s http://127.0.0.1:9002/health | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'Height: {d.get(\"height\",\"?\")}')"

# 3. Blocks — count should grow over time
curl -s http://127.0.0.1:9002/health | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'Blocks: {d.get(\"blocks_count\",\"?\")}')"
```

### Full Network Health (all nodes at once)

```bash
./deploy/scripts/healthcheck.sh
```

### JSON output for scripting

```bash
./deploy/scripts/healthcheck.sh --json
```

### Continuous monitoring

```bash
./deploy/scripts/healthcheck.sh --watch --interval 10
```

### Check All Services Status

```bash
for svc in iona-val{1,2,3,4} iona-rpc; do
    echo -n "$svc: "
    systemctl is-active "$svc" 2>/dev/null || echo "not found"
done
```

### Check Logs

```bash
# Recent logs for a specific node
journalctl -u iona-val2 --since "5 minutes ago" --no-pager

# Follow logs in real-time
journalctl -u iona-val2 -f

# Errors only
journalctl -u iona-val2 -p err --since today
```

---

## 4. Upgrade Procedure

### 4.1 Minor Upgrade (rolling, no downtime)

Use the automated script:

```bash
./deploy/scripts/atomic_deploy.sh all /path/to/new/iona-node
```

**Manual procedure:**

```bash
# For each node (order: val2 → val3 → val4 → val1 → rpc):

# 1. Stop the node
sudo systemctl stop iona-val2

# 2. Atomic binary replacement (avoids "Text file busy")
sudo cp /path/to/new/iona-node /usr/local/bin/iona-node.new
sudo mv /usr/local/bin/iona-node.new /usr/local/bin/iona-node

# 3. Verify binary
/usr/local/bin/iona-node --version

# 4. Start the node
sudo systemctl start iona-val2

# 5. Verify health
sleep 5
curl -s http://127.0.0.1:9002/health

# 6. Wait 10s before next node
sleep 10
```

### 4.2 Major Upgrade (protocol version bump)

See `UPGRADE.md` for detailed procedure including:
- Pre-upgrade checklist
- Activation height coordination
- Rollback plan

### 4.3 Pre-Deploy Checklist

```bash
./deploy/scripts/pre_deploy_checklist.sh
```

---

## 5. Reset Policy

### Golden Rule

> **NEVER delete data unless you are creating a new chain from genesis.**

### 5.1 Soft Reset (preserve identity)

```bash
./deploy/scripts/dev_reset.sh --node val2
```

This removes: blocks, WAL, snapshots, receipts, evidence, state
This preserves: `keys.json` (node identity)

### 5.2 Full Reset (new identity)

```bash
./deploy/scripts/dev_reset.sh --full --node val2
```

This removes **everything** including keys. Only use when:
- Creating entirely new chain
- Node identity is compromised
- Changing validator set in genesis

### 5.3 Reset All Nodes

```bash
# Soft reset (keep identities):
./deploy/scripts/dev_reset.sh

# Full reset (new chain):
./deploy/scripts/dev_reset.sh --full
```

### 5.4 When to Reset

| Scenario                          | Action              |
|-----------------------------------|---------------------|
| Binary upgrade                    | NO reset needed     |
| Config change (non-genesis)       | Restart, no reset   |
| Genesis change                    | Full reset ALL nodes|
| Corrupted WAL                     | Soft reset 1 node   |
| Node identity compromised         | Full reset 1 node   |
| Stuck consensus                   | Check logs first!   |

---

## 6. Troubleshooting

### 6.1 "Height not advancing"

**Symptoms:** All nodes report same height for >30s

**Diagnosis:**
```bash
# Check how many producers are running
for p in 9002 9003 9004; do
    echo -n "Port $p: "
    curl -sf http://127.0.0.1:$p/health && echo "" || echo "DOWN"
done
```

**Common causes:**
1. **Less than 2 producers online** → Start missing producers
2. **Clock skew** → Sync NTP: `sudo ntpdate -s time.nist.gov`
3. **Network partition** → Check peer counts (should be ≥2)
4. **Consensus stuck** → Check logs for `"round timeout"` messages

### 6.2 "Text file busy" on upgrade

**Cause:** Writing directly to running binary

**Fix:** Always use atomic deploy:
```bash
# WRONG (causes "Text file busy"):
cp new-binary /usr/local/bin/iona-node

# CORRECT (atomic):
cp new-binary /usr/local/bin/iona-node.new
mv /usr/local/bin/iona-node.new /usr/local/bin/iona-node
```

### 6.3 "Peer disconnects in loop"

**Symptoms:** Logs show repeated connect/disconnect

**Diagnosis:**
```bash
journalctl -u iona-val2 --since "5 min ago" | grep -c "disconnect"
```

**Common causes:**
1. **Self-bootstrap** → Check config: node should NOT have itself in peers
2. **Identity collision** → Two nodes using same keys.json (check seeds)
3. **Port conflict** → Verify no duplicate P2P ports
4. **Firewall** → Ensure P2P ports are open between validators

### 6.4 "Service fails to start"

```bash
# Check exit code
systemctl status iona-val2

# Check recent logs
journalctl -u iona-val2 -n 50 --no-pager

# Common issues:
# - Config parse error → validate TOML
# - Port already in use → check with: ss -tlnp | grep 9002
# - Permission denied → check data dir ownership
# - Missing keys.json → run node once to generate, or restore from backup
```

### 6.5 "Node stuck syncing"

```bash
# Check if height is increasing (slowly)
watch -n5 'curl -s http://127.0.0.1:9001/health | python3 -c "
import sys,json; d=json.load(sys.stdin); print(d.get(\"height\",0))"'

# If not increasing at all:
# 1. Check peer connections
# 2. Try soft reset + restart
# 3. Enable state sync in config: enable_p2p_state_sync = true
```

---

## 7. Monitoring

### 7.1 Healthcheck Script

```bash
# One-shot check
./deploy/scripts/healthcheck.sh

# Continuous monitoring (every 30s)
./deploy/scripts/healthcheck.sh --watch

# JSON output (for integration)
./deploy/scripts/healthcheck.sh --json
```

### 7.2 Key Metrics to Watch

| Metric               | Normal              | Alert if              |
|----------------------|---------------------|-----------------------|
| Block height         | Increasing          | Stuck for >30s        |
| Peer count           | ≥2 (producers)      | <2 (consensus at risk)|
| Block time           | <1s                 | >5s                   |
| Mempool size         | <100k               | >500k                 |
| Disk usage           | <80%                | >90%                  |
| Last commit age      | <5s                 | >60s                  |

### 7.3 Log Patterns

```bash
# Successful block production
journalctl -u iona-val2 | grep "committed block"

# Consensus rounds
journalctl -u iona-val2 | grep "new round"

# Peer connections
journalctl -u iona-val2 | grep -E "peer (connected|disconnected)"

# Errors
journalctl -u iona-val2 -p err
```

### 7.4 Alerting (simple)

Add to crontab:
```bash
# Check every minute
* * * * * /path/to/deploy/scripts/healthcheck.sh --json 2>/dev/null | \
    python3 -c "
import sys,json
data=json.load(sys.stdin)
for node in data.get('nodes',[]):
    if node.get('status')!='healthy':
        print(f'ALERT: {node[\"name\"]} unhealthy')
" >> /var/log/iona/alerts.log
```

---

## 8. Emergency Procedures

### 8.1 Network Halt (all producers down)

```bash
# 1. Restart producers in order
sudo systemctl start iona-val2
sleep 3
sudo systemctl start iona-val3
sleep 3
sudo systemctl start iona-val4

# 2. Wait for consensus
sleep 15

# 3. Verify height advancing
H1=$(curl -sf http://127.0.0.1:9002/health | python3 -c "import sys,json;print(json.load(sys.stdin).get('height',0))")
sleep 5
H2=$(curl -sf http://127.0.0.1:9002/health | python3 -c "import sys,json;print(json.load(sys.stdin).get('height',0))")
echo "Height: $H1 → $H2"

# 4. Restart followers
sudo systemctl start iona-val1
sudo systemctl start iona-rpc
```

### 8.2 Corrupted Node

```bash
# 1. Stop the corrupted node
sudo systemctl stop iona-val3

# 2. Soft reset (preserves identity)
./deploy/scripts/dev_reset.sh --node val3

# 3. Restart — will sync from other producers
sudo systemctl start iona-val3

# 4. Monitor sync progress
watch -n5 'curl -s http://127.0.0.1:9003/health'
```

### 8.3 Emergency Shutdown

```bash
# Stop in reverse order (RPC first, producers last)
sudo systemctl stop iona-rpc
sudo systemctl stop iona-val1
sudo systemctl stop iona-val4
sudo systemctl stop iona-val3
sudo systemctl stop iona-val2

echo "All IONA services stopped."
```

### 8.4 Backup Before Risky Operation

```bash
# Backup all node data
DATE=$(date +%Y%m%d_%H%M%S)
for node in val1 val2 val3 val4 rpc; do
    sudo tar czf "/var/backups/iona_${node}_${DATE}.tar.gz" \
        "/var/lib/iona/${node}/" 2>/dev/null
done
echo "Backups saved to /var/backups/"
```

---

## Appendix: Checklist Templates

### A. Daily Check

- [ ] All 5 services running (`systemctl is-active`)
- [ ] Height advancing on all nodes
- [ ] Peer count ≥2 on all producers
- [ ] Disk usage <80% on all machines
- [ ] No error logs in last 24h

### B. Pre-Upgrade Check

- [ ] Read CHANGELOG for breaking changes
- [ ] Backup data on at least 1 node
- [ ] Run pre-deploy checklist script
- [ ] Test new binary on non-producer first
- [ ] Coordinate upgrade window with team

### C. Post-Incident

- [ ] Document what happened
- [ ] Identify root cause
- [ ] Verify all nodes healthy
- [ ] Check no data corruption
- [ ] Update runbook if needed
