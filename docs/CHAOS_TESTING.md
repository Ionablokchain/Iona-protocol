# Chaos testing

## Prereqs
- `iproute2` (tc), `iptables`, `jq`, `curl`

## Single host netem
Apply:
  ./scripts/chaos/apply_netem.sh eth0 "delay 200ms 50ms loss 5%"

Clear:
  ./scripts/chaos/clear_netem.sh eth0

## Partitions (docker)
Use `scripts/chaos/partition_docker.sh` to drop traffic for specific containers.
