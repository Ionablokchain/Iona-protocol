#!/usr/bin/env bash
# Drops all ingress/egress inside a container (simple partition)
# Usage: ./scripts/chaos/partition_docker.sh <container> on|off
set -euo pipefail
C="${1:?container name/id required}"
MODE="${2:?on|off}"
if [[ "${MODE}" == "on" ]]; then
  docker exec -u 0 "${C}" sh -lc "iptables -A INPUT -j DROP; iptables -A OUTPUT -j DROP"
  echo "Partition ON for ${C}"
elif [[ "${MODE}" == "off" ]]; then
  docker exec -u 0 "${C}" sh -lc "iptables -F"
  echo "Partition OFF for ${C}"
else
  echo "mode must be on|off" >&2
  exit 2
fi
