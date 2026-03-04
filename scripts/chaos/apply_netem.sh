#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:-eth0}"
ARGS="${2:-delay 200ms 50ms loss 5%}"
sudo tc qdisc del dev "${IFACE}" root 2>/dev/null || true
sudo tc qdisc add dev "${IFACE}" root netem ${ARGS}
echo "Applied netem: ${IFACE} -> ${ARGS}"
