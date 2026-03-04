#!/usr/bin/env bash
# IONA Testnet Firewall Setup
# File: deploy/firewall/setup_ufw.sh
#
# Usage: sudo ./deploy/firewall/setup_ufw.sh [--bootnode] [--rpc]
#
# Flags:
#   --bootnode   Open P2P port to public (for bootnode machines: val2, val3)
#   --rpc        Open HTTPS port for nginx reverse proxy (for rpc machine)

set -euo pipefail

BOOTNODE=false
RPC=false
INTERNAL_SUBNET="10.0.1.0/24"

while [[ $# -gt 0 ]]; do
    case $1 in
        --bootnode) BOOTNODE=true; shift ;;
        --rpc) RPC=true; shift ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
done

echo "=== IONA Testnet Firewall Setup ==="
echo "Bootnode: $BOOTNODE"
echo "RPC: $RPC"
echo "Internal subnet: $INTERNAL_SUBNET"
echo ""

# Reset UFW
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# SSH (always)
ufw allow 22/tcp comment "SSH"

# P2P ports
if [ "$BOOTNODE" = true ]; then
    echo ">> Opening P2P ports to public (bootnode mode)"
    for port in 30334 30335; do
        ufw allow ${port}/tcp comment "IONA bootnode P2P"
    done
else
    echo ">> Opening P2P ports to internal subnet only"
    for port in 30333 30334 30335 30336 30337; do
        ufw allow from ${INTERNAL_SUBNET} to any port ${port} comment "IONA P2P internal"
    done
fi

# RPC via nginx
if [ "$RPC" = true ]; then
    echo ">> Opening HTTPS/HTTP ports for nginx"
    ufw allow 443/tcp comment "HTTPS (nginx proxy for IONA RPC)"
    ufw allow 80/tcp comment "HTTP (redirect to HTTPS)"
fi

# Prometheus (internal only)
ufw allow from ${INTERNAL_SUBNET} to any port 9090 comment "Prometheus internal"

# Enable
ufw --force enable

echo ""
echo "=== Firewall configured ==="
ufw status verbose
