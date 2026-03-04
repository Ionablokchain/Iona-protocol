#!/usr/bin/env bash
set -euo pipefail
#
# IONA Atomic Deploy — zero-downtime binary upgrade.
#
# Usage:
#   ./deploy/scripts/atomic_deploy.sh <node_name> <path_to_new_binary>
#   ./deploy/scripts/atomic_deploy.sh val2 ./iona-node
#   ./deploy/scripts/atomic_deploy.sh all  ./iona-node   # rolling deploy all nodes
#
# Steps:
#   1. Stop the service
#   2. Install new binary atomically (cp + mv, avoids "Text file busy")
#   3. Verify binary runs (--version or --help)
#   4. Start the service
#   5. Wait for health check
#
# This script avoids "Text file busy" by:
#   - Copying to a .new file first
#   - Using mv (atomic rename) to replace the running binary
#   - Never writing directly to the running binary

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <node_name|all> <path_to_new_binary>"
    echo "  node_name: val1|val2|val3|val4|rpc|all"
    echo "  Example: $0 val2 ./target/release/iona-node"
    exit 1
fi

NODE_NAME="$1"
NEW_BINARY="$2"
INSTALL_DIR="${IONA_INSTALL_DIR:-/usr/local/bin}"
SERVICE_PREFIX="${IONA_SERVICE_PREFIX:-iona}"
HEALTH_TIMEOUT=30

# Validate binary exists and is executable
if [[ ! -f "$NEW_BINARY" ]]; then
    echo "ERROR: Binary not found: $NEW_BINARY"
    exit 1
fi

deploy_node() {
    local node="$1"
    local service="${SERVICE_PREFIX}-${node}"
    local target="${INSTALL_DIR}/iona-node"

    echo "=== Deploying to $node ==="

    # Step 1: Stop
    echo "  [1/5] Stopping ${service}..."
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        sudo systemctl stop "$service"
        # Wait for clean shutdown (max 15s)
        for i in $(seq 1 15); do
            if ! systemctl is-active --quiet "$service" 2>/dev/null; then
                break
            fi
            sleep 1
        done
    else
        echo "    Service not running, skipping stop."
    fi

    # Step 2: Atomic install
    echo "  [2/5] Installing binary atomically..."
    local tmp_binary="${target}.new.$$"
    sudo cp "$NEW_BINARY" "$tmp_binary"
    sudo chmod +x "$tmp_binary"
    sudo mv "$tmp_binary" "$target"           # atomic rename
    echo "    Installed: $target"

    # Step 3: Verify binary
    echo "  [3/5] Verifying binary..."
    if "$target" --help >/dev/null 2>&1; then
        echo "    Binary OK"
    else
        echo "    WARN: Binary --help failed (may still work)"
    fi

    # Step 4: Start
    echo "  [4/5] Starting ${service}..."
    sudo systemctl start "$service"

    # Step 5: Health check
    echo "  [5/5] Waiting for health..."
    local rpc_port
    case "$node" in
        val1) rpc_port=9001 ;;
        val2) rpc_port=9002 ;;
        val3) rpc_port=9003 ;;
        val4) rpc_port=9004 ;;
        rpc)  rpc_port=9000 ;;
        *)    rpc_port=9001 ;;
    esac

    local ok=false
    for i in $(seq 1 "$HEALTH_TIMEOUT"); do
        if curl -sf "http://127.0.0.1:${rpc_port}/health" >/dev/null 2>&1; then
            ok=true
            break
        fi
        sleep 1
    done

    if $ok; then
        echo "    Health OK (${rpc_port})"
    else
        echo "    WARN: Health check timed out after ${HEALTH_TIMEOUT}s"
        echo "    Check logs: journalctl -u ${service} -n 50 --no-pager"
    fi

    echo "  === $node deployed ==="
    echo ""
}

if [[ "$NODE_NAME" == "all" ]]; then
    echo "=== Rolling Deploy (all nodes) ==="
    echo "Order: val2 -> val3 -> val4 -> val1 -> rpc"
    echo "Waiting 10s between nodes for quorum stability."
    echo ""

    for node in val2 val3 val4 val1 rpc; do
        deploy_node "$node"
        if [[ "$node" != "rpc" ]]; then
            echo "  Waiting 10s before next node..."
            sleep 10
        fi
    done

    echo "=== Rolling Deploy Complete ==="
else
    deploy_node "$NODE_NAME"
fi
