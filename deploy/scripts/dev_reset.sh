#!/usr/bin/env bash
set -euo pipefail
#
# IONA Dev Reset — controlled chain reset for development/testnet.
#
# Usage:
#   ./deploy/scripts/dev_reset.sh                  # reset data, KEEP keys
#   ./deploy/scripts/dev_reset.sh --full            # reset data AND keys (new chain)
#   ./deploy/scripts/dev_reset.sh --node val2       # reset only val2
#
# Rules:
#   - Keys (keys.json) are preserved by default (identity persistence).
#   - Only pass --full when you genuinely want a brand-new chain.
#   - Always stop services BEFORE running this script.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

FULL_RESET=false
TARGET_NODE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --full)     FULL_RESET=true; shift ;;
        --node)     TARGET_NODE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--full] [--node <name>]"
            echo "  --full   Reset keys too (new chain identity)"
            echo "  --node   Reset only the specified node (val1|val2|val3|val4|rpc)"
            exit 0
            ;;
        *)          echo "Unknown option: $1"; exit 1 ;;
    esac
done

DATA_ROOT="${IONA_DATA_ROOT:-/var/lib/iona}"
NODES=("val1" "val2" "val3" "val4" "rpc")

if [[ -n "$TARGET_NODE" ]]; then
    NODES=("$TARGET_NODE")
fi

echo "=== IONA Dev Reset ==="
echo "  Data root:  $DATA_ROOT"
echo "  Full reset: $FULL_RESET"
echo "  Nodes:      ${NODES[*]}"
echo ""

# Safety: check that services are stopped
for node in "${NODES[@]}"; do
    if systemctl is-active --quiet "iona-${node}" 2>/dev/null; then
        echo "ERROR: iona-${node} is still running. Stop it first:"
        echo "  sudo systemctl stop iona-${node}"
        exit 1
    fi
done

for node in "${NODES[@]}"; do
    NODE_DIR="${DATA_ROOT}/${node}"
    if [[ ! -d "$NODE_DIR" ]]; then
        echo "  [SKIP] $NODE_DIR does not exist"
        continue
    fi

    echo "  [RESET] $node"

    # Backup keys if not full reset
    if [[ "$FULL_RESET" == "false" ]] && [[ -f "$NODE_DIR/keys.json" ]]; then
        cp "$NODE_DIR/keys.json" "/tmp/iona_keys_${node}_$(date +%s).json"
        echo "    keys.json backed up to /tmp"
    fi

    # Remove chain data (blocks, WAL, state, snapshots, caches)
    rm -rf "${NODE_DIR}/blocks"
    rm -rf "${NODE_DIR}/wal"
    rm -rf "${NODE_DIR}/snapshots"
    rm -rf "${NODE_DIR}/receipts"
    rm -rf "${NODE_DIR}/evidence"
    rm -f  "${NODE_DIR}/state_full.json"
    rm -f  "${NODE_DIR}/stakes.json"
    rm -f  "${NODE_DIR}/schema.json"
    rm -f  "${NODE_DIR}/node_meta.json"
    rm -f  "${NODE_DIR}/quarantine.json"
    rm -f  "${NODE_DIR}/tx_index.json"

    if [[ "$FULL_RESET" == "true" ]]; then
        rm -f "${NODE_DIR}/keys.json"
        rm -f "${NODE_DIR}/keys.json.enc"
        echo "    keys.json removed (full reset)"
    else
        # Restore keys
        LATEST_BACKUP=$(ls -t /tmp/iona_keys_${node}_*.json 2>/dev/null | head -1 || true)
        if [[ -n "$LATEST_BACKUP" ]]; then
            cp "$LATEST_BACKUP" "$NODE_DIR/keys.json"
            echo "    keys.json restored"
        fi
    fi

    echo "    done"
done

echo ""
echo "=== Reset complete ==="
if [[ "$FULL_RESET" == "true" ]]; then
    echo "FULL reset: keys were removed. Nodes will generate new identities on next start."
    echo "This means a NEW CHAIN — old data is incompatible."
else
    echo "Data reset: keys preserved. Nodes keep their identity."
    echo "Start nodes in order: val2 -> val3 -> val4 -> val1 -> rpc"
fi
