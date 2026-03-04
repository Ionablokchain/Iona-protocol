#!/usr/bin/env bash
# ============================================================================
# IONA Testnet Status Checker
# ============================================================================
# Checks the health and status of all running testnet nodes.
#
# Usage:
#   ./scripts/testnet/testnet_status.sh [OPTIONS]
#
# Options:
#   --base-rpc PORT    Base RPC port (default: 19001)
#   --nodes N          Number of nodes (default: 4)
#   --host HOST        Host address (default: 127.0.0.1)
#   --json             Output in JSON format
#   --watch            Continuously monitor (every 5 seconds)
# ============================================================================

set -euo pipefail

BASE_RPC_PORT=19001
NUM_NODES=4
HOST="127.0.0.1"
JSON_OUTPUT=false
WATCH=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --base-rpc) BASE_RPC_PORT="$2"; shift 2 ;;
        --nodes)    NUM_NODES="$2"; shift 2 ;;
        --host)     HOST="$2"; shift 2 ;;
        --json)     JSON_OUTPUT=true; shift ;;
        --watch)    WATCH=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

check_status() {
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "{"
        echo "  \"timestamp\": \"$timestamp\","
        echo "  \"nodes\": ["
    else
        echo "============================================"
        echo " IONA Testnet Status — $timestamp"
        echo "============================================"
        echo ""
    fi

    local all_healthy=true
    local max_height=0
    local min_height=999999999

    for i in $(seq 1 "$NUM_NODES"); do
        local rpc_port=$((BASE_RPC_PORT + i - 1))
        local url="http://$HOST:$rpc_port"

        # Check health
        local health_status="DOWN"
        local height="N/A"
        local peers="N/A"
        local version="N/A"

        if health_resp=$(curl -s -m 2 "$url/health" 2>/dev/null); then
            health_status="UP"
        else
            health_status="DOWN"
            all_healthy=false
        fi

        # Get status if healthy
        if [[ "$health_status" == "UP" ]]; then
            if status_resp=$(curl -s -m 2 "$url/status" 2>/dev/null); then
                height=$(echo "$status_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('height', 'N/A'))" 2>/dev/null || echo "N/A")
                peers=$(echo "$status_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('peers', d.get('peer_count', 'N/A')))" 2>/dev/null || echo "N/A")
                version=$(echo "$status_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version', d.get('node_version', 'N/A')))" 2>/dev/null || echo "N/A")

                if [[ "$height" =~ ^[0-9]+$ ]]; then
                    [[ $height -gt $max_height ]] && max_height=$height
                    [[ $height -lt $min_height ]] && min_height=$height
                fi
            fi
        fi

        if [[ "$JSON_OUTPUT" == "true" ]]; then
            local comma=""
            [[ $i -lt $NUM_NODES ]] && comma=","
            echo "    {\"node\": $i, \"port\": $rpc_port, \"status\": \"$health_status\", \"height\": \"$height\", \"peers\": \"$peers\", \"version\": \"$version\"}$comma"
        else
            local status_icon="[DOWN]"
            [[ "$health_status" == "UP" ]] && status_icon="[ UP ]"
            printf "  Node %d  %s  Port: %d  Height: %s  Peers: %s  Version: %s\n" \
                "$i" "$status_icon" "$rpc_port" "$height" "$peers" "$version"
        fi
    done

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "  ],"
        echo "  \"summary\": {"
        echo "    \"all_healthy\": $all_healthy,"
        echo "    \"max_height\": $max_height,"
        echo "    \"min_height\": $min_height,"
        local height_diff=$((max_height - min_height))
        echo "    \"height_diff\": $height_diff"
        echo "  }"
        echo "}"
    else
        echo ""
        echo "  Summary:"
        if [[ "$all_healthy" == "true" ]]; then
            echo "    All $NUM_NODES nodes healthy"
        else
            echo "    WARNING: Some nodes are DOWN"
        fi
        if [[ $max_height -gt 0 ]]; then
            local height_diff=$((max_height - min_height))
            echo "    Height range: $min_height - $max_height (diff: $height_diff)"
            if [[ $height_diff -gt 5 ]]; then
                echo "    WARNING: Nodes are out of sync (diff > 5)"
            fi
        fi
        echo ""
        echo "============================================"
    fi
}

if [[ "$WATCH" == "true" ]]; then
    while true; do
        clear
        check_status
        sleep 5
    done
else
    check_status
fi
