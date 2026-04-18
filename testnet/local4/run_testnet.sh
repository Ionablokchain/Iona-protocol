#!/usr/bin/env bash
# Start 4‑node IONA testnet locally
# Usage: bash run_testnet.sh [binary] [options]
#
# Options:
#   --binary PATH   Path to iona-node binary (default: ./target/release/iona-node)
#   --base DIR      Base directory containing node1..node4 subdirectories (default: script location)
#   --wait SECONDS  Time to wait for each node to become healthy (default: 5)
#   --verbose       Print detailed logs

set -euo pipefail

# -----------------------------------------------------------------------------
# Default values
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="${SCRIPT_DIR}/target/release/iona-node"
BASE_DIR="${SCRIPT_DIR}"
WAIT_SECONDS=5
VERBOSE=0
PIDS=()

# -----------------------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            BINARY="$2"
            shift 2
            ;;
        --base)
            BASE_DIR="$2"
            shift 2
            ;;
        --wait)
            WAIT_SECONDS="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--binary PATH] [--base DIR] [--wait SECONDS] [--verbose]"
            exit 1
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Validate binary and directories
# -----------------------------------------------------------------------------
if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: Binary not found or not executable: $BINARY"
    echo "Build it with: cargo build --release --bin iona-node"
    exit 1
fi
echo "Using binary: $BINARY"

for i in {1..4}; do
    CONFIG_FILE="${BASE_DIR}/node${i}/config.toml"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: Config file not found: $CONFIG_FILE"
        exit 1
    fi
    # Ensure log directory exists
    mkdir -p "${BASE_DIR}/node${i}"
done

# -----------------------------------------------------------------------------
# Cleanup function
# -----------------------------------------------------------------------------
cleanup() {
    echo ""
    echo "Stopping testnet..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "Testnet stopped."
}
trap cleanup EXIT INT TERM

# -----------------------------------------------------------------------------
# Start nodes
# -----------------------------------------------------------------------------
echo "Starting 4‑node IONA testnet..."
echo "----------------------------------------"

for i in {1..4}; do
    CONFIG_FILE="${BASE_DIR}/node${i}/config.toml"
    LOG_FILE="${BASE_DIR}/node${i}/node.log"
    RPC_PORT=$((8540 + i))

    echo "Starting node$i (RPC: http://127.0.0.1:${RPC_PORT})"
    if [[ $VERBOSE -eq 1 ]]; then
        "$BINARY" --config "$CONFIG_FILE" 2>&1 | tee -a "$LOG_FILE" &
    else
        "$BINARY" --config "$CONFIG_FILE" >> "$LOG_FILE" 2>&1 &
    fi
    PIDS+=($!)
    echo "  PID: ${PIDS[-1]}, log: $LOG_FILE"
    sleep 0.5
done

echo "----------------------------------------"
echo "Waiting for nodes to become healthy (${WAIT_SECONDS}s max per node)..."

# -----------------------------------------------------------------------------
# Health check
# -----------------------------------------------------------------------------
HEALTHY_COUNT=0
for i in {1..4}; do
    RPC_PORT=$((8540 + i))
    HEALTH_URL="http://127.0.0.1:${RPC_PORT}/health"
    echo -n "  node$i (${HEALTH_URL}) ... "

    for ((t=1; t<=WAIT_SECONDS; t++)); do
        if curl -s -f -o /dev/null "$HEALTH_URL" 2>/dev/null; then
            echo "OK (${t}s)"
            ((HEALTHY_COUNT++))
            break
        fi
        sleep 1
    done
    if [[ $t -gt $WAIT_SECONDS ]]; then
        echo "FAILED (timeout)"
    fi
done

echo "----------------------------------------"
if [[ $HEALTHY_COUNT -eq 4 ]]; then
    echo "✅ All 4 nodes are healthy!"
else
    echo "⚠️  Only ${HEALTHY_COUNT}/4 nodes are healthy. Check logs for details."
fi

echo ""
echo "Testnet running. RPC endpoints:"
for i in {1..4}; do
    echo "  node$i: http://127.0.0.1:$((8540 + i))"
done
echo ""
echo "Log files: ${BASE_DIR}/node{1..4}/node.log"
echo ""
echo "Press Ctrl+C to stop all nodes."

# -----------------------------------------------------------------------------
# Wait for all background processes
# -----------------------------------------------------------------------------
wait
