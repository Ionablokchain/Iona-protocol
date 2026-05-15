#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# IONA Testnet Runner — Production‑Grade
# =============================================================================
# Starts a 4‑node IONA testnet locally (configurable number of nodes).
# Each node runs in the background; all are terminated on Ctrl+C.
#
# Usage: $0 [OPTIONS]
#
# Options:
#   --binary PATH      Path to iona-node binary (default: ./target/release/iona-node)
#   --base DIR         Base directory containing node1..nodeN subdirs (default: script location)
#   --nodes N          Number of nodes to start (default: 4, max: 10)
#   --wait SECONDS     Time to wait per node for health check (default: 5)
#   --verbose          Print detailed logs to stdout instead of files
#   --clean            Kill any processes already using the RPC ports before starting
#   --help             Show this help
# =============================================================================

# ── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${SCRIPT_DIR}/target/release/iona-node"
BASE_DIR="${SCRIPT_DIR}"
NUM_NODES=4
WAIT_SECONDS=5
VERBOSE=0
CLEAN=0
PIDS=()
BASE_RPC_PORT=8540
BASE_P2P_PORT=7001

# Colours for output (safe for non‑TTY)
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''
fi

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }
verbose() { [[ $VERBOSE -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $*"; }

# ── Helper functions ─────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --binary PATH      Path to iona-node binary (default: ./target/release/iona-node)
  --base DIR         Base directory containing node1..nodeN subdirs (default: script location)
  --nodes N          Number of nodes to start (default: 4, max: 10)
  --wait SECONDS     Time to wait per node for health check (default: 5)
  --verbose          Print detailed logs to stdout instead of files
  --clean            Kill any processes already using the RPC ports before starting
  --help             Show this help
EOF
  exit 0
}

# Check if a port is in use
port_in_use() {
  local port=$1
  (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null && return 0 || return 1
}

# Kill any process using a given port (Linux/macOS)
kill_port() {
  local port=$1
  local pid
  if command -v lsof &>/dev/null; then
    pid=$(lsof -ti "tcp:$port" 2>/dev/null || true)
    if [[ -n "$pid" ]]; then
      kill -TERM "$pid" 2>/dev/null || true
      sleep 0.5
      kill -KILL "$pid" 2>/dev/null || true
      info "Killed process on port $port (PID $pid)"
    fi
  else
    warn "lsof not installed; cannot auto‑clean port $port"
  fi
}

# Cleanup function to terminate all started nodes
cleanup() {
  echo ""
  info "Stopping testnet..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  # Wait a moment for graceful shutdown
  sleep 1
  for pid in "${PIDS[@]}"; do
    kill -KILL "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  info "Testnet stopped."
}
trap cleanup EXIT INT TERM

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)   BINARY="$2"; shift 2 ;;
    --base)     BASE_DIR="$2"; shift 2 ;;
    --nodes)    NUM_NODES="$2"; shift 2 ;;
    --wait)     WAIT_SECONDS="$2"; shift 2 ;;
    --verbose)  VERBOSE=1; shift ;;
    --clean)    CLEAN=1; shift ;;
    --help)     usage ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

# Validate number of nodes
if [[ ! "$NUM_NODES" =~ ^[0-9]+$ ]] || [[ $NUM_NODES -lt 1 ]] || [[ $NUM_NODES -gt 10 ]]; then
  die "Number of nodes must be between 1 and 10 (got $NUM_NODES)"
fi

# Validate binary
if [[ ! -x "$BINARY" ]]; then
  die "Binary not found or not executable: $BINARY\nBuild with: cargo build --release --bin iona-node"
fi
info "Using binary: $BINARY"

# Validate base directory and config files
for i in $(seq 1 "$NUM_NODES"); do
  CONFIG_FILE="${BASE_DIR}/node${i}/config.toml"
  if [[ ! -f "$CONFIG_FILE" ]]; then
    die "Config file not found: $CONFIG_FILE"
  fi
  # Ensure log directory exists
  mkdir -p "${BASE_DIR}/node${i}"
done

# Clean ports if requested
if [[ $CLEAN -eq 1 ]]; then
  info "Checking for port conflicts..."
  for i in $(seq 1 "$NUM_NODES"); do
    rpc_port=$((BASE_RPC_PORT + i))
    if port_in_use "$rpc_port"; then
      warn "Port $rpc_port is in use (node$i RPC). Killing..."
      kill_port "$rpc_port"
    fi
    p2p_port=$((BASE_P2P_PORT + i))
    if port_in_use "$p2p_port"; then
      warn "Port $p2p_port is in use (node$i P2P). Killing..."
      kill_port "$p2p_port"
    fi
  done
fi

# ── Start nodes ──────────────────────────────────────────────────────────────
echo ""
info "Starting ${NUM_NODES}-node IONA testnet..."
echo "──────────────────────────────────────────────────────────────────────"

for i in $(seq 1 "$NUM_NODES"); do
  CONFIG_FILE="${BASE_DIR}/node${i}/config.toml"
  LOG_FILE="${BASE_DIR}/node${i}/node.log"
  RPC_PORT=$((BASE_RPC_PORT + i))
  P2P_PORT=$((BASE_P2P_PORT + i))

  info "Starting node$i (RPC: http://127.0.0.1:${RPC_PORT}, P2P: $P2P_PORT)"
  if [[ $VERBOSE -eq 1 ]]; then
    "$BINARY" --config "$CONFIG_FILE" 2>&1 | tee -a "$LOG_FILE" &
  else
    "$BINARY" --config "$CONFIG_FILE" >> "$LOG_FILE" 2>&1 &
  fi
  pid=$!
  PIDS+=("$pid")
  verbose "  PID: $pid, log: $LOG_FILE"
  sleep 0.5
done

echo "──────────────────────────────────────────────────────────────────────"
info "Waiting for nodes to become healthy (${WAIT_SECONDS}s max per node)..."

# ── Health checks ────────────────────────────────────────────────────────────
HEALTHY_COUNT=0
for i in $(seq 1 "$NUM_NODES"); do
  RPC_PORT=$((BASE_RPC_PORT + i))
  HEALTH_URL="http://127.0.0.1:${RPC_PORT}/health"
  echo -n "  node$i (${HEALTH_URL}) ... "

  for ((t=1; t<=WAIT_SECONDS; t++)); do
    if curl -s -f -o /dev/null "$HEALTH_URL" 2>/dev/null; then
      echo -e " ${GREEN}OK${NC} (${t}s)"
      ((HEALTHY_COUNT++))
      break
    fi
    sleep 1
  done
  if [[ $t -gt $WAIT_SECONDS ]]; then
    echo -e " ${RED}FAILED${NC} (timeout)"
  fi
done

echo "──────────────────────────────────────────────────────────────────────"
if [[ $HEALTHY_COUNT -eq $NUM_NODES ]]; then
  echo -e "${GREEN}✅ All ${NUM_NODES} nodes are healthy!${NC}"
else
  echo -e "${YELLOW}⚠️  Only ${HEALTHY_COUNT}/${NUM_NODES} nodes are healthy. Check logs for details.${NC}"
fi

echo ""
info "Testnet running. RPC endpoints:"
for i in $(seq 1 "$NUM_NODES"); do
  echo "  node$i: http://127.0.0.1:$((BASE_RPC_PORT + i))"
done
echo ""
info "Log files: ${BASE_DIR}/node{1..${NUM_NODES}}/node.log"
echo ""
info "Press Ctrl+C to stop all nodes."

# ── Wait for background processes ───────────────────────────────────────────
wait
