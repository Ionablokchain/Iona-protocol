#!/usr/bin/env bash
# convert_config.sh — CometBFT config.toml → IONA config.toml mapping tool
#
# Migrates essential settings from a CometBFT configuration file to an
# IONA-compatible configuration.  Handles ports, timeouts, peer addresses,
# and mempool sizes where a direct mapping exists.
#
# USAGE
#   ./convert_config.sh [OPTIONS] <cometbft-config.toml> [output-file]
#
# OPTIONS
#   --chain-id <id>          Set the IONA chain ID (default: 6126151)
#   --p2p-port <port>        Override IONA P2P listen port (default: 7001)
#   --rpc-port <port>        Override IONA RPC listen port (default: 9001)
#   --unsafe-rpc-public      Bind RPC to 0.0.0.0 (insecure; use with caution)
#   --help                   Show this help
#
# REQUIREMENTS
#   bash 4+, grep, sed, awk, cut, tr, date
#
# EXIT CODES
#   0   Success
#   1   Usage or input error
#   2   Runtime error (missing dependencies, etc.)

set -euo pipefail

# -----------------------------------------------------------------------------
# Constants & defaults
# -----------------------------------------------------------------------------
IONA_DEFAULT_P2P_PORT=7001
IONA_DEFAULT_RPC_PORT=9001
IONA_DEFAULT_CHAIN_ID=6126151
COMETBFT_DEFAULT_P2P_PORT=26656
COMETBFT_DEFAULT_RPC_PORT=26657

# -----------------------------------------------------------------------------
# Terminal colours (only if stdout is a tty)
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' NC=''
fi

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
usage() {
    sed -n '1,/^$/p' "$0" | grep -E '^#( |$)' | sed 's/^# \?//'
    exit 0
}

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
check_deps() {
    for cmd in grep sed awk cut tr date; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Required command not found: $cmd"
            exit 2
        fi
    done
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
INPUT=""
OUTPUT="iona_config.toml"
CHAIN_ID="$IONA_DEFAULT_CHAIN_ID"
P2P_PORT="$IONA_DEFAULT_P2P_PORT"
RPC_PORT="$IONA_DEFAULT_RPC_PORT"
UNSAFE_RPC_PUBLIC=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --chain-id)
            CHAIN_ID="$2"; shift 2 ;;
        --p2p-port)
            P2P_PORT="$2"; shift 2 ;;
        --rpc-port)
            RPC_PORT="$2"; shift 2 ;;
        --unsafe-rpc-public)
            UNSAFE_RPC_PUBLIC=1; shift ;;
        --help)
            usage ;;
        -*)
            err "Unknown option: $1"
            echo "Try '$0 --help' for more information." >&2
            exit 1 ;;
        *)
            if [[ -z "$INPUT" ]]; then
                INPUT="$1"
            else
                OUTPUT="$1"
            fi
            shift ;;
    esac
done

if [[ -z "$INPUT" ]]; then
    err "No input file specified."
    echo "Usage: $0 [OPTIONS] <cometbft-config.toml> [output-file]" >&2
    exit 1
fi
if [[ ! -f "$INPUT" ]]; then
    err "Input file not found: $INPUT"
    exit 1
fi
if [[ ! -r "$INPUT" ]]; then
    err "Cannot read input file: $INPUT"
    exit 1
fi

# -----------------------------------------------------------------------------
# TOML value extractor (safe, section-aware)
# -----------------------------------------------------------------------------
# Extracts a value for `key` in optional `[section]`. If section is empty,
# searches globally.  Strips quotes and inline comments.
toml_get() {
    local file="$1" section="$2" key="$3" default="${4:-}"
    local val
    if [[ -n "$section" ]]; then
        # Find the section, then the key within it
        val=$(awk -v section="[$section]" -v key="$key" '
            BEGIN { in_section=0 }
            $0 == section { in_section=1; next }
            /^\[/ { in_section=0; next }
            in_section && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
                sub(/^[[:space:]]*[^=]+=[[:space:]]*/, "");
                sub(/[[:space:]]*#.*$/, "");
                gsub(/"/, ""); gsub(/\x27/, "");
                print; exit
            }' "$file")
    else
        val=$(grep -E "^\s*${key}\s*=" "$file" | head -1 | \
              sed -E 's/^\s*[^=]+=\s*//; s/\s*#.*//' | tr -d '"' | tr -d "'" | xargs)
    fi
    echo "${val:-$default}"
}

# -----------------------------------------------------------------------------
# Value extraction from CometBFT config
# -----------------------------------------------------------------------------
info "Reading CometBFT config: $INPUT"

# P2P
P2P_LADDR=$(toml_get "$INPUT" "p2p" "laddr" "tcp://0.0.0.0:${COMETBFT_DEFAULT_P2P_PORT}")
P2P_SEEDS=$(toml_get "$INPUT" "p2p" "seeds" "")
P2P_PERSISTENT_PEERS=$(toml_get "$INPUT" "p2p" "persistent_peers" "")
P2P_MAX_PEERS=$(toml_get "$INPUT" "p2p" "max_num_outbound_peers" "10")
P2P_HANDSHAKE_TIMEOUT=$(toml_get "$INPUT" "p2p" "handshake_timeout" "20s")

# RPC
RPC_LADDR=$(toml_get "$INPUT" "rpc" "laddr" "tcp://127.0.0.1:${COMETBFT_DEFAULT_RPC_PORT}")

# Mempool
MEMPOOL_SIZE=$(toml_get "$INPUT" "mempool" "size" "5000")
MEMPOOL_MAX_TX=$(toml_get "$INPUT" "mempool" "max_tx_bytes" "1048576")

# Consensus
TIMEOUT_PROPOSE=$(toml_get "$INPUT" "consensus" "timeout_propose" "3s")
TIMEOUT_PREVOTE=$(toml_get "$INPUT" "consensus" "timeout_prevote" "1s")
TIMEOUT_PRECOMMIT=$(toml_get "$INPUT" "consensus" "timeout_precommit" "1s")
TIMEOUT_COMMIT=$(toml_get "$INPUT" "consensus" "timeout_commit" "5s")

# -----------------------------------------------------------------------------
# Port conversions
# -----------------------------------------------------------------------------
# Extract host part from CometBFT P2P address (tcp://host:port)
P2P_HOST=$(echo "$P2P_LADDR" | sed -n 's|^tcp://\([^:]*\):.*|\1|p')
if [[ -z "$P2P_HOST" ]]; then
    warn "Could not parse P2P listen address '$P2P_LADDR', defaulting to 0.0.0.0"
    P2P_HOST="0.0.0.0"
fi

IONA_P2P_LISTEN="${P2P_HOST}:${P2P_PORT}"
if [[ "$P2P_HOST" == "127.0.0.1" || "$P2P_HOST" == "localhost" ]]; then
    IONA_P2P_LISTEN="127.0.0.1:${P2P_PORT}"
fi

# RPC listen
if [[ "$UNSAFE_RPC_PUBLIC" -eq 1 ]]; then
    IONA_RPC_LISTEN="0.0.0.0:${RPC_PORT}"
    warn "RPC will be exposed to 0.0.0.0 — this is INSECURE for production."
else
    IONA_RPC_LISTEN="127.0.0.1:${RPC_PORT}"
    if echo "$RPC_LADDR" | grep -q "0\.0\.0\.0"; then
        warn "CometBFT RPC was bound to 0.0.0.0. IONA RPC will listen on 127.0.0.1 (safer)."
        warn "Use --unsafe-rpc-public if you really need public RPC."
    fi
fi

# -----------------------------------------------------------------------------
# Peer address conversion
# -----------------------------------------------------------------------------
# CometBFT: nodeID@host:26656  →  IONA: "host:port"
convert_peers() {
    local peers="$1" target_port="$2"
    local result=""
    local IFS=','
    for peer in $peers; do
        peer=$(echo "$peer" | xargs)
        [[ -z "$peer" ]] && continue
        # Extract host and optional port
        local host_port="${peer#*@}"
        local host="${host_port%:*}"
        local port="${host_port##*:}"
        # If port is the standard CometBFT port, replace with IONA port
        [[ "$port" == "$COMETBFT_DEFAULT_P2P_PORT" ]] && port="$target_port"
        [[ -z "$host" ]] && continue
        if [[ -n "$result" ]]; then result+=", "; fi
        result+="\"${host}:${port}\""
    done
    echo "$result"
}

IONA_PEERS=$(convert_peers "${P2P_PERSISTENT_PEERS},${P2P_SEEDS}" "$P2P_PORT")

# -----------------------------------------------------------------------------
# Timeout conversion to milliseconds
# -----------------------------------------------------------------------------
to_ms() {
    local val="$1" default="$2"
    if echo "$val" | grep -qE '^[0-9]+s$'; then
        echo "$((${val%s} * 1000))"
    elif echo "$val" | grep -qE '^[0-9]+ms$'; then
        echo "${val%ms}"
    elif echo "$val" | grep -qE '^[0-9]+$'; then
        # Assume seconds if no unit
        echo "$((val * 1000))"
    else
        echo "$default"
    fi
}

IONA_PROPOSE_MS=$(to_ms "$TIMEOUT_PROPOSE" "3000")
IONA_PREVOTE_MS=$(to_ms "$TIMEOUT_PREVOTE" "1000")
IONA_PRECOMMIT_MS=$(to_ms "$TIMEOUT_PRECOMMIT" "1000")

# -----------------------------------------------------------------------------
# Generate IONA config
# -----------------------------------------------------------------------------
info "Writing IONA config to: $OUTPUT"

# Create parent directory if needed
output_dir=$(dirname "$OUTPUT")
if [[ ! -d "$output_dir" ]]; then
    mkdir -p "$output_dir" || { err "Failed to create directory $output_dir"; exit 2; }
fi

cat > "$OUTPUT" << TOML
# IONA config.toml — generated by adapters/cosmos/convert_config.sh
# Source: ${INPUT}
# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
#
# REVIEW THIS FILE before starting IONA.
# Not all CometBFT settings have direct equivalents; see UNMAPPED section
# at the bottom of this file for settings that require manual attention.

[node]
data_dir    = "./data"
keystore    = "encrypted"
seed        = 0          # unused when keystore=encrypted
chain_id    = ${CHAIN_ID}

[network]
listen   = "${IONA_P2P_LISTEN}"
$([ -n "$IONA_PEERS" ] && echo "peers    = [${IONA_PEERS}]" || echo "peers    = []")
bootnodes = []
enable_mdns = false
enable_kad  = true

# Eclipse resistance (not in CometBFT; IONA-specific)
# "mainnet" = stricter peer diversity; "testnet" = relaxed
eclipse_profile = "mainnet"

[rpc]
listen = "${IONA_RPC_LISTEN}"
# NOTE: CometBFT RPC was at ${RPC_LADDR}
# IONA default is 127.0.0.1:${RPC_PORT} (loopback only for security)

cors_allow_all  = false
max_body_bytes  = ${MEMPOOL_MAX_TX:-1048576}
enable_faucet   = false

[admin]
listen         = "127.0.0.1:9002"
require_mtls   = true
rbac_path      = "./rbac.toml"
tls_cert_pem   = "./tls/admin-server.crt.pem"
tls_key_pem    = "./tls/admin-server.key.pem"
tls_ca_cert_pem = "./tls/ca.crt.pem"
audit_log_path = "./data/audit.log"

[consensus]
propose_timeout_ms    = ${IONA_PROPOSE_MS}
prevote_timeout_ms    = ${IONA_PREVOTE_MS}
precommit_timeout_ms  = ${IONA_PRECOMMIT_MS}
# NOTE: timeout_commit (${TIMEOUT_COMMIT}) controls block interval in CometBFT.
# In IONA this is managed by the proposer; adjust max_txs_per_block instead.
max_txs_per_block     = 4096
gas_target            = 30000000

[mempool]
# CometBFT mempool.size = ${MEMPOOL_SIZE}
# IONA uses a priority queue; capacity is in entries
capacity = ${MEMPOOL_SIZE}

[storage]
enable_snapshots        = true
snapshot_every_n_blocks = 500
snapshot_keep           = 5
snapshot_zstd_level     = 3

# ── Port mapping reference ─────────────────────────────────────────────────
# CometBFT ${COMETBFT_DEFAULT_P2P_PORT} (P2P)  → IONA ${P2P_PORT}
# CometBFT ${COMETBFT_DEFAULT_RPC_PORT} (RPC)  → IONA ${RPC_PORT}
# CometBFT 9090  (gRPC) → IONA 9090 (metrics)
# CometBFT 9091  (REST) → IONA ${RPC_PORT} (same RPC)

# ── UNMAPPED SETTINGS ──────────────────────────────────────────────────────
# The following CometBFT settings have no direct IONA equivalent.
# Review each one manually:
#
# [p2p].pex                    → IONA uses libp2p Kademlia DHT (enable_kad)
# [p2p].addr_book_strict       → No equivalent; IONA uses eclipse scoring
# [p2p].flush_throttle_timeout → No equivalent
# [p2p].send_rate / recv_rate  → No equivalent (use OS-level tc/iptables)
# [mempool].cache_size         → No equivalent; IONA deduplicates by hash
# [mempool].version            → IONA uses a single priority-queue mempool
# [consensus].create_empty_blocks → IONA always creates empty blocks on schedule
# [consensus].double_sign_check_height → IONA DoubleSignGuard covers this
# [statesync].*                → Use iona backup/restore instead
# [instrumentation].prometheus  → IONA always exposes /metrics on port 9090
# [fastsync] / [blocksync].*   → IONA uses P2P state sync automatically
TOML

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
info "Conversion complete: $OUTPUT"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mapped settings:"
echo "    ✓  P2P listen     ${P2P_LADDR} → ${IONA_P2P_LISTEN}"
echo "    ✓  RPC listen     (loopback)  → ${IONA_RPC_LISTEN}"
echo "    ✓  Peer addresses (max ${P2P_MAX_PEERS}) → converted"
echo "    ✓  Timeouts       propose/prevote/precommit"
echo "    ✓  Mempool size   ${MEMPOOL_SIZE} entries"
echo ""
echo "  Requires manual review (see UNMAPPED section in $OUTPUT):"
warn "    ⚠  pex / addr_book settings"
warn "    ⚠  statesync configuration"
warn "    ⚠  chain_id — update [node].chain_id if needed"
warn "    ⚠  Peer addresses — verify multiaddr format was converted"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next steps:"
echo "  1. Review $OUTPUT — especially chain_id and peer addresses"
echo "  2. Run: iona keys check ./data"
echo "  3. Run: iona-node --check-compat --config $OUTPUT"
echo "  4. Test on IONA testnet before mainnet"
echo "  5. See adapters/cosmos/migrate_validator.md for full procedure"
echo ""
