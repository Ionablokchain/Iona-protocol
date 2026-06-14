#!/usr/bin/env bash
# convert_config.sh — CometBFT config.toml → IONA config.toml converter
#
# Migrates essential settings from a CometBFT configuration to an
# IONA-compatible configuration. Handles ports, timeouts, peer addresses,
# mempool sizes, and where possible maps to IONA equivalents.
#
# USAGE
#   ./convert_config.sh [OPTIONS] <cometbft-config.toml> [output-file]
#
# OPTIONS
#   --chain-id <id>          Set IONA chain ID (default: 6126151)
#   --p2p-port <port>        Override IONA P2P listen port (default: 7001)
#   --rpc-port <port>        Override IONA RPC listen port (default: 9001)
#   --admin-port <port>      IONA admin API port (default: 9002)
#   --p2p-multiaddr <fmt>    Output format for peers: "host_port" (default) or "libp2p"
#   --unsafe-rpc-public      Bind RPC to 0.0.0.0 (insecure; use with caution)
#   --overwrite              Overwrite output file if exists (else create backup)
#   --backup <dir>           Backup output file to directory before overwriting
#   --verbose                Verbose output
#   --quiet                  Suppress all non‑error output
#   --version                Show version
#   --help                   Show this help
#
# REQUIREMENTS
#   bash 4+, grep, sed, awk, cut, tr, date, mktemp, install
#
# EXIT CODES
#   0   Success
#   1   Usage or input error
#   2   Runtime error (missing dependencies, invalid config, etc.)
#   3   Permission error (cannot write output)
#   4   Checksum verification failed (if enabled)

set -euo pipefail

# -----------------------------------------------------------------------------
# Constants & defaults
# -----------------------------------------------------------------------------
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly IONA_DEFAULT_P2P_PORT=7001
readonly IONA_DEFAULT_RPC_PORT=9001
readonly IONA_DEFAULT_ADMIN_PORT=9002
readonly IONA_DEFAULT_CHAIN_ID=6126151
readonly COMETBFT_DEFAULT_P2P_PORT=26656
readonly COMETBFT_DEFAULT_RPC_PORT=26657

# -----------------------------------------------------------------------------
# Global variables
# -----------------------------------------------------------------------------
INPUT=""
OUTPUT=""
CHAIN_ID="$IONA_DEFAULT_CHAIN_ID"
P2P_PORT="$IONA_DEFAULT_P2P_PORT"
RPC_PORT="$IONA_DEFAULT_RPC_PORT"
ADMIN_PORT="$IONA_DEFAULT_ADMIN_PORT"
PEER_OUTPUT_FORMAT="host_port"  # "host_port" or "libp2p"
UNSAFE_RPC_PUBLIC=0
OVERWRITE=0
BACKUP_DIR=""
VERBOSE=0
QUIET=0
SHOW_VERSION=0

# Colours (only if stdout is a tty and not quiet)
if [[ -t 1 && ${QUIET} -eq 0 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' NC=''
fi

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
info() {
    if [[ ${QUIET} -eq 0 ]]; then echo -e "${GREEN}[INFO]${NC}  $*"; fi
}
warn() {
    if [[ ${QUIET} -eq 0 ]]; then echo -e "${YELLOW}[WARN]${NC}  $*" >&2; fi
}
err() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}
die() {
    err "$1"
    exit "${2:-1}"
}

# Log only if verbose
debug() {
    if [[ ${VERBOSE} -eq 1 && ${QUIET} -eq 0 ]]; then
        echo -e "[DEBUG] $*"
    fi
}

# -----------------------------------------------------------------------------
# Help & version
# -----------------------------------------------------------------------------
usage() {
    sed -n '1,/^$/p' "$0" | grep -E '^#( |$)' | sed 's/^# \?//'
    exit 0
}

version() {
    echo "${SCRIPT_NAME} version ${SCRIPT_VERSION}"
    exit 0
}

# -----------------------------------------------------------------------------
# Dependency check
# -----------------------------------------------------------------------------
check_deps() {
    local deps=(grep sed awk cut tr date mktemp install)
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            die "Required command not found: $cmd" 2
        fi
    done
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --chain-id)         CHAIN_ID="$2"; shift 2 ;;
            --p2p-port)         P2P_PORT="$2"; shift 2 ;;
            --rpc-port)         RPC_PORT="$2"; shift 2 ;;
            --admin-port)       ADMIN_PORT="$2"; shift 2 ;;
            --p2p-multiaddr)    PEER_OUTPUT_FORMAT="$2"; shift 2 ;;
            --unsafe-rpc-public) UNSAFE_RPC_PUBLIC=1; shift ;;
            --overwrite)        OVERWRITE=1; shift ;;
            --backup)           BACKUP_DIR="$2"; shift 2 ;;
            --verbose)          VERBOSE=1; shift ;;
            --quiet)            QUIET=1; shift ;;
            --version)          SHOW_VERSION=1; shift ;;
            --help)             usage ;;
            -*)
                die "Unknown option: $1\nTry '$0 --help' for more information." 1
                ;;
            *)
                if [[ -z "$INPUT" ]]; then
                    INPUT="$1"
                else
                    OUTPUT="$1"
                fi
                shift
                ;;
        esac
    done

    if [[ $SHOW_VERSION -eq 1 ]]; then version; fi
    if [[ -z "$INPUT" ]]; then
        die "No input file specified.\nUsage: $0 [OPTIONS] <cometbft-config.toml> [output-file]" 1
    fi
    if [[ ! -f "$INPUT" ]]; then
        die "Input file not found: $INPUT" 1
    fi
    if [[ ! -r "$INPUT" ]]; then
        die "Cannot read input file: $INPUT" 1
    fi

    # Default output name
    if [[ -z "$OUTPUT" ]]; then
        OUTPUT="iona_config.toml"
    fi

    if [[ "$PEER_OUTPUT_FORMAT" != "host_port" && "$PEER_OUTPUT_FORMAT" != "libp2p" ]]; then
        die "Invalid --p2p-multiaddr value: $PEER_OUTPUT_FORMAT (must be 'host_port' or 'libp2p')" 1
    fi
}

# -----------------------------------------------------------------------------
# TOML value extractor (safe, section-aware)
# -----------------------------------------------------------------------------
toml_get() {
    local file="$1" section="$2" key="$3" default="${4:-}"
    local val
    if [[ -n "$section" ]]; then
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
# Time conversion (s/ms → milliseconds)
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

# -----------------------------------------------------------------------------
# Convert CometBFT peer strings to IONA format
# Input: nodeID@host:port or host:port
# Output: IONA multiaddr or "host:port" depending on PEER_OUTPUT_FORMAT
# -----------------------------------------------------------------------------
convert_peer() {
    local peer="$1"
    local target_port="$2"
    peer=$(echo "$peer" | xargs)
    [[ -z "$peer" ]] && return

    local host_port="${peer#*@}"
    local host="${host_port%:*}"
    local port="${host_port##*:}"
    local peer_id="${peer%%@*}"
    if [[ "$peer_id" == "$host_port" ]]; then
        peer_id=""   # no node ID given
    fi

    # Replace default CometBFT port with IONA port if present
    if [[ "$port" == "$COMETBFT_DEFAULT_P2P_PORT" ]]; then
        port="$target_port"
    fi

    if [[ "$PEER_OUTPUT_FORMAT" == "host_port" ]]; then
        echo "\"${host}:${port}\""
    else
        if [[ -n "$peer_id" ]]; then
            echo "\"/ip4/${host}/tcp/${port}/p2p/${peer_id}\""
        else
            # Without peer ID, we can only put host:port; libp2p multiaddr requires peer ID.
            # We'll still output a string and let user add the ID.
            echo "\"/ip4/${host}/tcp/${port}/p2p/_\""
            warn "Peer $host:$port lacks a node ID; please replace '_' with actual peer ID."
        fi
    fi
}

# -----------------------------------------------------------------------------
# Convert comma-separated list of peers
# -----------------------------------------------------------------------------
convert_peers() {
    local peers="$1" target_port="$2"
    local result=""
    local IFS=','

    for peer in $peers; do
        peer=$(echo "$peer" | xargs)
        [[ -z "$peer" ]] && continue
        local conv=$(convert_peer "$peer" "$target_port")
        if [[ -n "$result" ]]; then
            result+=", "
        fi
        result+="$conv"
    done
    echo "$result"
}

# -----------------------------------------------------------------------------
# Generate IONA config file atomically
# -----------------------------------------------------------------------------
generate_config() {
    local output_tmp
    output_tmp="$(mktemp -p "$(dirname "$OUTPUT")" tmp.iona_config.XXXXXX)" || die "Failed to create temporary file" 2

    # Capture values from CometBFT config
    info "Reading CometBFT config: $INPUT"

    # P2P
    local p2p_laddr=$(toml_get "$INPUT" "p2p" "laddr" "tcp://0.0.0.0:${COMETBFT_DEFAULT_P2P_PORT}")
    local p2p_seeds=$(toml_get "$INPUT" "p2p" "seeds" "")
    local p2p_persistent=$(toml_get "$INPUT" "p2p" "persistent_peers" "")
    local p2p_max_peers=$(toml_get "$INPUT" "p2p" "max_num_outbound_peers" "10")
    local p2p_handshake_timeout=$(toml_get "$INPUT" "p2p" "handshake_timeout" "20s")

    # RPC
    local rpc_laddr=$(toml_get "$INPUT" "rpc" "laddr" "tcp://127.0.0.1:${COMETBFT_DEFAULT_RPC_PORT}")

    # Mempool
    local mempool_size=$(toml_get "$INPUT" "mempool" "size" "5000")
    local mempool_max_tx=$(toml_get "$INPUT" "mempool" "max_tx_bytes" "1048576")

    # Consensus
    local timeout_propose=$(toml_get "$INPUT" "consensus" "timeout_propose" "3s")
    local timeout_prevote=$(toml_get "$INPUT" "consensus" "timeout_prevote" "1s")
    local timeout_precommit=$(toml_get "$INPUT" "consensus" "timeout_precommit" "1s")
    local timeout_commit=$(toml_get "$INPUT" "consensus" "timeout_commit" "5s")

    # Convert timeouts to milliseconds
    local iona_propose_ms=$(to_ms "$timeout_propose" "3000")
    local iona_prevote_ms=$(to_ms "$timeout_prevote" "1000")
    local iona_precommit_ms=$(to_ms "$timeout_precommit" "1000")

    # Extract P2P listen host
    local p2p_host=$(echo "$p2p_laddr" | sed -n 's|^tcp://\([^:]*\):.*|\1|p')
    if [[ -z "$p2p_host" ]]; then
        warn "Could not parse P2P listen address '$p2p_laddr', defaulting to 0.0.0.0"
        p2p_host="0.0.0.0"
    fi
    local iona_p2p_listen="${p2p_host}:${P2P_PORT}"
    if [[ "$p2p_host" == "127.0.0.1" || "$p2p_host" == "localhost" ]]; then
        iona_p2p_listen="127.0.0.1:${P2P_PORT}"
    fi

    # RPC listen
    local iona_rpc_listen
    if [[ "$UNSAFE_RPC_PUBLIC" -eq 1 ]]; then
        iona_rpc_listen="0.0.0.0:${RPC_PORT}"
        warn "RPC will be exposed to 0.0.0.0 — this is INSECURE for production."
    else
        iona_rpc_listen="127.0.0.1:${RPC_PORT}"
        if echo "$rpc_laddr" | grep -q "0\.0\.0\.0"; then
            warn "CometBFT RPC was bound to 0.0.0.0. IONA RPC will listen on 127.0.0.1 (safer)."
            warn "Use --unsafe-rpc-public if you really need public RPC."
        fi
    fi

    # Convert peers
    local all_peers="${p2p_persistent}"
    if [[ -n "$p2p_seeds" ]]; then
        all_peers="${all_peers:+$all_peers,}${p2p_seeds}"
    fi
    local iona_peers=$(convert_peers "$all_peers" "$P2P_PORT")

    debug "P2P listen: $p2p_laddr -> $iona_p2p_listen"
    debug "Peers: $iona_peers"
    debug "Timeouts: propose=$iona_propose_ms ms, prevote=$iona_prevote_ms ms, precommit=$iona_precommit_ms ms"

    # Write the config
    {
        echo "# IONA config.toml — generated by ${SCRIPT_NAME} v${SCRIPT_VERSION}"
        echo "# Source: ${INPUT}"
        echo "# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "#"
        echo "# REVIEW THIS FILE before starting IONA."
        echo "# Not all CometBFT settings have direct equivalents; see UNMAPPED section at the bottom."
        echo ""

        echo "[node]"
        echo "data_dir    = \"./data\""
        echo "keystore    = \"encrypted\""
        echo "seed        = 0          # unused when keystore=encrypted"
        echo "chain_id    = ${CHAIN_ID}"
        echo ""

        echo "[network]"
        echo "listen   = \"${iona_p2p_listen}\""
        if [[ -n "$iona_peers" ]]; then
            echo "peers    = [${iona_peers}]"
        else
            echo "peers    = []"
        fi
        echo "bootnodes = []"
        echo "enable_mdns = false"
        echo "enable_kad  = true"
        echo ""
        echo "# Eclipse resistance (not in CometBFT; IONA-specific)"
        echo "# \"mainnet\" = stricter peer diversity; \"testnet\" = relaxed"
        echo "eclipse_profile = \"mainnet\""
        echo ""

        echo "[rpc]"
        echo "listen = \"${iona_rpc_listen}\""
        echo "# NOTE: CometBFT RPC was at ${rpc_laddr}"
        echo "# IONA default is 127.0.0.1:${RPC_PORT} (loopback only for security)"
        echo "cors_allow_all  = false"
        echo "max_body_bytes  = ${mempool_max_tx}"
        echo "enable_faucet   = false"
        echo ""

        echo "[admin]"
        echo "listen         = \"127.0.0.1:${ADMIN_PORT}\""
        echo "require_mtls   = true"
        echo "rbac_path      = \"./rbac.toml\""
        echo "tls_cert_pem   = \"./tls/admin-server.crt.pem\""
        echo "tls_key_pem    = \"./tls/admin-server.key.pem\""
        echo "tls_ca_cert_pem = \"./tls/ca.crt.pem\""
        echo "audit_log_path = \"./data/audit.log\""
        echo ""

        echo "[consensus]"
        echo "propose_timeout_ms    = ${iona_propose_ms}"
        echo "prevote_timeout_ms    = ${iona_prevote_ms}"
        echo "precommit_timeout_ms  = ${iona_precommit_ms}"
        echo "# NOTE: timeout_commit (${timeout_commit}) controls block interval in CometBFT."
        echo "# In IONA this is managed by the proposer; adjust max_txs_per_block instead."
        echo "max_txs_per_block     = 4096"
        echo "gas_target            = 30000000"
        echo ""

        echo "[mempool]"
        echo "# CometBFT mempool.size = ${mempool_size}"
        echo "# IONA uses a priority queue; capacity is in entries"
        echo "capacity = ${mempool_size}"
        echo ""

        echo "[storage]"
        echo "enable_snapshots        = true"
        echo "snapshot_every_n_blocks = 500"
        echo "snapshot_keep           = 5"
        echo "snapshot_zstd_level     = 3"
        echo ""

        echo "# ── Port mapping reference ─────────────────────────────────────────────────"
        echo "# CometBFT ${COMETBFT_DEFAULT_P2P_PORT} (P2P)  → IONA ${P2P_PORT}"
        echo "# CometBFT ${COMETBFT_DEFAULT_RPC_PORT} (RPC)  → IONA ${RPC_PORT}"
        echo "# CometBFT 9090  (gRPC) → IONA 9090 (metrics)"
        echo "# CometBFT 9091  (REST) → IONA ${RPC_PORT} (same RPC)"
        echo ""

        echo "# ── UNMAPPED SETTINGS ──────────────────────────────────────────────────────"
        echo "# The following CometBFT settings have no direct IONA equivalent."
        echo "# Review each one manually:"
        echo "#"
        echo "# [p2p].pex                    → IONA uses libp2p Kademlia DHT (enable_kad)"
        echo "# [p2p].addr_book_strict       → No equivalent; IONA uses eclipse scoring"
        echo "# [p2p].flush_throttle_timeout → No equivalent"
        echo "# [p2p].send_rate / recv_rate  → No equivalent (use OS-level tc/iptables)"
        echo "# [mempool].cache_size         → No equivalent; IONA deduplicates by hash"
        echo "# [mempool].version            → IONA uses a single priority-queue mempool"
        echo "# [consensus].create_empty_blocks → IONA always creates empty blocks on schedule"
        echo "# [consensus].double_sign_check_height → IONA DoubleSignGuard covers this"
        echo "# [statesync].*                → Use iona backup/restore instead"
        echo "# [instrumentation].prometheus  → IONA always exposes /metrics on port 9090"
        echo "# [fastsync] / [blocksync].*   → IONA uses P2P state sync automatically"
        echo "#"
    } > "$output_tmp"

    # Handle existing output file
    if [[ -e "$OUTPUT" ]]; then
        if [[ $OVERWRITE -eq 1 ]]; then
            warn "Overwriting existing $OUTPUT"
            if [[ -n "$BACKUP_DIR" ]]; then
                mkdir -p "$BACKUP_DIR" || die "Cannot create backup directory $BACKUP_DIR" 3
                local backup_file="${BACKUP_DIR}/$(basename "$OUTPUT").$(date +%Y%m%d_%H%M%S).bak"
                cp "$OUTPUT" "$backup_file"
                info "Backup saved to $backup_file"
            fi
        else
            die "Output file $OUTPUT already exists. Use --overwrite or --backup to proceed." 3
        fi
    fi

    # Atomic move
    install -m 644 "$output_tmp" "$OUTPUT" || die "Failed to write $OUTPUT" 3
    rm -f "$output_tmp"
    info "Configuration written to $OUTPUT"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    check_deps
    parse_args "$@"
    generate_config

    echo ""
    info "Conversion complete: $OUTPUT"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Mapped settings:"
    echo "    ✓  P2P listen     → $(grep -E '^listen\s*=' "$OUTPUT" | sed 's/.*= //')"
    echo "    ✓  RPC listen     → $(grep -E '^listen\s*=' "$OUTPUT" | grep -A1 '\[rpc\]' | tail -1 | sed 's/.*= //')"
    echo "    ✓  Peer addresses  → converted (see peers list)"
    echo "    ✓  Timeouts       → propose/prevote/precommit"
    echo "    ✓  Mempool size   → ${MEMPOOL_SIZE:-?} entries"
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
}

main "$@"
