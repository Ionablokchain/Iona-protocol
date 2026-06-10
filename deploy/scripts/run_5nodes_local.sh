#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Local 5‑Node Network — Production‑Grade
# =============================================================================
#
# Pornește o rețea IONA completă de 5 noduri pe mașina locală pentru
# dezvoltare și testare.  Fiecare nod primește o configurație generată
# automat.
#
# Topologie:
#   val2 (producător, seed=2, p2p=7002, rpc=9002)
#   val3 (producător, seed=3, p2p=7003, rpc=9003)
#   val4 (producător, seed=4, p2p=7004, rpc=9004)
#   val1 (follower,   seed=1, p2p=7001, rpc=9001)
#   rpc  (public,     seed=100, p2p=7005, rpc=9000)
#
# Utilizare:
#   ./run_5nodes_local.sh [OPȚIUNI]
#
# Opțiuni:
#   --binary PATH       Calea către binarul iona‑node
#   --data-root DIR     Directorul rădăcină pentru date (implicit: ./data)
#   --skip-build        Nu recompila binarul
#   --log-level LEVEL   Nivelul de log (implicit: info)
#   --clean             Șterge datele existente înainte de pornire
#   --health-timeout SEC Timp maxim de așteptare pentru health check (implicit: 30)
#   --verbose           Output detaliat
#   --help              Afișează acest mesaj

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export RUST_LOG=${RUST_LOG:-info}

# ── Configurare implicită ───────────────────────────────────────────────────
BINARY="$ROOT_DIR/target/release/iona-node"
DATA_ROOT="$ROOT_DIR/data"
SKIP_BUILD=0
LOG_LEVEL="info"
CLEAN=0
HEALTH_TIMEOUT=30
VERBOSE=0

# ── Culori (sigure pentru non‑TTY) ──────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $*"; }
die()         { log_error "$*"; exit 1; }

# ── Parsare argumente ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)        BINARY="$2"; shift 2 ;;
        --data-root)     DATA_ROOT="$2"; shift 2 ;;
        --skip-build)    SKIP_BUILD=1; shift ;;
        --log-level)     LOG_LEVEL="$2"; shift 2 ;;
        --clean)         CLEAN=1; shift ;;
        --health-timeout) HEALTH_TIMEOUT="$2"; shift 2 ;;
        --verbose)       VERBOSE=1; shift ;;
        --help)
            sed -n '/^# Utilizare:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Opțiune necunoscută: $1 (încercați --help)" ;;
    esac
done

# ── Curățare date anterioare (dacă s-a cerut) ──────────────────────────────
if [[ "$CLEAN" -eq 1 ]]; then
    log_info "Curățare date existente..."
    rm -rf "$DATA_ROOT"/{val1,val2,val3,val4,rpc}
fi

mkdir -p "$DATA_ROOT"/{val1,val2,val3,val4,rpc}

# ── Funcție pentru generarea configurațiilor ────────────────────────────────
gen_config() {
    local name="$1" seed="$2" p2p_port="$3" rpc_port="$4" producer="$5"
    shift 5
    local peers_toml=""
    for p in "$@"; do
        if [[ -n "$peers_toml" ]]; then peers_toml="${peers_toml}, "; fi
        peers_toml="${peers_toml}\"${p}\""
    done

    cat > "$DATA_ROOT/${name}/config.toml" <<EOF
[node]
data_dir  = "${DATA_ROOT}/${name}"
seed      = ${seed}
chain_id  = 6126151
log_level = "${LOG_LEVEL}"

[consensus]
propose_timeout_ms   = 300
prevote_timeout_ms   = 200
precommit_timeout_ms = 200
max_txs_per_block    = 4096
gas_target           = 43000000
fast_quorum          = true
initial_base_fee     = 1
stake_each           = 1000
simple_producer      = ${producer}
validator_seeds      = [2, 3, 4]

[network]
listen = "/ip4/127.0.0.1/tcp/${p2p_port}"
peers  = [${peers_toml}]
bootnodes  = []
enable_mdns = false
enable_kad  = true
reconnect_s = 10

[mempool]
capacity = 200000

[rpc]
listen        = "127.0.0.1:${rpc_port}"
enable_faucet = true

[storage]
enable_snapshots        = true
snapshot_every_n_blocks = 500
snapshot_keep           = 5
snapshot_zstd_level     = 1
EOF
    log_verbose "Configurare generată pentru $name"
}

# ── Generare configurații pentru fiecare nod ────────────────────────────────
log_info "Generare configurații..."

# val2 (producător): peers = val3, val4, val1, rpc
gen_config val2 2 7002 9002 true \
    "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7004" \
    "/ip4/127.0.0.1/tcp/7001" \
    "/ip4/127.0.0.1/tcp/7005"

# val3 (producător): peers = val2, val4, val1, rpc
gen_config val3 3 7003 9003 true \
    "/ip4/127.0.0.1/tcp/7002" \
    "/ip4/127.0.0.1/tcp/7004" \
    "/ip4/127.0.0.1/tcp/7001" \
    "/ip4/127.0.0.1/tcp/7005"

# val4 (producător): peers = val2, val3, val1, rpc
gen_config val4 4 7004 9004 true \
    "/ip4/127.0.0.1/tcp/7002" \
    "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7001" \
    "/ip4/127.0.0.1/tcp/7005"

# val1 (follower): peers = val2, val3, val4, rpc
gen_config val1 1 7001 9001 false \
    "/ip4/127.0.0.1/tcp/7002" \
    "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7004" \
    "/ip4/127.0.0.1/tcp/7005"

# rpc (public): peers = val2, val3, val4
gen_config rpc 100 7005 9000 false \
    "/ip4/127.0.0.1/tcp/7002" \
    "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7004"

# ── Compilare (dacă este necesar) ───────────────────────────────────────────
if [[ "$SKIP_BUILD" -eq 0 ]]; then
    log_info "Compilare iona-node..."
    ( cd "$ROOT_DIR" && cargo build --release --locked --bin iona-node ) || die "Compilarea a eșuat"
else
    log_info "Se omite compilarea (--skip-build)"
fi

if [[ ! -x "$BINARY" ]]; then
    die "Binarul nu a fost găsit: $BINARY"
fi
log_info "Binar: $BINARY"

# ── Pornire noduri în ordinea corectă ──────────────────────────────────────
PIDS=()
cleanup() {
    echo ""
    log_info "Oprire toate nodurile..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    log_info "Toate nodurile au fost oprite."
}
trap cleanup INT TERM EXIT

echo ""
log_info "Pornire producători (val2, val3, val4)..."
( cd "$ROOT_DIR" && "$BINARY" --config "$DATA_ROOT/val2/config.toml" ) &
PIDS+=($!)
sleep 1
( cd "$ROOT_DIR" && "$BINARY" --config "$DATA_ROOT/val3/config.toml" ) &
PIDS+=($!)
sleep 1
( cd "$ROOT_DIR" && "$BINARY" --config "$DATA_ROOT/val4/config.toml" ) &
PIDS+=($!)
sleep 3

log_info "Pornire follower (val1)..."
( cd "$ROOT_DIR" && "$BINARY" --config "$DATA_ROOT/val1/config.toml" ) &
PIDS+=($!)
sleep 1

log_info "Pornire nod RPC..."
( cd "$ROOT_DIR" && "$BINARY" --config "$DATA_ROOT/rpc/config.toml" ) &
PIDS+=($!)

# ── Verificare health check ─────────────────────────────────────────────────
echo ""
log_info "Așteptare health check (timeout: ${HEALTH_TIMEOUT}s per nod)..."

NODES_HEALTH=("val2:9002" "val3:9003" "val4:9004" "val1:9001" "rpc:9000")
HEALTHY=0

for entry in "${NODES_HEALTH[@]}"; do
    node="${entry%%:*}"
    port="${entry##*:}"
    health_url="http://127.0.0.1:${port}/health"
    echo -n "  $node ($health_url) ... "

    ok=false
    for ((i=1; i<=HEALTH_TIMEOUT; i++)); do
        if curl -sf --max-time 2 "$health_url" >/dev/null 2>&1; then
            ok=true
            echo -e "${GREEN}OK${NC} (${i}s)"
            HEALTHY=$((HEALTHY + 1))
            break
        fi
        sleep 1
    done

    if [[ "$ok" == false ]]; then
        echo -e "${RED}FAILED${NC}"
    fi
done

# ── Sumar ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  IONA 5‑Node Local Network                                  ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  val2 (producător)  RPC: http://127.0.0.1:9002/health      ║"
echo "║  val3 (producător)  RPC: http://127.0.0.1:9003/health      ║"
echo "║  val4 (producător)  RPC: http://127.0.0.1:9004/health      ║"
echo "║  val1 (follower)    RPC: http://127.0.0.1:9001/health      ║"
echo "║  rpc  (public)      RPC: http://127.0.0.1:9000/health      ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Noduri sănătoase: $HEALTHY/5                                    ║"
echo "║  Apăsați Ctrl+C pentru a opri toate nodurile.               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

wait
