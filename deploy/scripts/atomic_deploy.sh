#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Atomic Deploy — Zero‑Downtime Binary Upgrade (Production‑Grade)
# =============================================================================
#
# Performs a rolling, zero‑downtime upgrade of IONA validator nodes.
# Each node is stopped, the binary is atomically replaced, the node is
# restarted, and a health check confirms the upgrade succeeded.
# If the health check fails, the previous binary is automatically restored.
#
# Usage:
#   ./atomic_deploy.sh [OPTIONS] <node_name|all> <path_to_new_binary>
#
# Options:
#   --skip-health-check    Skip post‑deploy health verification
#   --skip-backup          Skip automatic backup of the current binary
#   --skip-version-check   Skip version compatibility verification
#   --health-timeout SEC   Health check timeout in seconds (default: 30)
#   --service-prefix NAME  Systemd service prefix (default: iona)
#   --install-dir DIR      Binary installation directory (default: /usr/local/bin)
#   --lock-file PATH       Path to lock file (default: /tmp/iona-deploy.lock)
#   --log-file PATH        Path to deployment log (default: /var/log/iona-deploy.log)
#   --verbose              Enable detailed output
#   --help                 Show this help
#
# Environment variables (fallback):
#   IONA_SKIP_HEALTH_CHECK, IONA_SKIP_BACKUP, IONA_SKIP_VERSION_CHECK,
#   IONA_HEALTH_TIMEOUT, IONA_SERVICE_PREFIX, IONA_INSTALL_DIR,
#   IONA_LOCK_FILE, IONA_DEPLOY_LOG

# ── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${IONA_INSTALL_DIR:-/usr/local/bin}"
SERVICE_PREFIX="${IONA_SERVICE_PREFIX:-iona}"
HEALTH_TIMEOUT="${IONA_HEALTH_TIMEOUT:-30}"
LOCK_FILE="${IONA_LOCK_FILE:-/tmp/iona-deploy.lock}"
LOG_FILE="${IONA_DEPLOY_LOG:-/var/log/iona-deploy.log}"
SKIP_HEALTH_CHECK="${IONA_SKIP_HEALTH_CHECK:-0}"
SKIP_BACKUP="${IONA_SKIP_BACKUP:-0}"
SKIP_VERSION_CHECK="${IONA_SKIP_VERSION_CHECK:-0}"
VERBOSE="${IONA_VERBOSE:-0}"

NODE_NAME=""
NEW_BINARY=""
DEPLOY_START_TIME=$(date +%s)

# ── Colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

# ── Logging ─────────────────────────────────────────────────────────────────
log_info()    { echo -e "${GREEN}[INFO]${NC}  $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" >&2; }
log_verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE"; }

die() { log_error "$*"; release_lock; exit 1; }

# ── Lock file (prevents concurrent deploys) ─────────────────────────────────
acquire_lock() {
    mkdir -p "$(dirname "$LOCK_FILE")"
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            die "Another deploy is already running (PID $pid). Remove $LOCK_FILE if stale."
        fi
    fi
    echo $$ > "$LOCK_FILE"
    log_verbose "Lock acquired: $LOCK_FILE"
}

release_lock() {
    rm -f "$LOCK_FILE"
    log_verbose "Lock released: $LOCK_FILE"
}

# ── Parse arguments ─────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-health-check)  SKIP_HEALTH_CHECK=1; shift ;;
            --skip-backup)        SKIP_BACKUP=1; shift ;;
            --skip-version-check) SKIP_VERSION_CHECK=1; shift ;;
            --health-timeout)     HEALTH_TIMEOUT="$2"; shift 2 ;;
            --service-prefix)     SERVICE_PREFIX="$2"; shift 2 ;;
            --install-dir)        INSTALL_DIR="$2"; shift 2 ;;
            --lock-file)          LOCK_FILE="$2"; shift 2 ;;
            --log-file)           LOG_FILE="$2"; shift 2 ;;
            --verbose)            VERBOSE=1; shift ;;
            --help)
                sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
                exit 0
                ;;
            -*)
                die "Unknown option: $1 (use --help)"
                ;;
            *)
                if [[ -z "$NODE_NAME" ]]; then
                    NODE_NAME="$1"
                elif [[ -z "$NEW_BINARY" ]]; then
                    NEW_BINARY="$1"
                else
                    die "Unexpected argument: $1"
                fi
                shift
                ;;
        esac
    done

    if [[ -z "$NODE_NAME" ]] || [[ -z "$NEW_BINARY" ]]; then
        echo "Usage: $0 [OPTIONS] <node_name|all> <path_to_new_binary>"
        echo "  Example: $0 val2 ./target/release/iona-node"
        exit 1
    fi
}

# ── Validate binary ─────────────────────────────────────────────────────────
validate_binary() {
    local binary="$1"

    if [[ ! -f "$binary" ]]; then
        die "Binary not found: $binary"
    fi

    if [[ ! -x "$binary" ]]; then
        chmod +x "$binary" || die "Cannot make binary executable: $binary"
        log_verbose "Made binary executable: $binary"
    fi

    # Quick sanity check: binary must be an ELF file
    if command -v file &>/dev/null; then
        if ! file "$binary" | grep -q "ELF"; then
            die "Binary is not a valid ELF file: $binary"
        fi
    fi

    log_info "Binary validated: $binary"
}

# ── Get version from binary ─────────────────────────────────────────────────
get_version() {
    local binary="$1"
    if [[ -x "$binary" ]]; then
        "$binary" --version 2>/dev/null | grep -oP 'v?\d+\.\d+\.\d+' | head -1 || echo "unknown"
    else
        echo "unknown"
    fi
}

# ── RPC port mapping ────────────────────────────────────────────────────────
get_rpc_port() {
    local node="$1"
    case "$node" in
        val1) echo 9001 ;;
        val2) echo 9002 ;;
        val3) echo 9003 ;;
        val4) echo 9004 ;;
        rpc)  echo 9000 ;;
        *)    echo 9001 ;;
    esac
}

# ── Deploy a single node ────────────────────────────────────────────────────
deploy_node() {
    local node="$1"
    local service="${SERVICE_PREFIX}-${node}"
    local target="${INSTALL_DIR}/iona-node"
    local rpc_port
    rpc_port=$(get_rpc_port "$node")
    local backup_path="${target}.backup.$(date +%Y%m%d-%H%M%S)"
    local failed=false

    echo ""
    echo "================================================================"
    echo "  Deploying to: $node (service: $service, port: $rpc_port)"
    echo "================================================================"
    log_info "Starting deploy to $node"

    # ── Get current version ──────────────────────────────────────────────
    local old_version new_version
    old_version=$(get_version "$target" 2>/dev/null || echo "not-installed")
    new_version=$(get_version "$NEW_BINARY" 2>/dev/null || echo "unknown")
    log_info "Current version: $old_version"
    log_info "New version:     $new_version"

    # ── Version check ────────────────────────────────────────────────────
    if [[ "$SKIP_VERSION_CHECK" -eq 0 ]]; then
        if [[ "$old_version" == "$new_version" ]] && [[ "$old_version" != "unknown" ]]; then
            log_warn "New binary has same version as current ($old_version). Use --skip-version-check to force."
        fi
    fi

    # ── Step 1: Stop service ────────────────────────────────────────────
    log_info "[1/6] Stopping $service..."
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        systemctl stop "$service" || log_warn "Failed to stop $service gracefully"
        # Wait for clean shutdown
        local stopped=false
        for i in $(seq 1 15); do
            if ! systemctl is-active --quiet "$service" 2>/dev/null; then
                stopped=true
                break
            fi
            sleep 1
        done
        if [[ "$stopped" == false ]]; then
            log_warn "Service did not stop gracefully after 15s, forcing kill..."
            systemctl kill -s KILL "$service" 2>/dev/null || true
            sleep 1
        fi
        log_info "Service stopped"
    else
        log_info "Service not running, skipping stop."
    fi

    # ── Step 2: Backup current binary ───────────────────────────────────
    if [[ "$SKIP_BACKUP" -eq 0 ]] && [[ -f "$target" ]]; then
        log_info "[2/6] Backing up current binary to $backup_path"
        cp "$target" "$backup_path" || die "Backup failed"
        chmod +x "$backup_path"
        log_info "Backup created"
    else
        log_info "[2/6] Backup skipped ($([[ "$SKIP_BACKUP" -eq 1 ]] && echo "--skip-backup" || echo "no existing binary"))"
        backup_path=""
    fi

    # ── Step 3: Atomic install ──────────────────────────────────────────
    log_info "[3/6] Installing binary atomically..."
    local tmp_binary="${target}.new.$$"
    cp "$NEW_BINARY" "$tmp_binary" || die "Failed to copy binary"
    chmod +x "$tmp_binary"
    # Atomic rename: mv on the same filesystem is atomic on Linux
    mv "$tmp_binary" "$target" || die "Failed to install binary"
    log_info "Binary installed: $target"

    # ── Step 4: Verify binary ───────────────────────────────────────────
    log_info "[4/6] Verifying binary..."
    if "$target" --help >/dev/null 2>&1; then
        log_info "Binary verification passed"
    else
        log_warn "Binary --help returned non-zero (may still work)"
    fi

    # ── Step 5: Start service ───────────────────────────────────────────
    log_info "[5/6] Starting $service..."
    systemctl start "$service" || {
        log_error "Failed to start service"
        failed=true
    }

    # ── Step 6: Health check ────────────────────────────────────────────
    if [[ "$failed" == false ]]; then
        if [[ "$SKIP_HEALTH_CHECK" -eq 0 ]]; then
            log_info "[6/6] Waiting for health check (timeout: ${HEALTH_TIMEOUT}s)..."
            local ok=false
            for i in $(seq 1 "$HEALTH_TIMEOUT"); do
                if curl -sf "http://127.0.0.1:${rpc_port}/health" >/dev/null 2>&1; then
                    ok=true
                    log_info "Health check passed after ${i}s"
                    break
                fi
                if [[ $((i % 10)) -eq 0 ]]; then
                    log_info "  Still waiting... ($i/${HEALTH_TIMEOUT}s)"
                fi
                sleep 1
            done

            if [[ "$ok" == false ]]; then
                log_error "Health check failed after ${HEALTH_TIMEOUT}s"
                failed=true
            fi
        else
            log_info "[6/6] Health check skipped (--skip-health-check)"
        fi
    fi

    # ── Rollback on failure ───────────────────────────────────────────────
    if [[ "$failed" == true ]]; then
        log_error "Deploy to $node FAILED"
        if [[ -n "$backup_path" ]] && [[ -f "$backup_path" ]]; then
            log_warn "Rolling back to previous binary..."
            systemctl stop "$service" 2>/dev/null || true
            sleep 2
            cp "$backup_path" "$target" || log_error "ROLLBACK FAILED! Manual intervention required."
            chmod +x "$target"
            systemctl start "$service" 2>/dev/null || log_error "Failed to start service after rollback"
            log_info "Rollback complete. Previous binary restored."
        else
            log_error "No backup available for rollback. Manual intervention required!"
        fi
        release_lock
        exit 1
    fi

    log_info "Deploy to $node COMPLETED successfully"
    echo "  === $node deployed ($old_version → $new_version) ==="
}

# ── Rolling deploy (all nodes) ──────────────────────────────────────────────
rolling_deploy_all() {
    local deploy_order=("val2" "val3" "val4" "val1" "rpc")
    local total=${#deploy_order[@]}
    local current=0

    echo ""
    echo "================================================================"
    echo "  Rolling Deploy (all $total nodes)"
    echo "  Order: ${deploy_order[*]}"
    echo "  Waiting 10s between nodes for quorum stability."
    echo "================================================================"
    log_info "Starting rolling deploy of $total nodes"

    for node in "${deploy_order[@]}"; do
        current=$((current + 1))
        echo ""
        log_info "Node $current/$total: $node"
        deploy_node "$node"

        if [[ "$node" != "rpc" ]] && [[ "$current" -lt "$total" ]]; then
            log_info "Waiting 10s before next node..."
            sleep 10
        fi
    done

    echo ""
    echo "================================================================"
    echo "  Rolling Deploy Complete ($total nodes)"
    echo "================================================================"
    log_info "Rolling deploy of all nodes completed"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    mkdir -p "$(dirname "$LOG_FILE")"
    log_info "IONA Atomic Deploy started (PID: $$)"

    parse_args "$@"
    acquire_lock
    validate_binary "$NEW_BINARY"

    if [[ "$NODE_NAME" == "all" ]]; then
        rolling_deploy_all
    else
        deploy_node "$NODE_NAME"
    fi

    local duration
    duration=$(($(date +%s) - DEPLOY_START_TIME))
    log_info "Deploy completed in ${duration}s"
    release_lock
}

