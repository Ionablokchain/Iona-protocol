#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Dev Reset — Controlled Chain Reset for Development/Testnet (Production‑Grade)
# =============================================================================
#
# Resets chain data while preserving or regenerating validator keys.
# Supports per‑node resets, automated pre‑reset backups, safety confirmations,
# and a dry‑run mode.
#
# Usage:
#   ./dev_reset.sh [OPTIONS]
#
# Options:
#   --full             Reset keys too (new chain identity)
#   --node NAME        Reset only the specified node (val1|val2|val3|val4|rpc)
#   --data-root DIR    Override data root (default: /var/lib/iona)
#   --backup-dir DIR   Directory for pre‑reset backups (default: /tmp/iona-reset-backups)
#   --dry-run          Show what would be deleted without actually doing it
#   --force            Skip confirmation prompts
#   --verbose          Enable detailed output
#   --help             Show this help
#
# Environment variables (fallback):
#   IONA_DATA_ROOT, IONA_BACKUP_DIR, IONA_FORCE, IONA_VERBOSE

# ── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_ROOT="${IONA_DATA_ROOT:-/var/lib/iona}"
BACKUP_DIR="${IONA_BACKUP_DIR:-/tmp/iona-reset-backups}"
FULL_RESET=false
TARGET_NODE=""
DRY_RUN=false
FORCE="${IONA_FORCE:-0}"
VERBOSE="${IONA_VERBOSE:-0}"

# Colours for output
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

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --full)        FULL_RESET=true; shift ;;
        --node)        TARGET_NODE="$2"; shift 2 ;;
        --data-root)   DATA_ROOT="$2"; shift 2 ;;
        --backup-dir)  BACKUP_DIR="$2"; shift 2 ;;
        --dry-run)     DRY_RUN=true; shift ;;
        --force)       FORCE=1; shift ;;
        --verbose)     VERBOSE=1; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Determine nodes to reset ─────────────────────────────────────────────────
NODES=("val1" "val2" "val3" "val4" "rpc")
if [[ -n "$TARGET_NODE" ]]; then
    # Validate node name
    if [[ ! " ${NODES[*]} " =~ " ${TARGET_NODE} " ]]; then
        die "Unknown node: $TARGET_NODE (valid: ${NODES[*]})"
    fi
    NODES=("$TARGET_NODE")
fi

# ── Safety checks ───────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  IONA Dev Reset                                                 ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
log_info "Data root:   $DATA_ROOT"
log_info "Full reset:  $FULL_RESET"
log_info "Nodes:       ${NODES[*]}"
log_info "Backup dir:  $BACKUP_DIR"
log_info "Dry run:     $DRY_RUN"
echo ""

# Check that services are stopped (skip if dry-run)
if [[ "$DRY_RUN" == false ]]; then
    for node in "${NODES[@]}"; do
        if systemctl is-active --quiet "iona-${node}" 2>/dev/null; then
            die "iona-${node} is still running. Stop it first: sudo systemctl stop iona-${node}"
        fi
    done
    log_info "All target services are stopped"
fi

# Confirmation (skip if --force or --dry-run)
if [[ "$FORCE" -eq 0 ]] && [[ "$DRY_RUN" == false ]]; then
    if [[ "$FULL_RESET" == true ]]; then
        log_warn "FULL reset requested — keys WILL be deleted!"
    fi
    echo -n "Proceed with reset? [y/N] "
    read -r answer
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        die "Aborted by user"
    fi
fi

# ── Pre‑reset backup ────────────────────────────────────────────────────────
if [[ "$DRY_RUN" == false ]]; then
    BACKUP_TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    mkdir -p "$BACKUP_DIR"
    log_info "Creating pre‑reset backups in $BACKUP_DIR"
fi

# ── Reset each node ─────────────────────────────────────────────────────────
for node in "${NODES[@]}"; do
    NODE_DIR="${DATA_ROOT}/${node}"

    if [[ ! -d "$NODE_DIR" ]]; then
        log_info "  [SKIP] $NODE_DIR does not exist"
        continue
    fi

    echo ""
    log_info "  [RESET] $node"

    # ── Backup keys (if preserving) ─────────────────────────────────────
    KEY_BACKUP_PATH=""
    if [[ "$FULL_RESET" == false ]] && [[ -f "$NODE_DIR/keys.json" ]]; then
        KEY_BACKUP_PATH="${BACKUP_DIR}/keys_${node}_${BACKUP_TIMESTAMP}.json"
        if [[ "$DRY_RUN" == false ]]; then
            cp "$NODE_DIR/keys.json" "$KEY_BACKUP_PATH"
            chmod 600 "$KEY_BACKUP_PATH"
            log_verbose "    keys.json backed up to $KEY_BACKUP_PATH"
        else
            log_info "    [DRY RUN] Would backup keys.json to $KEY_BACKUP_PATH"
        fi
    fi

    # ── Directories to remove ───────────────────────────────────────────
    DIRS_TO_REMOVE=("blocks" "wal" "snapshots" "receipts" "evidence" "tx_index")
    FILES_TO_REMOVE=("state_full.json" "stakes.json" "schema.json" "node_meta.json" "quarantine.json")

    for dir in "${DIRS_TO_REMOVE[@]}"; do
        if [[ -d "${NODE_DIR}/${dir}" ]]; then
            if [[ "$DRY_RUN" == false ]]; then
                rm -rf "${NODE_DIR:?}/${dir}"
                log_verbose "    Removed ${NODE_DIR}/${dir}"
            else
                log_info "    [DRY RUN] Would remove ${NODE_DIR}/${dir}"
            fi
        fi
    done

    for file in "${FILES_TO_REMOVE[@]}"; do
        if [[ -f "${NODE_DIR}/${file}" ]]; then
            if [[ "$DRY_RUN" == false ]]; then
                rm -f "${NODE_DIR:?}/${file}"
                log_verbose "    Removed ${NODE_DIR}/${file}"
            else
                log_info "    [DRY RUN] Would remove ${NODE_DIR}/${file}"
            fi
        fi
    done

    # ── Handle keys ─────────────────────────────────────────────────────
    if [[ "$FULL_RESET" == true ]]; then
        for key_file in "keys.json" "keys.json.enc"; do
            if [[ -f "${NODE_DIR}/${key_file}" ]]; then
                if [[ "$DRY_RUN" == false ]]; then
                    rm -f "${NODE_DIR:?}/${key_file}"
                    log_verbose "    Removed ${NODE_DIR}/${key_file}"
                else
                    log_info "    [DRY RUN] Would remove ${NODE_DIR}/${key_file}"
                fi
            fi
        done
        log_info "    Keys removed (full reset)"
    else
        # Restore keys from backup
        if [[ -n "$KEY_BACKUP_PATH" ]] && [[ "$DRY_RUN" == false ]]; then
            cp "$KEY_BACKUP_PATH" "$NODE_DIR/keys.json"
            chmod 600 "$NODE_DIR/keys.json"
            log_info "    Keys restored from backup"
        elif [[ "$DRY_RUN" == false ]]; then
            log_verbose "    No keys to restore"
        fi
    fi

    log_info "    done"
done

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Reset Complete                                                 ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

if [[ "$DRY_RUN" == true ]]; then
    log_info "DRY RUN — no changes were made."
else
    if [[ "$FULL_RESET" == true ]]; then
        log_warn "FULL reset: keys were removed. Nodes will generate new identities."
        log_warn "This means a NEW CHAIN — old data is incompatible."
    else
        log_info "Data reset: keys preserved. Nodes keep their identity."
    fi

    log_info "Backups saved to: $BACKUP_DIR"
    echo ""
    log_info "Start nodes in order: val2 → val3 → val4 → val1 → rpc"
    echo "  sudo systemctl start iona-val2"
    echo "  sleep 5"
    echo "  sudo systemctl start iona-val3"
    echo "  sleep 5"
    echo "  sudo systemctl start iona-val4"
    echo "  sleep 5"
    echo "  sudo systemctl start iona-val1"
    echo "  sudo systemctl start iona-rpc"
fi
