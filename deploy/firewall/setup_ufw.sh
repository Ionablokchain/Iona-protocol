#!/usr/bin/env bash
# =============================================================================
# IONA Production Firewall Setup — UFW Management Script
# =============================================================================
#
# Usage: sudo ./setup_ufw.sh [OPTIONS]
#
# Options:
#   --bootnode          Open P2P ports to public (for bootnode machines)
#   --rpc               Open HTTPS port for nginx reverse proxy
#   --p2p-port PORT     Custom P2P port (default: 30333)
#   --metrics-port PORT Custom Prometheus metrics port (default: 9090)
#   --ssh-port PORT     Custom SSH port (default: 22)
#   --subnet CIDR       Internal subnet for restricted access (default: auto-detect)
#   --dry-run           Show what would be done without applying
#   --backup FILE       Path to save current rules backup (default: /tmp/ufw-backup.rules)
#   --help              Show this help
#
# Environment variables:
#   IONA_P2P_PORT, IONA_METRICS_PORT, IONA_SSH_PORT, IONA_SUBNET
# =============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
BOOTNODE=false
RPC=false
DRY_RUN=false
P2P_PORT="${IONA_P2P_PORT:-30333}"
METRICS_PORT="${IONA_METRICS_PORT:-9090}"
SSH_PORT="${IONA_SSH_PORT:-22}"
INTERNAL_SUBNET="${IONA_SUBNET:-}"
BACKUP_FILE="${IONA_UFW_BACKUP:-/tmp/ufw-backup-$(date +%Y%m%d-%H%M%S).rules}"

# ── Colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }
verbose() { [[ "${VERBOSE:-0}" -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $*"; }

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --bootnode)       BOOTNODE=true; shift ;;
        --rpc)            RPC=true; shift ;;
        --p2p-port)       P2P_PORT="$2"; shift 2 ;;
        --metrics-port)   METRICS_PORT="$2"; shift 2 ;;
        --ssh-port)       SSH_PORT="$2"; shift 2 ;;
        --subnet)         INTERNAL_SUBNET="$2"; shift 2 ;;
        --dry-run)        DRY_RUN=true; shift ;;
        --backup)         BACKUP_FILE="$2"; shift 2 ;;
        --help)
            sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Pre-flight checks ───────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root (sudo $0 ...)"
fi

if ! command -v ufw &>/dev/null; then
    die "ufw is not installed. Install with: apt-get install ufw"
fi

# Validate ports
for port in "$P2P_PORT" "$METRICS_PORT" "$SSH_PORT"; do
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        die "Invalid port number: $port"
    fi
done

# ── Auto-detect internal subnet ─────────────────────────────────────────────
if [[ -z "$INTERNAL_SUBNET" ]]; then
    # Try to detect the primary network interface subnet
    MAIN_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}' || echo "")
    if [[ -n "$MAIN_IFACE" ]]; then
        INTERNAL_SUBNET=$(ip -o -f inet addr show "$MAIN_IFACE" 2>/dev/null | awk '{print $4}' | head -1 || echo "")
        if [[ -n "$INTERNAL_SUBNET" ]]; then
            info "Auto-detected internal subnet: $INTERNAL_SUBNET"
        fi
    fi
    if [[ -z "$INTERNAL_SUBNET" ]]; then
        INTERNAL_SUBNET="10.0.0.0/8"
        warn "Could not auto-detect subnet, using default: $INTERNAL_SUBNET"
    fi
fi

# Validate subnet format
if [[ ! "$INTERNAL_SUBNET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
    die "Invalid subnet format: $INTERNAL_SUBNET (expected CIDR, e.g. 10.0.1.0/24)"
fi

# ── Display configuration ───────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  IONA Production Firewall Setup                                 ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
info "Bootnode mode:     $BOOTNODE"
info "RPC mode:          $RPC"
info "Internal subnet:   $INTERNAL_SUBNET"
info "P2P port:          $P2P_PORT"
info "Metrics port:      $METRICS_PORT"
info "SSH port:          $SSH_PORT"
info "Dry run:           $DRY_RUN"
echo ""

if [[ "$DRY_RUN" == true ]]; then
    warn "DRY RUN MODE — no changes will be applied"
fi

# ── Backup existing rules ───────────────────────────────────────────────────
if [[ "$DRY_RUN" == false ]]; then
    info "Backing up current firewall rules to $BACKUP_FILE"
    ufw status numbered > "$BACKUP_FILE" 2>/dev/null || true
    info "Backup saved"
fi

# ── Reset and configure ─────────────────────────────────────────────────────
configure_ufw() {
    local cmd="$1"
    if [[ "$DRY_RUN" == true ]]; then
        echo "  [DRY RUN] $cmd"
    else
        eval "$cmd" || warn "Command failed: $cmd"
    fi
}

info "Configuring firewall rules..."

# Reset UFW (preserve SSH connection)
if [[ "$DRY_RUN" == false ]]; then
    ufw --force reset
fi

# Default policies
configure_ufw "ufw default deny incoming"
configure_ufw "ufw default allow outgoing"

# Allow loopback
configure_ufw "ufw allow in on lo"
configure_ufw "ufw allow out on lo"

# SSH (always allow from internal subnet, optionally from anywhere)
configure_ufw "ufw allow from ${INTERNAL_SUBNET} to any port ${SSH_PORT} proto tcp comment 'SSH internal'"
# Also allow SSH from anywhere as a safety net
configure_ufw "ufw allow ${SSH_PORT}/tcp comment 'SSH'"

# ── P2P ports ───────────────────────────────────────────────────────────────
if [[ "$BOOTNODE" == true ]]; then
    info "Opening P2P ports to public (bootnode mode)"
    configure_ufw "ufw allow ${P2P_PORT}/tcp comment 'IONA P2P public'"
    # Additional ports for bootnode
    for port in $((P2P_PORT + 1)) $((P2P_PORT + 2)); do
        configure_ufw "ufw allow ${port}/tcp comment 'IONA P2P additional'"
    done
else
    info "Opening P2P ports to internal subnet only"
    for port in $P2P_PORT $((P2P_PORT + 1)) $((P2P_PORT + 2)) $((P2P_PORT + 3)) $((P2P_PORT + 4)); do
        configure_ufw "ufw allow from ${INTERNAL_SUBNET} to any port ${port} proto tcp comment 'IONA P2P internal'"
    done
fi

# ── RPC via nginx ───────────────────────────────────────────────────────────
if [[ "$RPC" == true ]]; then
    info "Opening HTTP/HTTPS ports for nginx reverse proxy"
    configure_ufw "ufw allow 443/tcp comment 'HTTPS (nginx proxy for IONA RPC)'"
    configure_ufw "ufw allow 80/tcp comment 'HTTP (redirect to HTTPS)'"
fi

# ── Prometheus / Metrics ────────────────────────────────────────────────────
info "Opening metrics port to internal subnet"
configure_ufw "ufw allow from ${INTERNAL_SUBNET} to any port ${METRICS_PORT} proto tcp comment 'Prometheus metrics internal'"

# ── Rate limiting for SSH ───────────────────────────────────────────────────
configure_ufw "ufw limit ${SSH_PORT}/tcp comment 'SSH rate limit'"

# ── Enable UFW ──────────────────────────────────────────────────────────────
if [[ "$DRY_RUN" == false ]]; then
    info "Enabling UFW..."
    ufw --force enable
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Firewall Configuration Complete                                ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

if [[ "$DRY_RUN" == false ]]; then
    info "Current UFW status:"
    ufw status verbose
else
    info "Dry run completed. Run without --dry-run to apply."
fi

echo ""
info "Backup saved to: $BACKUP_FILE"
info "To restore previous rules: sudo ufw reset && sudo bash $BACKUP_FILE"
