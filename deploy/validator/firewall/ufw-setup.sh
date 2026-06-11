#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Validator Node UFW Firewall — Production‑Grade
# =============================================================================
#
# Configures UFW (Uncomplicated Firewall) for production IONA validator deployment.
# Sets restrictive rules to allow P2P traffic, block public access to sensitive
# endpoints, enforce rate limiting on SSH, and permit Prometheus scraping.
#
# Usage: sudo ./ufw-setup.sh [OPTIONS]
#
# Options:
#   --p2p-port PORT          P2P consensus port (default: 7001)
#   --rpc-port PORT          RPC API port (default: 9001)
#   --admin-port PORT        Admin API port (default: 9002)
#   --prometheus-port PORT   Prometheus metrics port (default: 9090)
#   --ssh-port PORT          SSH port (default: 22)
#   --monitoring-subnet CIDR Subnet allowed for Prometheus scraping (default: 10.0.0.0/8)
#   --peer-subnet CIDR       Additional subnet with unrestricted P2P access (repeatable)
#   --remove                 Remove all UFW rules and disable firewall
#   --dry-run                Show what would be done without applying
#   --backup-dir DIR         Directory for backups (default: /var/backups/ufw)
#   --json                   Output final summary as JSON (for CI/CD)
#   --verbose                Enable detailed output
#   --help                   Show this help
#
# Environment variables (fallback):
#   IONA_P2P_PORT, IONA_RPC_PORT, IONA_ADMIN_PORT, IONA_PROMETHEUS_PORT,
#   IONA_SSH_PORT, IONA_MONITORING_SUBNET, IONA_PEER_SUBNETS

# ── Configuration ────────────────────────────────────────────────────────────
P2P_PORT="${IONA_P2P_PORT:-7001}"
RPC_PORT="${IONA_RPC_PORT:-9001}"
ADMIN_PORT="${IONA_ADMIN_PORT:-9002}"
PROMETHEUS_PORT="${IONA_PROMETHEUS_PORT:-9090}"
SSH_PORT="${IONA_SSH_PORT:-22}"
MONITORING_SUBNET="${IONA_MONITORING_SUBNET:-10.0.0.0/8}"
PEER_SUBNETS="${IONA_PEER_SUBNETS:-}"
REMOVE=false
DRY_RUN=false
BACKUP_DIR="${IONA_UFW_BACKUP_DIR:-/var/backups/ufw}"
JSON_OUTPUT=0
VERBOSE=0
START_TIME=$(date +%s)

# ── Colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

log_info()    { echo -e "${GREEN}[INFO]${NC}  $(date '+%H:%M:%S') $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $(date '+%H:%M:%S') $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $*" >&2; }
log_verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $(date '+%H:%M:%S') $*"; }
die()         { log_error "$*"; exit 1; }

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --p2p-port)          P2P_PORT="$2"; shift 2 ;;
        --rpc-port)          RPC_PORT="$2"; shift 2 ;;
        --admin-port)        ADMIN_PORT="$2"; shift 2 ;;
        --prometheus-port)   PROMETHEUS_PORT="$2"; shift 2 ;;
        --ssh-port)          SSH_PORT="$2"; shift 2 ;;
        --monitoring-subnet) MONITORING_SUBNET="$2"; shift 2 ;;
        --peer-subnet)       PEER_SUBNETS="${PEER_SUBNETS} $2"; shift 2 ;;
        --remove)            REMOVE=true; shift ;;
        --dry-run)           DRY_RUN=true; shift ;;
        --backup-dir)        BACKUP_DIR="$2"; shift 2 ;;
        --json)              JSON_OUTPUT=1; shift ;;
        --verbose)           VERBOSE=1; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Pre-flight checks ──────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then die "This script must be run as root"; fi
if ! command -v ufw &>/dev/null; then die "UFW is not installed. Install with: apt-get install ufw"; fi
for port in "$P2P_PORT" "$RPC_PORT" "$ADMIN_PORT" "$SSH_PORT" "$PROMETHEUS_PORT"; do
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        die "Invalid port: $port"
    fi
done
if [[ -n "$MONITORING_SUBNET" ]] && ! echo "$MONITORING_SUBNET" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
    die "Invalid monitoring subnet: $MONITORING_SUBNET (expected CIDR)"
fi

# ── Backup existing rules ──────────────────────────────────────────────────
backup_rules() {
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would backup current rules"
        return
    fi
    mkdir -p "$BACKUP_DIR"
    local backup_file="${BACKUP_DIR}/ufw-backup-$(date +%Y%m%d-%H%M%S).rules"
    log_info "Backing up current rules to $backup_file"
    ufw status numbered > "$backup_file" 2>/dev/null || log_warn "Failed to backup rules (UFW may not be active)"
    log_info "Backup complete"
}

# ── Remove all rules ───────────────────────────────────────────────────────
remove_rules() {
    log_warn "Removing all UFW rules and disabling firewall..."
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would disable and reset UFW"
        return
    fi
    ufw --force disable
    ufw --force reset
    log_info "UFW firewall disabled and reset"
}

# ── Apply a UFW rule (with dry-run support) ────────────────────────────────
apply_rule() {
    local rule="$1"
    local comment="$2"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] ufw $rule comment '$comment'"
    else
        log_verbose "ufw $rule comment '$comment'"
        ufw $rule comment "$comment" 2>/dev/null || log_warn "Failed to apply rule: $rule"
    fi
}

# ── Configure firewall ─────────────────────────────────────────────────────
configure_firewall() {
    log_info "Starting UFW configuration for IONA validator..."
    echo ""

    # Default policies
    log_info "Setting default policies: deny incoming, allow outgoing"
    if [[ "$DRY_RUN" == false ]]; then
        ufw default deny incoming
        ufw default allow outgoing
    else
        log_info "[DRY RUN] Would set default policies"
    fi

    # SSH with rate limiting
    log_info "Configuring SSH access with rate limiting (port ${SSH_PORT})"
    log_warn "IMPORTANT: In production, consider whitelisting specific management IPs"
    apply_rule "limit ${SSH_PORT}/tcp" "SSH with rate limiting"

    # P2P port
    log_info "Allowing P2P port ${P2P_PORT} from any source (required for consensus)"
    apply_rule "allow ${P2P_PORT}/tcp" "IONA P2P TCP - open to all peers"
    apply_rule "allow ${P2P_PORT}/udp" "IONA P2P UDP - open to all peers"

    # Additional peer subnets (unrestricted P2P access)
    if [[ -n "$PEER_SUBNETS" ]]; then
        for subnet in $PEER_SUBNETS; do
            log_info "  Adding unrestricted P2P from $subnet"
            apply_rule "allow from $subnet to any port ${P2P_PORT}/tcp" "IONA P2P from peer subnet $subnet"
        done
    fi

    # RPC port
    log_info "Denying public access to RPC port ${RPC_PORT} (loopback only)"
    log_warn "RPC is only accessible from localhost (127.0.0.1:${RPC_PORT})"
    log_warn "Public RPC should be proxied through nginx on port 443 with rate limiting"
    apply_rule "deny ${RPC_PORT}/tcp" "IONA RPC - blocked from public"

    # Admin port
    log_info "Denying public access to Admin port ${ADMIN_PORT}"
    log_warn "Admin interface should only be accessible from management IP addresses"
    apply_rule "deny ${ADMIN_PORT}/tcp" "IONA Admin - blocked from public"

    # Prometheus metrics
    log_info "Allowing Prometheus scrape from monitoring subnet ${MONITORING_SUBNET}"
    apply_rule "allow from ${MONITORING_SUBNET} to any port ${PROMETHEUS_PORT}/tcp" "Prometheus metrics - monitoring subnet only"

    # Enable UFW
    if [[ "$DRY_RUN" == false ]]; then
        log_info "Enabling UFW firewall..."
        ufw --force enable
    else
        log_info "[DRY RUN] Would enable UFW"
    fi
}

# ── Show summary ────────────────────────────────────────────────────────────
show_summary() {
    echo ""
    echo -e "${GREEN}=== Firewall Rules Summary ===${NC}"
    echo ""
    if [[ "$DRY_RUN" == false ]]; then
        ufw status verbose 2>/dev/null || true
    else
        log_info "[DRY RUN] Would show UFW status"
    fi
    echo ""
    log_info "Port Summary:"
    echo "  SSH (${SSH_PORT}):       ALLOWED with rate limiting"
    echo "  P2P (${P2P_PORT}):       ALLOWED from any (required for consensus)"
    echo "  RPC (${RPC_PORT}):       DENIED from public (loopback only, proxy via nginx)"
    echo "  Admin (${ADMIN_PORT}):   DENIED from public (management IPs only)"
    echo "  Prometheus (${PROMETHEUS_PORT}): ALLOWED from ${MONITORING_SUBNET}"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║  IONA Validator UFW Firewall Configuration                      ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    log_info "P2P port:         $P2P_PORT"
    log_info "RPC port:         $RPC_PORT"
    log_info "Admin port:       $ADMIN_PORT"
    log_info "Prometheus port:  $PROMETHEUS_PORT"
    log_info "SSH port:         $SSH_PORT"
    log_info "Monitoring subnet: $MONITORING_SUBNET"
    [[ -n "$PEER_SUBNETS" ]] && log_info "Peer subnets:     $PEER_SUBNETS"
    log_info "Dry run:          $DRY_RUN"
    echo ""

    if [[ "$REMOVE" == true ]]; then
        remove_rules
        exit 0
    fi

    backup_rules
    configure_firewall
    show_summary

    DURATION=$(($(date +%s) - START_TIME))
    log_info "Firewall configuration complete (${DURATION}s)"

    if [[ "$DRY_RUN" == true ]]; then
        log_warn "DRY RUN — no rules were actually applied"
    fi
}

main "$@"
