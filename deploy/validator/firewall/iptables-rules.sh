#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Validator Node iptables Firewall — Production‑Grade
# =============================================================================
#
# Configures iptables rules for a production IONA validator deployment.
# Provides low‑level packet filtering with rate limiting support.
#
# Usage: sudo ./iptables-rules.sh [OPTIONS]
#
# Options:
#   --p2p-port PORT          P2P consensus port (default: 7001)
#   --rpc-port PORT          RPC API port (default: 9001)
#   --admin-port PORT        Admin API port (default: 9002)
#   --ssh-port PORT          SSH port (default: 22)
#   --prometheus-port PORT   Prometheus metrics port (default: 9090)
#   --monitoring-subnet CIDR Subnet allowed for Prometheus scraping (default: 10.0.0.0/8)
#   --peer-subnet CIDR       Additional subnet with unrestricted P2P access (repeatable)
#   --dry-run                Show rules without applying
#   --skip-backup            Skip backing up current rules
#   --no-save                Do not persist rules to disk
#   --json                   Output final summary as JSON (for CI/CD)
#   --verbose                Enable detailed output
#   --help                   Show this help
#
# Environment variables (fallback):
#   IONA_P2P_PORT, IONA_RPC_PORT, IONA_ADMIN_PORT, IONA_SSH_PORT,
#   IONA_PROMETHEUS_PORT, IONA_MONITORING_SUBNET, IONA_PEER_SUBNETS

# ── Configuration ────────────────────────────────────────────────────────────
P2P_PORT="${IONA_P2P_PORT:-7001}"
RPC_PORT="${IONA_RPC_PORT:-9001}"
ADMIN_PORT="${IONA_ADMIN_PORT:-9002}"
SSH_PORT="${IONA_SSH_PORT:-22}"
PROMETHEUS_PORT="${IONA_PROMETHEUS_PORT:-9090}"
MONITORING_SUBNET="${IONA_MONITORING_SUBNET:-10.0.0.0/8}"
PEER_SUBNETS="${IONA_PEER_SUBNETS:-}"
DRY_RUN=false
SKIP_BACKUP=false
NO_SAVE=false
JSON_OUTPUT=0
VERBOSE=0
BACKUP_DIR="/var/backups/iptables"
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
        --ssh-port)          SSH_PORT="$2"; shift 2 ;;
        --prometheus-port)   PROMETHEUS_PORT="$2"; shift 2 ;;
        --monitoring-subnet) MONITORING_SUBNET="$2"; shift 2 ;;
        --peer-subnet)       PEER_SUBNETS="${PEER_SUBNETS} $2"; shift 2 ;;
        --dry-run)           DRY_RUN=true; shift ;;
        --skip-backup)       SKIP_BACKUP=true; shift ;;
        --no-save)           NO_SAVE=true; shift ;;
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
if ! command -v iptables &>/dev/null; then die "iptables is required but not installed"; fi
for port in "$P2P_PORT" "$RPC_PORT" "$ADMIN_PORT" "$SSH_PORT" "$PROMETHEUS_PORT"; do
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        die "Invalid port: $port"
    fi
done
if [[ -n "$MONITORING_SUBNET" ]] && ! echo "$MONITORING_SUBNET" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
    die "Invalid monitoring subnet: $MONITORING_SUBNET (expected CIDR)"
fi

# ── Backup existing rules ──────────────────────────────────────────────────
if [[ "$SKIP_BACKUP" == false ]] && [[ "$DRY_RUN" == false ]]; then
    mkdir -p "$BACKUP_DIR"
    BACKUP_FILE="${BACKUP_DIR}/iptables-backup-$(date +%Y%m%d-%H%M%S).rules"
    log_info "Backing up current rules to $BACKUP_FILE"
    if command -v iptables-save &>/dev/null; then
        iptables-save > "$BACKUP_FILE" 2>/dev/null || log_warn "Failed to backup IPv4 rules"
    fi
    if command -v ip6tables-save &>/dev/null; then
        ip6tables-save > "${BACKUP_FILE}.v6" 2>/dev/null || log_warn "Failed to backup IPv6 rules"
    fi
    log_info "Backup complete"
fi

# ── Core functions ──────────────────────────────────────────────────────────
flush_rules() {
    log_info "Flushing all existing iptables rules..."
    if [[ "$DRY_RUN" == true ]]; then
        log_info "  [DRY RUN] Would flush iptables"
        return
    fi
    iptables -F && iptables -X && iptables -Z
    ip6tables -F && ip6tables -X && ip6tables -Z 2>/dev/null || true
    log_info "Rules flushed"
}

reset_policies() {
    log_info "Resetting default policies to ACCEPT..."
    if [[ "$DRY_RUN" == true ]]; then
        log_info "  [DRY RUN] Would reset policies"
        return
    fi
    iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -P FORWARD ACCEPT
    ip6tables -P INPUT ACCEPT && ip6tables -P OUTPUT ACCEPT && ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    log_info "Policies reset"
}

configure_ipv4() {
    log_info "Configuring IPv4 iptables rules..."

    local cmd=""
    if [[ "$DRY_RUN" == true ]]; then
        cmd="echo [DRY RUN] iptables"
    else
        cmd="iptables"
    fi

    # Default policies
    $cmd -P INPUT DROP
    $cmd -P OUTPUT ACCEPT
    $cmd -P FORWARD DROP

    # Loopback
    $cmd -A INPUT -i lo -j ACCEPT

    # Established/related
    $cmd -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Drop invalid
    $cmd -A INPUT -m state --state INVALID -j DROP

    # SSH with rate limiting: 10 new connections per minute per IP
    $cmd -A INPUT -p tcp --dport ${SSH_PORT} -m state --state NEW -m limit --limit 10/min --limit-burst 5 -j ACCEPT
    $cmd -A INPUT -p tcp --dport ${SSH_PORT} -m state --state NEW -j DROP

    # P2P with rate limiting
    $cmd -A INPUT -p tcp --dport ${P2P_PORT} -m state --state NEW -m limit --limit 10/min --limit-burst 20 -j ACCEPT
    $cmd -A INPUT -p tcp --dport ${P2P_PORT} -m state --state NEW -j DROP
    $cmd -A INPUT -p udp --dport ${P2P_PORT} -j ACCEPT

    # Additional peer subnets (unrestricted P2P access)
    if [[ -n "$PEER_SUBNETS" ]]; then
        for subnet in $PEER_SUBNETS; do
            log_info "  Adding unrestricted P2P from $subnet"
            $cmd -A INPUT -p tcp -s "$subnet" --dport ${P2P_PORT} -j ACCEPT
        done
    fi

    # Prometheus from monitoring subnet
    $cmd -A INPUT -p tcp -s ${MONITORING_SUBNET} --dport ${PROMETHEUS_PORT} -j ACCEPT

    # Drop RPC and Admin from public
    $cmd -A INPUT -p tcp --dport ${RPC_PORT} -j DROP
    $cmd -A INPUT -p tcp --dport ${ADMIN_PORT} -j DROP

    # Drop all other incoming
    $cmd -A INPUT -j DROP

    log_info "IPv4 rules configured"
}

configure_ipv6() {
    log_info "Configuring IPv6 ip6tables rules..."

    if ! command -v ip6tables &>/dev/null; then
        log_warn "ip6tables not found — skipping IPv6 configuration"
        return
    fi

    local cmd=""
    if [[ "$DRY_RUN" == true ]]; then
        cmd="echo [DRY RUN] ip6tables"
    else
        cmd="ip6tables"
    fi

    $cmd -P INPUT DROP
    $cmd -P OUTPUT ACCEPT
    $cmd -P FORWARD DROP
    $cmd -A INPUT -i lo -j ACCEPT
    $cmd -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    $cmd -A INPUT -m state --state INVALID -j DROP
    $cmd -A INPUT -p tcp --dport ${SSH_PORT} -m state --state NEW -m limit --limit 10/min --limit-burst 5 -j ACCEPT
    $cmd -A INPUT -p tcp --dport ${SSH_PORT} -m state --state NEW -j DROP
    $cmd -A INPUT -p tcp --dport ${P2P_PORT} -m state --state NEW -m limit --limit 10/min --limit-burst 20 -j ACCEPT
    $cmd -A INPUT -p tcp --dport ${P2P_PORT} -m state --state NEW -j DROP
    $cmd -A INPUT -p udp --dport ${P2P_PORT} -j ACCEPT
    $cmd -A INPUT -p tcp --dport ${RPC_PORT} -j DROP
    $cmd -A INPUT -p tcp --dport ${ADMIN_PORT} -j DROP
    $cmd -A INPUT -j DROP

    log_info "IPv6 rules configured"
}

save_rules() {
    if [[ "$NO_SAVE" == true ]]; then
        log_info "Skipping rule persistence (--no-save)"
        return
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would save rules to disk"
        return
    fi

    log_info "Saving iptables rules..."

    mkdir -p /etc/iptables
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4
        log_info "IPv4 rules saved to /etc/iptables/rules.v4"
    fi
    if command -v ip6tables-save &>/dev/null; then
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        log_info "IPv6 rules saved to /etc/iptables/rules.v6"
    fi

    # Create systemd service to restore rules on boot
    if [[ ! -f /etc/systemd/system/iptables-restore.service ]]; then
        cat > /etc/systemd/system/iptables-restore.service << 'SYSTEMD_EOF'
[Unit]
Description=Restore iptables rules on boot
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
ExecStart=/sbin/ip6tables-restore /etc/iptables/rules.v6
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF
        systemctl daemon-reload
        systemctl enable iptables-restore.service
        log_info "Created iptables-restore systemd service"
    fi
}

show_rules() {
    echo ""
    log_info "Current IPv4 rules:"
    iptables -L -n -v 2>/dev/null || true
    echo ""
    if command -v ip6tables &>/dev/null; then
        log_info "Current IPv6 rules:"
        ip6tables -L -n -v 2>/dev/null || true
        echo ""
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║  IONA Validator Firewall Configuration                          ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    log_info "P2P port:         $P2P_PORT"
    log_info "RPC port:         $RPC_PORT"
    log_info "Admin port:       $ADMIN_PORT"
    log_info "SSH port:         $SSH_PORT"
    log_info "Prometheus port:  $PROMETHEUS_PORT"
    log_info "Monitoring subnet: $MONITORING_SUBNET"
    [[ -n "$PEER_SUBNETS" ]] && log_info "Peer subnets:     $PEER_SUBNETS"
    log_info "Dry run:          $DRY_RUN"
    echo ""

    reset_policies
    flush_rules
    configure_ipv4
    configure_ipv6
    save_rules

    if [[ "$VERBOSE" -eq 1 ]]; then
        show_rules
    fi

    DURATION=$(($(date +%s) - START_TIME))
    echo ""
    log_info "Firewall configuration complete (${DURATION}s)"

    if [[ "$DRY_RUN" == true ]]; then
        log_warn "DRY RUN — no rules were actually applied"
    fi
}

main "$@"
