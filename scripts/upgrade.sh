#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IONA Node Upgrade Script v30.0.0                                          ║
# ║                                                                            ║
# ║  Safely upgrades the IONA node binary with validation and rollback support.║
# ║  Creates backups before upgrade and verifies health after completion.      ║
# ║                                                                            ║
# ║  Usage:                                                                    ║
# ║    sudo ./upgrade.sh v28.1.0                                               ║
# ║    sudo ./upgrade.sh v28.1.0 --dry-run                                     ║
# ║    sudo ./upgrade.sh v28.1.0 --skip-compat                                 ║
# ║    sudo ./upgrade.sh v28.1.0 --no-backup                                   ║
# ║                                                                            ║
# ║  Options:                                                                  ║
# ║    --dry-run        Simulate upgrade without making changes                ║
# ║    --skip-compat    Skip compatibility check                               ║
# ║    --no-backup      Skip data directory backup                             ║
# ║    --keep-backup    Keep backup files after successful upgrade             ║
# ║    --verbose        Show detailed output                                   ║
# ║    --help           Show this help                                         ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

# ── Default configuration ────────────────────────────────────────────────────
INSTALL_DIR="${IONA_INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="${IONA_DATA_DIR:-/opt/iona/data}"
CONFIG_DIR="${IONA_CONFIG_DIR:-/etc/iona}"
BACKUP_DIR="${IONA_BACKUP_DIR:-/opt/iona/backups}"
SERVICE_NAME="${IONA_SERVICE_NAME:-iona-node}"
GITHUB_REPO="${GITHUB_REPO:-ionablokchain/Iona-protocol}"
RPC_ENDPOINT="${IONA_RPC_ENDPOINT:-http://127.0.0.1:9001}"
TIMEOUT_SECONDS="${IONA_UPGRADE_TIMEOUT:-60}"

DRY_RUN=false
SKIP_COMPAT=false
NO_BACKUP=false
KEEP_BACKUP=false
VERBOSE=false
TARGET_VERSION="${1:-}"
START_TIME=$(date +%s)

# ── Helper functions ─────────────────────────────────────────────────────────
log_info()   { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()   { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_section() { echo -e "\n${BOLD}${BLUE}═══ $* ═══${NC}"; }
log_verbose() { [[ "$VERBOSE" == true ]] && echo -e "[VERBOSE] $*"; }

command_exists() { command -v "$1" &>/dev/null; }
die() { log_error "$*"; exit 1; }

# ── Parse arguments ──────────────────────────────────────────────────────────
if [[ -z "$TARGET_VERSION" ]]; then
    sed -n '/^# Usage:/,/^# ╚══/p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)       DRY_RUN=true; shift ;;
        --skip-compat)   SKIP_COMPAT=true; shift ;;
        --no-backup)     NO_BACKUP=true; shift ;;
        --keep-backup)   KEEP_BACKUP=true; shift ;;
        --verbose)       VERBOSE=true; shift ;;
        --help)          sed -n '/^# Usage:/,/^# ╚══/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)               log_warn "Unknown option: $1"; shift ;;
    esac
done

# ── Check root ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root (sudo ./upgrade.sh ...)"
fi

# ── Dry run mode ─────────────────────────────────────────────────────────────
if [[ "$DRY_RUN" == true ]]; then
    log_warn "DRY RUN MODE — no changes will be made"
fi

# ── Helper: get current version ──────────────────────────────────────────────
get_current_version() {
    local bin="${1:-$INSTALL_DIR/iona-node}"
    if [[ ! -f "$bin" ]]; then
        echo "not-installed"
        return
    fi
    "$bin" --version 2>/dev/null | awk '{print $2}' || echo "unknown"
}

# ── Helper: safe download with retry ─────────────────────────────────────────
safe_download() {
    local url="$1"
    local output="$2"
    local max_retries=3
    local retry=0

    while [[ $retry -lt $max_retries ]]; do
        if curl -fSL --progress-bar "$url" -o "$output"; then
            return 0
        fi
        retry=$((retry + 1))
        log_warn "Download failed (attempt $retry/$max_retries), retrying..."
        sleep 2
    done
    return 1
}

# ── Helper: verify GPG signature (if available) ──────────────────────────────
verify_gpg() {
    local file="$1"
    local sig_url="$2"
    local key_url="${3:-https://github.com/${GITHUB_REPO}/releases/download/${TARGET_VERSION}/iona-release-signing-key.asc}"

    if ! command_exists gpg; then
        log_warn "gpg not installed — skipping signature verification"
        return 0
    fi

    # Import release key
    local key_file="/tmp/iona-release-key.asc"
    if ! curl -fsSL "$key_url" -o "$key_file" 2>/dev/null; then
        log_warn "Release key not found — skipping signature verification"
        return 0
    fi
    gpg --batch --import "$key_file" 2>/dev/null

    # Download signature
    local sig_file="${file}.sig"
    if ! curl -fsSL "$sig_url" -o "$sig_file"; then
        log_warn "Signature file not found — skipping verification"
        return 0
    fi

    if gpg --batch --verify "$sig_file" "$file" 2>/dev/null; then
        log_info "GPG signature: VALID"
        return 0
    else
        log_error "GPG signature verification FAILED"
        return 1
    fi
}

# ── 1. Create backup ─────────────────────────────────────────────────────────
log_section "Creating Backup"
mkdir -p "$BACKUP_DIR"

CURRENT_VERSION=$(get_current_version)
log_info "Current version: $CURRENT_VERSION"
log_info "Target version:  $TARGET_VERSION"

# Binary backup
if [[ -f "$INSTALL_DIR/iona-node" ]]; then
    BACKUP_BINARY="$BACKUP_DIR/iona-node-$(date +%Y%m%d-%H%M%S)"
    if [[ "$DRY_RUN" == false ]]; then
        cp "$INSTALL_DIR/iona-node" "$BACKUP_BINARY"
        log_info "Binary backed up to $BACKUP_BINARY"
    else
        log_info "[DRY RUN] Would backup binary to $BACKUP_BINARY"
    fi
fi

# Data directory backup
if [[ "$NO_BACKUP" == false ]]; then
    DATA_BACKUP="$BACKUP_DIR/data-$(date +%Y%m%d-%H%M%S).tar.gz"
    if [[ "$DRY_RUN" == false ]]; then
        log_info "Backing up data directory to $DATA_BACKUP..."
        tar czf "$DATA_BACKUP" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")" --exclude='*.log' 2>/dev/null || true
        log_info "Data backup complete"
    else
        log_info "[DRY RUN] Would backup data directory to $DATA_BACKUP"
    fi
else
    log_warn "Skipping data backup (--no-backup)"
fi

# ── 2. Download new binary ───────────────────────────────────────────────────
log_section "Downloading Binary"

BINARY_FILE="iona-node-${TARGET_VERSION}-x86_64-unknown-linux-gnu"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${TARGET_VERSION}/${BINARY_FILE}"
SHA256_URL="${DOWNLOAD_URL}.sha256"

TMP_BINARY="/tmp/iona-node-upgrade"

if [[ "$DRY_RUN" == false ]]; then
    log_info "Downloading $TARGET_VERSION..."
    safe_download "$DOWNLOAD_URL" "$TMP_BINARY" || die "Failed to download binary"

    # Verify SHA256
    log_info "Verifying SHA256 checksum..."
    curl -fsSL "$SHA256_URL" -o "/tmp/iona-node-upgrade.sha256" || {
        log_warn "SHA256 file not found, skipping verification"
    }
    if [[ -f "/tmp/iona-node-upgrade.sha256" ]]; then
        (cd /tmp && sha256sum -c iona-node-upgrade.sha256) || die "SHA256 verification failed"
        log_info "SHA256 checksum verified"
    fi

    # Verify GPG signature (optional)
    verify_gpg "$TMP_BINARY" "${DOWNLOAD_URL}.sig" || die "GPG verification failed"

    chmod +x "$TMP_BINARY"
    log_info "Binary downloaded and verified"
else
    log_info "[DRY RUN] Would download $TARGET_VERSION"
fi

# ── 3. Compatibility check ───────────────────────────────────────────────────
if [[ "$SKIP_COMPAT" == false ]]; then
    log_section "Checking Compatibility"
    if [[ "$DRY_RUN" == false ]]; then
        log_info "Running compatibility check..."
        if ! "$TMP_BINARY" --check-compat --config "$CONFIG_DIR/config.toml" 2>&1; then
            log_error "Compatibility check failed"
            exit 1
        fi
        log_info "Compatibility check passed"
    else
        log_info "[DRY RUN] Would run compatibility check"
    fi
else
    log_warn "Skipping compatibility check (--skip-compat)"
fi

# ── 4. Stop service ──────────────────────────────────────────────────────────
log_section "Stopping Service"
if [[ "$DRY_RUN" == false ]]; then
    if command_exists systemctl && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping $SERVICE_NAME..."
        systemctl stop "$SERVICE_NAME"
        sleep 3
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_warn "Service still running, forcing stop..."
            systemctl kill -s KILL "$SERVICE_NAME" || true
            sleep 1
        fi
        log_info "Service stopped"
    else
        log_warn "Service $SERVICE_NAME not running or not found"
    fi
else
    log_info "[DRY RUN] Would stop $SERVICE_NAME"
fi

# ── 5. Replace binary ────────────────────────────────────────────────────────
log_section "Installing New Binary"
if [[ "$DRY_RUN" == false ]]; then
    mv "$TMP_BINARY" "$INSTALL_DIR/iona-node"
    log_info "Binary replaced: $INSTALL_DIR/iona-node"
else
    log_info "[DRY RUN] Would install binary to $INSTALL_DIR/iona-node"
fi

# ── 6. Start service ─────────────────────────────────────────────────────────
log_section "Starting Service"
if [[ "$DRY_RUN" == false ]]; then
    if command_exists systemctl; then
        systemctl start "$SERVICE_NAME" || {
            log_error "Failed to start service"
            exit 1
        }
        sleep 3
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_info "Service started"
        else
            log_error "Service failed to start"
            journalctl -u "$SERVICE_NAME" -n 20 --no-pager
            exit 1
        fi
    else
        log_warn "systemctl not found, skipping service start"
    fi
else
    log_info "[DRY RUN] Would start $SERVICE_NAME"
fi

# ── 7. Health check ──────────────────────────────────────────────────────────
log_section "Health Check"
if [[ "$DRY_RUN" == false ]]; then
    log_info "Waiting for node to be ready (timeout: ${TIMEOUT_SECONDS}s)..."
    ATTEMPT=1
    while [[ $ATTEMPT -le $TIMEOUT_SECONDS ]]; do
        if curl -sf "$RPC_ENDPOINT/health" >/dev/null 2>&1; then
            log_info "Health check passed after ${ATTEMPT}s"
            break
        fi
        if [[ $((ATTEMPT % 5)) -eq 0 ]]; then
            log_info "Still waiting... ($ATTEMPT/${TIMEOUT_SECONDS}s)"
        fi
        sleep 1
        ATTEMPT=$((ATTEMPT + 1))
    done

    if [[ $ATTEMPT -gt $TIMEOUT_SECONDS ]]; then
        log_error "Health check failed after ${TIMEOUT_SECONDS}s"
        log_section "Rolling Back"
        # Restore binary from backup
        if [[ -f "$BACKUP_BINARY" ]]; then
            cp "$BACKUP_BINARY" "$INSTALL_DIR/iona-node"
            systemctl restart "$SERVICE_NAME" || true
            log_info "Rollback completed"
        else
            log_error "No backup found; manual intervention required"
        fi
        exit 1
    fi
else
    log_info "[DRY RUN] Would check node health"
fi

# ── 8. Cleanup ───────────────────────────────────────────────────────────────
if [[ "$KEEP_BACKUP" == false ]] && [[ "$DRY_RUN" == false ]]; then
    log_section "Cleaning Up"
    # Remove backup binary older than 7 days
    find "$BACKUP_DIR" -name "iona-node-*" -type f -mtime +7 -delete 2>/dev/null || true
    find "$BACKUP_DIR" -name "data-*.tar.gz" -type f -mtime +7 -delete 2>/dev/null || true
    log_info "Old backups cleaned (retaining last 7 days)"
fi

# ── 9. Summary ───────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

log_section "Upgrade Summary"
echo -e "${GREEN}Upgrade completed successfully!${NC}"
echo "  Duration:        ${DURATION}s"
echo "  Previous version: $CURRENT_VERSION"
echo "  New version:      $TARGET_VERSION"
echo "  Binary:           $INSTALL_DIR/iona-node"
echo "  Backup binary:    $BACKUP_BINARY"
echo ""
echo "View logs:"
echo "  sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo "Verify upgrade:"
echo "  $INSTALL_DIR/iona-node --version"
echo "  curl $RPC_ENDPOINT/health"
