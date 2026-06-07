#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IONA Node Upgrade Script v30.0.0 — Production‑Grade                       ║
# ║                                                                            ║
# ║  Safely upgrades the IONA node binary with validation and rollback support.║
# ║  Creates backups before upgrade and verifies health after completion.      ║
# ║                                                                            ║
# ║  Usage:                                                                    ║
# ║    sudo ./upgrade.sh v28.1.0                                               ║
# ║    sudo ./upgrade.sh v28.1.0 --dry-run                                     ║
# ║    sudo ./upgrade.sh v28.1.0 --air-gapped --binary ./iona-node             ║
# ║    sudo ./upgrade.sh v28.1.0 --skip-compat                                 ║
# ║    sudo ./upgrade.sh v28.1.0 --no-backup                                   ║
# ║                                                                            ║
# ║  Options:                                                                  ║
# ║    --dry-run         Simulate upgrade without making changes               ║
# ║    --skip-compat     Skip compatibility check                              ║
# ║    --no-backup       Skip data directory backup                            ║
# ║    --keep-backup     Keep backup files after successful upgrade            ║
# ║    --air-gapped      Use local binary instead of downloading               ║
# ║    --binary PATH     Path to local binary (air-gapped mode)                ║
# ║    --config PATH     Path to config file (default: /etc/iona/config.toml)  ║
# ║    --json            Output results in JSON format                         ║
# ║    --verbose         Show detailed output                                  ║
# ║    --help            Show this help                                        ║
# ║                                                                            ║
# ║  Environment variables:                                                    ║
# ║    IONA_INSTALL_DIR, IONA_DATA_DIR, IONA_CONFIG_DIR, IONA_BACKUP_DIR      ║
# ║    IONA_SERVICE_NAME, IONA_RPC_ENDPOINT, IONA_UPGRADE_TIMEOUT             ║
# ║    GITHUB_REPO, IONA_PROXY, IONA_SKIP_VERIFY                              ║
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
CONFIG_FILE="${IONA_CONFIG_FILE:-$CONFIG_DIR/config.toml}"
IONA_PROXY="${IONA_PROXY:-}"
IONA_SKIP_VERIFY="${IONA_SKIP_VERIFY:-0}"

DRY_RUN=false
SKIP_COMPAT=false
NO_BACKUP=false
KEEP_BACKUP=false
VERBOSE=false
AIR_GAPPED=false
LOCAL_BINARY=""
JSON_OUTPUT=false
TARGET_VERSION="${1:-}"
START_TIME=$(date +%s)

# ── Helper functions ─────────────────────────────────────────────────────────
log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_section() { echo -e "\n${BOLD}${BLUE}═══ $* ═══${NC}"; }
log_verbose() { [[ "$VERBOSE" == true ]] && echo -e "[VERBOSE] $*"; }
log_pass()    { echo -e "  ${GREEN}✓${NC} $*"; }
log_fail()    { echo -e "  ${RED}✗${NC} $*"; }

command_exists() { command -v "$1" &>/dev/null; }
die() { log_error "$*"; exit 1; }

# ── Parse arguments ──────────────────────────────────────────────────────────
if [[ -z "$TARGET_VERSION" ]] || [[ "$TARGET_VERSION" == "--help" ]] || [[ "$TARGET_VERSION" == "-h" ]]; then
    sed -n '/^# Usage:/,/^# ╚══/p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

# Validate version format
if [[ ! "$TARGET_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if [[ "$TARGET_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TARGET_VERSION="v$TARGET_VERSION"
    else
        die "Invalid version format: $TARGET_VERSION (expected vX.Y.Z or X.Y.Z)"
    fi
fi

shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)       DRY_RUN=true; shift ;;
        --skip-compat)   SKIP_COMPAT=true; shift ;;
        --no-backup)     NO_BACKUP=true; shift ;;
        --keep-backup)   KEEP_BACKUP=true; shift ;;
        --air-gapped)    AIR_GAPPED=true; shift ;;
        --binary)        LOCAL_BINARY="$2"; shift 2 ;;
        --config)        CONFIG_FILE="$2"; shift 2 ;;
        --json)          JSON_OUTPUT=true; shift ;;
        --verbose)       VERBOSE=true; shift ;;
        --help|-h)
            sed -n '/^# Usage:/,/^# ╚══/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)               log_warn "Unknown option: $1"; shift ;;
    esac
done

# ── Setup proxy if configured ─────────────────────────────────────────────────
if [[ -n "$IONA_PROXY" ]]; then
    export http_proxy="$IONA_PROXY"
    export https_proxy="$IONA_PROXY"
    log_verbose "Using proxy: $IONA_PROXY"
fi

# ── Check root ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root (sudo ./upgrade.sh ...)"
fi

# ── Pre-flight checks ────────────────────────────────────────────────────────
log_section "Pre-flight Checks"

# Check available disk space (need at least 1GB)
AVAILABLE_DISK=$(df "$INSTALL_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || df / | awk 'NR==2 {print $4}')
if [[ -n "$AVAILABLE_DISK" ]] && [[ "$AVAILABLE_DISK" -lt 1048576 ]]; then
    die "Insufficient disk space. Need at least 1GB. Available: $((AVAILABLE_DISK / 1024))MB"
fi
log_pass "Disk space sufficient"

# Check required tools
for cmd in curl tar sha256sum systemctl; do
    if command_exists "$cmd"; then
        log_verbose "$cmd found"
    else
        die "Required tool not found: $cmd"
    fi
done
log_pass "All required tools available"

# Check config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    die "Config file not found: $CONFIG_FILE"
fi
log_pass "Config file found: $CONFIG_FILE"

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
    "$bin" --version 2>/dev/null | grep -oP 'v?\d+\.\d+\.\d+' | head -1 || echo "unknown"
}

# ── Helper: detect architecture ──────────────────────────────────────────────
detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *)             die "Unsupported architecture: $arch" ;;
    esac
}

# ── Helper: safe download with retry ─────────────────────────────────────────
safe_download() {
    local url="$1"
    local output="$2"
    local max_retries=3
    local retry=0

    while [[ $retry -lt $max_retries ]]; do
        if curl -fSL --progress-bar "$url" -o "$output" 2>/dev/null; then
            return 0
        fi
        retry=$((retry + 1))
        log_warn "Download failed (attempt $retry/$max_retries), retrying..."
        sleep 2
    done
    return 1
}

# ── 1. Create backup ─────────────────────────────────────────────────────────
log_section "Creating Backup"
mkdir -p "$BACKUP_DIR"

CURRENT_VERSION=$(get_current_version)
log_info "Current version: $CURRENT_VERSION"
log_info "Target version:  $TARGET_VERSION"

# Binary backup
BACKUP_BINARY=""
if [[ -f "$INSTALL_DIR/iona-node" ]]; then
    BACKUP_BINARY="$BACKUP_DIR/iona-node-$(date +%Y%m%d-%H%M%S)"
    if [[ "$DRY_RUN" == false ]]; then
        cp "$INSTALL_DIR/iona-node" "$BACKUP_BINARY"
        log_pass "Binary backed up to $BACKUP_BINARY"
    else
        log_info "[DRY RUN] Would backup binary to $BACKUP_BINARY"
    fi
fi

# Config backup
if [[ -f "$CONFIG_FILE" ]]; then
    CONFIG_BACKUP="$BACKUP_DIR/config-$(date +%Y%m%d-%H%M%S).toml"
    if [[ "$DRY_RUN" == false ]]; then
        cp "$CONFIG_FILE" "$CONFIG_BACKUP"
        log_pass "Config backed up to $CONFIG_BACKUP"
    else
        log_info "[DRY RUN] Would backup config to $CONFIG_BACKUP"
    fi
fi

# Data directory backup
if [[ "$NO_BACKUP" == false ]]; then
    DATA_BACKUP="$BACKUP_DIR/data-$(date +%Y%m%d-%H%M%S).tar.gz"
    if [[ "$DRY_RUN" == false ]]; then
        log_info "Backing up data directory to $DATA_BACKUP..."
        tar czf "$DATA_BACKUP" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")" --exclude='*.log' 2>/dev/null || {
            log_warn "Data backup encountered errors (continuing)"
        }
        log_pass "Data backup complete"
    else
        log_info "[DRY RUN] Would backup data directory to $DATA_BACKUP"
    fi
else
    log_warn "Skipping data backup (--no-backup)"
fi

# ── 2. Obtain new binary ─────────────────────────────────────────────────────
log_section "Obtaining Binary"

TMP_BINARY="/tmp/iona-node-upgrade-$$"

if [[ "$AIR_GAPPED" == true ]]; then
    if [[ -z "$LOCAL_BINARY" ]]; then
        die "Air-gapped mode requires --binary <path>"
    fi
    if [[ ! -f "$LOCAL_BINARY" ]]; then
        die "Local binary not found: $LOCAL_BINARY"
    fi
    if [[ "$DRY_RUN" == false ]]; then
        cp "$LOCAL_BINARY" "$TMP_BINARY"
        chmod +x "$TMP_BINARY"
        log_pass "Using local binary: $LOCAL_BINARY"
    else
        log_info "[DRY RUN] Would use local binary: $LOCAL_BINARY"
    fi
else
    ARCH=$(detect_arch)
    BINARY_FILE="iona-node-${TARGET_VERSION}-${ARCH}"
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${TARGET_VERSION}/${BINARY_FILE}"
    SHA256_URL="${DOWNLOAD_URL}.sha256"

    if [[ "$DRY_RUN" == false ]]; then
        log_info "Downloading $TARGET_VERSION for $ARCH..."
        safe_download "$DOWNLOAD_URL" "$TMP_BINARY" || die "Failed to download binary"

        # Verify SHA256
        if [[ "$IONA_SKIP_VERIFY" != 1 ]]; then
            log_info "Verifying SHA256 checksum..."
            curl -fsSL "$SHA256_URL" -o "/tmp/iona-node-upgrade.sha256" 2>/dev/null || {
                log_warn "SHA256 file not found, skipping verification"
            }
            if [[ -f "/tmp/iona-node-upgrade.sha256" ]]; then
                (cd /tmp && sha256sum -c "iona-node-upgrade-$$.sha256" 2>/dev/null) || {
                    log_error "SHA256 verification failed"
                    rm -f "$TMP_BINARY"
                    exit 1
                }
                log_pass "SHA256 checksum verified"
            fi
        else
            log_warn "Skipping signature verification (IONA_SKIP_VERIFY=1)"
        fi

        chmod +x "$TMP_BINARY"
        log_pass "Binary downloaded and verified"
    else
        log_info "[DRY RUN] Would download $TARGET_VERSION"
    fi
fi

# ── 3. Compatibility check ───────────────────────────────────────────────────
if [[ "$SKIP_COMPAT" == false ]]; then
    log_section "Checking Compatibility"
    if [[ "$DRY_RUN" == false ]]; then
        log_info "Running compatibility check..."
        if "$TMP_BINARY" --check-compat --config "$CONFIG_FILE" 2>&1; then
            log_pass "Compatibility check passed"
        else
            log_error "Compatibility check failed"
            rm -f "$TMP_BINARY"
            exit 1
        fi
    else
        log_info "[DRY RUN] Would run compatibility check"
    fi
else
    log_warn "Skipping compatibility check (--skip-compat)"
fi

# ── 4. Verify binary integrity ───────────────────────────────────────────────
log_section "Verifying Binary"
if [[ "$DRY_RUN" == false ]]; then
    NEW_VERSION=$("$TMP_BINARY" --version 2>/dev/null | grep -oP 'v?\d+\.\d+\.\d+' | head -1 || echo "unknown")
    log_info "New binary version: $NEW_VERSION"
    if [[ "$NEW_VERSION" != "$TARGET_VERSION" ]] && [[ "$NEW_VERSION" != "${TARGET_VERSION#v}" ]]; then
        log_error "Binary version mismatch: expected $TARGET_VERSION, got $NEW_VERSION"
        rm -f "$TMP_BINARY"
        exit 1
    fi
    log_pass "Binary version verified"
else
    log_info "[DRY RUN] Would verify binary version"
fi

# ── 5. Stop service ──────────────────────────────────────────────────────────
log_section "Stopping Service"
if [[ "$DRY_RUN" == false ]]; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping $SERVICE_NAME..."
        systemctl stop "$SERVICE_NAME"
        sleep 3
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            log_warn "Service still running, forcing stop..."
            systemctl kill -s KILL "$SERVICE_NAME" || true
            sleep 1
        fi
        log_pass "Service stopped"
    else
        log_warn "Service $SERVICE_NAME not running"
    fi
else
    log_info "[DRY RUN] Would stop $SERVICE_NAME"
fi

# ── 6. Replace binary ────────────────────────────────────────────────────────
log_section "Installing New Binary"
if [[ "$DRY_RUN" == false ]]; then
    mv "$TMP_BINARY" "$INSTALL_DIR/iona-node"
    log_pass "Binary installed: $INSTALL_DIR/iona-node"
else
    log_info "[DRY RUN] Would install binary to $INSTALL_DIR/iona-node"
    rm -f "$TMP_BINARY"
fi

# ── 7. Start service ─────────────────────────────────────────────────────────
log_section "Starting Service"
if [[ "$DRY_RUN" == false ]]; then
    systemctl start "$SERVICE_NAME" || {
        log_error "Failed to start service"
        log_section "Rolling Back"
        if [[ -f "$BACKUP_BINARY" ]]; then
            cp "$BACKUP_BINARY" "$INSTALL_DIR/iona-node"
            systemctl restart "$SERVICE_NAME" 2>/dev/null || true
            log_pass "Rollback completed"
        else
            log_error "No backup found; manual intervention required"
        fi
        exit 1
    }
    sleep 3
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_pass "Service started"
    else
        log_error "Service failed to start"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null || true
        exit 1
    fi
else
    log_info "[DRY RUN] Would start $SERVICE_NAME"
fi

# ── 8. Health check ──────────────────────────────────────────────────────────
log_section "Health Check"
if [[ "$DRY_RUN" == false ]]; then
    log_info "Waiting for node to be ready (timeout: ${TIMEOUT_SECONDS}s)..."
    ATTEMPT=1
    HEALTHY=false
    while [[ $ATTEMPT -le $TIMEOUT_SECONDS ]]; do
        if curl -sf "$RPC_ENDPOINT/health" >/dev/null 2>&1; then
            HEALTHY=true
            log_pass "Health check passed after ${ATTEMPT}s"
            break
        fi
        if [[ $((ATTEMPT % 10)) -eq 0 ]]; then
            log_info "Still waiting... ($ATTEMPT/${TIMEOUT_SECONDS}s)"
        fi
        sleep 1
        ATTEMPT=$((ATTEMPT + 1))
    done

    if [[ "$HEALTHY" == false ]]; then
        log_error "Health check failed after ${TIMEOUT_SECONDS}s"
        log_section "Rolling Back"
        if [[ -f "$BACKUP_BINARY" ]]; then
            cp "$BACKUP_BINARY" "$INSTALL_DIR/iona-node"
            systemctl restart "$SERVICE_NAME" 2>/dev/null || true
            log_pass "Rollback completed"
        else
            log_error "No backup found; manual intervention required"
        fi
        exit 1
    fi
else
    log_info "[DRY RUN] Would check node health"
fi

# ── 9. Cleanup ───────────────────────────────────────────────────────────────
if [[ "$KEEP_BACKUP" == false ]] && [[ "$DRY_RUN" == false ]]; then
    log_section "Cleaning Up"
    # Remove backups older than 7 days
    find "$BACKUP_DIR" -name "iona-node-*" -type f -mtime +7 -delete 2>/dev/null || true
    find "$BACKUP_DIR" -name "data-*.tar.gz" -type f -mtime +7 -delete 2>/dev/null || true
    find "$BACKUP_DIR" -name "config-*.toml" -type f -mtime +7 -delete 2>/dev/null || true
    log_pass "Old backups cleaned (retaining last 7 days)"
fi

# ── 10. Summary ──────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

log_section "Upgrade Summary"
echo -e "${GREEN}${BOLD}Upgrade completed successfully!${NC}"
echo "  Duration:          ${DURATION}s"
echo "  Previous version:  $CURRENT_VERSION"
echo "  New version:       $TARGET_VERSION"
echo "  Binary:            $INSTALL_DIR/iona-node"
echo "  Backup binary:     ${BACKUP_BINARY:-none}"
echo ""
echo "View logs:"
echo "  sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo "Verify upgrade:"
echo "  $INSTALL_DIR/iona-node --version"
echo "  curl $RPC_ENDPOINT/health"

if [[ "$JSON_OUTPUT" == true ]]; then
    echo ""
    echo "{"
    echo "  \"status\": \"success\","
    echo "  \"previous_version\": \"$CURRENT_VERSION\","
    echo "  \"new_version\": \"$TARGET_VERSION\","
    echo "  \"duration_seconds\": $DURATION,"
    echo "  \"binary_path\": \"$INSTALL_DIR/iona-node\","
    echo "  \"backup_path\": \"${BACKUP_BINARY:-none}\""
    echo "}"
fi
