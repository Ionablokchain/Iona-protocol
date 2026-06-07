#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# IONA Node — Official Production Installer v30.0.0
# ─────────────────────────────────────────────────────────────────────────────
#
# Usage:
#   curl -sSf https://install.iona.sh | sh
#   curl -sSf https://install.iona.sh | sh -s -- --version v30.0.0
#   curl -sSf https://install.iona.sh | sh -s -- --deb
#   sudo bash install.sh --uninstall
#   sudo bash install.sh --air-gapped --tarball ./iona-node-v30.0.0.tar.gz
#
# Environment overrides:
#   IONA_VERSION            — specific tag to install (default: latest stable)
#   IONA_INSTALL_DIR        — binary install directory (default: /usr/local/bin)
#   IONA_DATA_DIR           — node data directory (default: /var/lib/iona)
#   IONA_CONFIG_DIR         — config directory (default: /etc/iona)
#   IONA_LOG_DIR            — log directory (default: /var/log/iona)
#   IONA_SERVICE_USER       — system user for the service (default: iona)
#   GITHUB_REPO             — repository slug (default: ionablokchain/Iona-protocol)
#   COSIGN_PUBLIC_KEY       — path or URL to cosign public key (optional)
#   GPG_KEY_URL             — URL to release signing GPG key (optional)
#   IONA_NO_START           — if set, don't start service after install
#   IONA_SKIP_VERIFY        — if set, skip signature verification
#   IONA_SKIP_SERVICE       — if set, don't install systemd service at all
#   IONA_VERBOSE            — enable verbose output
#   IONA_YES                — skip all prompts (non-interactive mode)
#   IONA_AIR_GAPPED         — air-gapped mode (skip downloads)
#   IONA_TARBALL            — path to local tarball (air-gapped mode)
#   IONA_PROXY              — HTTP proxy for downloads (e.g. http://proxy:8080)
#   IONA_CA_BUNDLE          — path to custom CA bundle for TLS verification
#
# This installer:
#   1. Detects OS and CPU architecture
#   2. Resolves the latest (or specified) release from GitHub
#   3. Downloads binary tarball or .deb package
#   4. Verifies SHA-256 checksum (mandatory)
#   5. Verifies GPG signature on SHA256SUMS (if gpg available)
#   6. Verifies cosign signature (if cosign available)
#   7. Installs binaries, creates system user, directories, systemd service
#   8. Runs post-install health checks
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail
IFS=$'\n\t'

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
    BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''
    CYAN=''; MAGENTA=''; BOLD=''; NC=''
fi

# ── Logging functions ─────────────────────────────────────────────────────────
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
section() { echo -e "\n${BLUE}${BOLD}═══ $* ═══${NC}"; }
sub_section() { echo -e "\n${CYAN}--- $* ---${NC}"; }

die() {
    error "$*"
    exit 1
}

ok() {
    echo -e "  ${GREEN}✓${NC} $*"
}

fail_check() {
    echo -e "  ${RED}✗${NC} $*"
    return 1
}

log_verbose() {
    if [[ "${IONA_VERBOSE:-0}" -eq 1 ]]; then
        echo -e "[VERBOSE] $*"
    fi
}

# ── Defaults ──────────────────────────────────────────────────────────────────
IONA_VERSION="${IONA_VERSION:-}"
IONA_INSTALL_DIR="${IONA_INSTALL_DIR:-/usr/local/bin}"
IONA_DATA_DIR="${IONA_DATA_DIR:-/var/lib/iona}"
IONA_CONFIG_DIR="${IONA_CONFIG_DIR:-/etc/iona}"
IONA_LOG_DIR="${IONA_LOG_DIR:-/var/log/iona}"
IONA_SERVICE_USER="${IONA_SERVICE_USER:-iona}"
GITHUB_REPO="${GITHUB_REPO:-ionablokchain/Iona-protocol}"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
GITHUB_DL="https://github.com/${GITHUB_REPO}/releases/download"

PREFER_DEB=false
IONA_SKIP_VERIFY="${IONA_SKIP_VERIFY:-0}"
DO_UNINSTALL=false
IONA_NO_START="${IONA_NO_START:-0}"
IONA_SKIP_SERVICE="${IONA_SKIP_SERVICE:-0}"
IONA_VERBOSE="${IONA_VERBOSE:-0}"
IONA_YES="${IONA_YES:-0}"
IONA_AIR_GAPPED="${IONA_AIR_GAPPED:-0}"
IONA_TARBALL="${IONA_TARBALL:-}"
IONA_PROXY="${IONA_PROXY:-}"
IONA_CA_BUNDLE="${IONA_CA_BUNDLE:-}"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)        IONA_VERSION="$2"; shift 2 ;;
        --version=*)      IONA_VERSION="${1#*=}"; shift ;;
        --deb)            PREFER_DEB=true; shift ;;
        --skip-verify)    IONA_SKIP_VERIFY=1; shift ;;
        --no-start)       IONA_NO_START=1; shift ;;
        --skip-service)   IONA_SKIP_SERVICE=1; shift ;;
        --uninstall)      DO_UNINSTALL=true; shift ;;
        --verbose|-v)     IONA_VERBOSE=1; shift ;;
        --yes|-y)         IONA_YES=1; shift ;;
        --air-gapped)     IONA_AIR_GAPPED=1; shift ;;
        --tarball)        IONA_TARBALL="$2"; shift 2 ;;
        --proxy)          IONA_PROXY="$2"; shift 2 ;;
        --ca-bundle)      IONA_CA_BUNDLE="$2"; shift 2 ;;
        --help|-h)
            sed -n '/^# Usage:/,/^# ─────────────────/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) warn "Unknown flag: $1 (ignored)"; shift ;;
    esac
done

# ── Helper: command_exists ────────────────────────────────────────────────────
command_exists() {
    command -v "$1" &>/dev/null
}

# ── Setup proxy if configured ─────────────────────────────────────────────────
if [[ -n "$IONA_PROXY" ]]; then
    export http_proxy="$IONA_PROXY"
    export https_proxy="$IONA_PROXY"
    log_verbose "Proxy configured: $IONA_PROXY"
fi

# Setup custom CA bundle if configured
if [[ -n "$IONA_CA_BUNDLE" ]] && [[ -f "$IONA_CA_BUNDLE" ]]; then
    export CURL_CA_BUNDLE="$IONA_CA_BUNDLE"
    export SSL_CERT_FILE="$IONA_CA_BUNDLE"
    log_verbose "Custom CA bundle: $IONA_CA_BUNDLE"
fi

# ── Root check ────────────────────────────────────────────────────────────────
if [[ "${EUID}" -ne 0 ]]; then
    die "This installer must be run as root.\nRe-run: sudo bash install.sh $*"
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  ██╗ ██████╗ ███╗   ██╗ █████╗ "
echo "  ██║██╔═══██╗████╗  ██║██╔══██╗"
echo "  ██║██║   ██║██╔██╗ ██║███████║"
echo "  ██║██║   ██║██║╚██╗██║██╔══██║"
echo "  ██║╚██████╔╝██║ ╚████║██║  ██║"
echo "  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝"
echo -e "${NC}  IONA Node Installer — Official v30.0.0\n"

# ── Uninstall path ────────────────────────────────────────────────────────────
if [[ "${DO_UNINSTALL}" == true ]]; then
    section "Uninstalling IONA"
    
    if [[ "$IONA_YES" -ne 1 ]]; then
        read -p "Are you sure you want to uninstall IONA? Data will be preserved. [y/N] " -r REPLY
        [[ ! "$REPLY" =~ ^[Yy]$ ]] && die "Uninstall cancelled"
    fi
    
    systemctl stop  iona-node 2>/dev/null && ok "Service stopped" || true
    systemctl disable iona-node 2>/dev/null && ok "Service disabled" || true
    rm -f /lib/systemd/system/iona-node.service
    systemctl daemon-reload 2>/dev/null || true
    rm -f "${IONA_INSTALL_DIR}/iona-node" \
          "${IONA_INSTALL_DIR}/iona-cli"  \
          "${IONA_INSTALL_DIR}/iona-remote-signer"
    warn "Chain data preserved at ${IONA_DATA_DIR}"
    warn "Config preserved at ${IONA_CONFIG_DIR}"
    info "To remove all data: sudo rm -rf ${IONA_DATA_DIR} ${IONA_CONFIG_DIR}"
    info "Uninstall complete."
    exit 0
fi

# ── Pre-flight checks ─────────────────────────────────────────────────────────
section "Pre-flight checks"

# Check minimum disk space (1GB)
AVAILABLE_DISK=$(df /usr/local/bin 2>/dev/null | awk 'NR==2 {print $4}' || df / | awk 'NR==2 {print $4}')
if [[ -n "$AVAILABLE_DISK" ]] && [[ "$AVAILABLE_DISK" -lt 1048576 ]]; then
    die "Insufficient disk space. Need at least 1GB free. Available: $((AVAILABLE_DISK / 1024))MB"
fi
ok "Disk space: sufficient"

# Check architecture support
UNAME_OS="$(uname -s)"
UNAME_ARCH="$(uname -m)"

case "${UNAME_OS}" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin"; warn "macOS detected — .deb not supported; using tarball" ;;
    *)      die "Unsupported OS: ${UNAME_OS} (supported: Linux, macOS)" ;;
esac

case "${UNAME_ARCH}" in
    x86_64|amd64)  ARCH="x86_64";  DEB_ARCH="amd64"  ;;
    aarch64|arm64) ARCH="aarch64"; DEB_ARCH="arm64"   ;;
    *)             die "Unsupported architecture: ${UNAME_ARCH} (supported: x86_64, aarch64)" ;;
esac

ok "OS: ${UNAME_OS} (${OS})"
ok "Architecture: ${UNAME_ARCH} (${ARCH})"

# Detect Debian family
IS_DEBIAN=false
if [[ -f /etc/debian_version ]] || command_exists dpkg; then
    IS_DEBIAN=true
fi
ok "Debian-family: ${IS_DEBIAN}"

# Check for existing installation
if [[ -f "${IONA_INSTALL_DIR}/iona-node" ]]; then
    EXISTING_VER="$("${IONA_INSTALL_DIR}/iona-node" --version 2>/dev/null || echo "unknown")"
    warn "Existing IONA installation found: ${EXISTING_VER}"
    if [[ "$IONA_YES" -ne 1 ]]; then
        read -p "Continue with installation? [Y/n] " -r REPLY
        [[ "$REPLY" =~ ^[Nn]$ ]] && die "Installation cancelled"
    fi
fi

# ── Resolve version ───────────────────────────────────────────────────────────
if [[ "$IONA_AIR_GAPPED" -ne 1 ]]; then
    section "Resolving version"

    if [[ -z "${IONA_VERSION}" ]]; then
        info "Fetching latest stable release from GitHub..."
        IONA_VERSION="$(
            curl -fsSL \
                -H "Accept: application/vnd.github.v3+json" \
                "${GITHUB_API}/releases/latest" \
            | grep '"tag_name"' \
            | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
        )" || die "Could not fetch latest version. Set IONA_VERSION manually or check your internet connection."
    fi

    # Ensure tag starts with 'v'
    [[ "${IONA_VERSION}" != v* ]] && IONA_VERSION="v${IONA_VERSION}"
    VERSION_CLEAN="${IONA_VERSION#v}"

    ok "Target version: ${IONA_VERSION}"
fi

# ── Decide install method ─────────────────────────────────────────────────────
if [[ "${PREFER_DEB}" == true ]] && [[ "${IS_DEBIAN}" == true ]]; then
    USE_DEB=true
    ok "Install method: .deb package"
else
    USE_DEB=false
    ok "Install method: tarball"
fi

# ── Check dependencies ────────────────────────────────────────────────────────
section "Checking dependencies"

REQUIRED_CMDS=("curl" "tar")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if command_exists "$cmd"; then
        ok "$cmd"
    else
        die "Required tool not found: $cmd"
    fi
done

# SHA256 tool detection
SHA256_CMD=""
if command_exists sha256sum; then
    SHA256_CMD="sha256sum"
    ok "sha256sum"
elif command_exists shasum; then
    SHA256_CMD="shasum -a 256"
    ok "shasum (sha256)"
else
    die "No SHA256 tool found. Install coreutils or equivalent."
fi

# Optional tools
for cmd in gpg cosign sha512sum dpkg; do
    if command_exists "$cmd"; then
        ok "$cmd (optional — available)"
    else
        warn "$cmd not found — some verification steps will be skipped"
    fi
done

# ── Air-gapped mode ───────────────────────────────────────────────────────────
if [[ "$IONA_AIR_GAPPED" -eq 1 ]]; then
    section "Air-gapped installation"
    
    if [[ -z "$IONA_TARBALL" ]]; then
        die "Air-gapped mode requires --tarball <path>"
    fi
    
    if [[ ! -f "$IONA_TARBALL" ]]; then
        die "Tarball not found: $IONA_TARBALL"
    fi
    
    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "${TMPDIR}"' EXIT
    
    cp "$IONA_TARBALL" "${TMPDIR}/"
    DOWNLOAD_FILE="$(basename "$IONA_TARBALL")"
    
    # Try to find checksum files alongside the tarball
    TARBALL_DIR="$(dirname "$IONA_TARBALL")"
    for f in SHA256SUMS SHA256SUMS.asc; do
        if [[ -f "${TARBALL_DIR}/${f}" ]]; then
            cp "${TARBALL_DIR}/${f}" "${TMPDIR}/"
            ok "Found ${f}"
        fi
    done
    
    USE_DEB=false
    ok "Air-gapped mode ready"
else
    # ── Download artefacts ────────────────────────────────────────────────────
    section "Downloading artefacts"

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "${TMPDIR}"' EXIT

    BASE_URL="${GITHUB_DL}/${IONA_VERSION}"

    if [[ "${USE_DEB}" == true ]]; then
        DEB_FILE="iona-node_${VERSION_CLEAN}_${DEB_ARCH}.deb"
        DOWNLOAD_FILE="${DEB_FILE}"
    else
        TARBALL="iona-node-${IONA_VERSION}-${ARCH}-${OS}.tar.gz"
        DOWNLOAD_FILE="${TARBALL}"
    fi

    info "Downloading ${DOWNLOAD_FILE}..."
    curl -fL --progress-bar \
        "${BASE_URL}/${DOWNLOAD_FILE}" \
        -o "${TMPDIR}/${DOWNLOAD_FILE}" \
    || die "Download failed. Verify that ${IONA_VERSION} exists at:\n  https://github.com/${GITHUB_REPO}/releases"

    info "Downloading SHA256SUMS..."
    curl -fsSL "${BASE_URL}/SHA256SUMS" -o "${TMPDIR}/SHA256SUMS" \
    || die "Could not download SHA256SUMS — release may be incomplete or version invalid."

    # Optional artefacts (non-fatal if absent)
    for f in SHA512SUMS SHA256SUMS.asc; do
        curl -fsSL "${BASE_URL}/${f}" -o "${TMPDIR}/${f}" 2>/dev/null && ok "Downloaded ${f}" || true
    done
    for f in "${DOWNLOAD_FILE}.sig" "${DOWNLOAD_FILE}.cert"; do
        curl -fsSL "${BASE_URL}/${f}" -o "${TMPDIR}/${f}" 2>/dev/null && ok "Downloaded ${f}" || true
    done
    curl -fsSL "${BASE_URL}/cosign.pub" -o "${TMPDIR}/cosign.pub" 2>/dev/null || true
    curl -fsSL "${BASE_URL}/iona-release-signing-key.asc" \
        -o "${TMPDIR}/iona-release-signing-key.asc" 2>/dev/null || true

    ok "Download complete: ${DOWNLOAD_FILE}"
fi

# ── Integrity verification ────────────────────────────────────────────────────
section "Verifying integrity"

if [[ "${IONA_SKIP_VERIFY}" == 1 ]]; then
    warn "--skip-verify set — SKIPPING checksum and signature verification"
    warn "This is NOT recommended for production deployments."
else
    # ── SHA-256 (mandatory) ───────────────────────────────────────────────────
    sub_section "SHA-256 checksum verification (mandatory)"
    (
        cd "${TMPDIR}"
        if [[ -f SHA256SUMS ]]; then
            if $SHA256_CMD --check --ignore-missing --strict SHA256SUMS 2>/dev/null; then
                ok "SHA-256 checksum: PASSED"
            else
                die "SHA-256 checksum FAILED.\nThe download may be corrupt or tampered with.\nDo NOT proceed."
            fi
        else
            die "SHA256SUMS not found — cannot verify integrity."
        fi
    )

    # ── SHA-512 (supplementary) ───────────────────────────────────────────────
    if [[ -f "${TMPDIR}/SHA512SUMS" ]] && command_exists sha512sum; then
        sub_section "SHA-512 checksum verification (supplementary)"
        (
            cd "${TMPDIR}"
            if sha512sum --check --ignore-missing --strict SHA512SUMS 2>/dev/null; then
                ok "SHA-512 checksum: PASSED"
            else
                warn "SHA-512 checksum verification failed (non-fatal, but investigate)"
            fi
        )
    fi

    # ── GPG signature ─────────────────────────────────────────────────────────
    if [[ -f "${TMPDIR}/SHA256SUMS.asc" ]] && command_exists gpg; then
        sub_section "GPG signature verification"
        if [[ -f "${TMPDIR}/iona-release-signing-key.asc" ]]; then
            gpg --batch --import "${TMPDIR}/iona-release-signing-key.asc" 2>/dev/null || true
        fi
        if [[ -n "${GPG_KEY_URL:-}" ]]; then
            curl -fsSL "${GPG_KEY_URL}" | gpg --batch --import 2>/dev/null || true
        fi
        if gpg --batch --verify "${TMPDIR}/SHA256SUMS.asc" "${TMPDIR}/SHA256SUMS" 2>/dev/null; then
            ok "GPG signature: VALID"
        else
            warn "GPG signature verification failed — key may not be imported."
            warn "To verify manually: gpg --verify SHA256SUMS.asc SHA256SUMS"
            warn "Fingerprint: see https://iona.network/security"
        fi
    fi

    # ── cosign ────────────────────────────────────────────────────────────────
    if [[ -f "${TMPDIR}/${DOWNLOAD_FILE}.sig" ]] && command_exists cosign; then
        sub_section "cosign signature verification"
        COSIGN_KEY="${COSIGN_PUBLIC_KEY:-}"
        [[ -z "${COSIGN_KEY}" ]] && [[ -f "${TMPDIR}/cosign.pub" ]] && COSIGN_KEY="${TMPDIR}/cosign.pub"
        if [[ -n "${COSIGN_KEY}" ]]; then
            if cosign verify-blob \
                --key "${COSIGN_KEY}" \
                --signature "${TMPDIR}/${DOWNLOAD_FILE}.sig" \
                "${TMPDIR}/${DOWNLOAD_FILE}" 2>/dev/null; then
                ok "cosign signature: VALID"
            else
                warn "cosign verification failed — investigate before continuing"
            fi
        fi
    fi
fi

# ── Installation ──────────────────────────────────────────────────────────────
section "Installing IONA ${IONA_VERSION}"

if [[ "${USE_DEB}" == true ]]; then
    # ── .deb install path ─────────────────────────────────────────────────────
    info "Installing via dpkg..."
    dpkg -i "${TMPDIR}/${DOWNLOAD_FILE}" || {
        warn "dpkg reported dependency issues — attempting fix..."
        apt-get install -f -y
        dpkg -i "${TMPDIR}/${DOWNLOAD_FILE}"
    }
    ok "Package installed"
    dpkg -s iona-node | grep -E "Version|Status" | while read line; do ok "$line"; done

else
    # ── Tarball install path ───────────────────────────────────────────────────
    info "Extracting ${DOWNLOAD_FILE}..."
    tar -xzf "${TMPDIR}/${DOWNLOAD_FILE}" -C "${TMPDIR}/"
    
    # Locate extracted directory
    EXTRACT_DIR="${TMPDIR}/iona-${IONA_VERSION}-${ARCH}-${OS}"
    if [[ ! -d "${EXTRACT_DIR}" ]]; then
        EXTRACT_DIR="$(find "${TMPDIR}" -maxdepth 1 -type d -name 'iona-*' | head -1)"
    fi
    if [[ -z "${EXTRACT_DIR}" ]]; then
        die "Failed to locate extracted directory"
    fi
    ok "Extracted to ${EXTRACT_DIR}"

    # Backup existing binaries if present
    sub_section "Backing up existing installation"
    BACKUP_DIR="${IONA_DATA_DIR}/backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    for bin in iona-node iona-cli iona-remote-signer; do
        if [[ -f "${IONA_INSTALL_DIR}/${bin}" ]]; then
            cp "${IONA_INSTALL_DIR}/${bin}" "${BACKUP_DIR}/${bin}"
            ok "Backed up: ${bin}"
        fi
    done

    # Install binaries
    info "Installing binaries to ${IONA_INSTALL_DIR}/"
    for bin in iona-node iona-cli iona-remote-signer; do
        if [[ -f "${EXTRACT_DIR}/${bin}" ]]; then
            install -m 755 "${EXTRACT_DIR}/${bin}" "${IONA_INSTALL_DIR}/${bin}"
            ok "${IONA_INSTALL_DIR}/${bin}"
        else
            warn "Binary not found: ${bin} (skipping)"
        fi
    done

    # Create system user
    if ! id -u "${IONA_SERVICE_USER}" &>/dev/null; then
        sub_section "Creating system user"
        info "Creating system user: ${IONA_SERVICE_USER}"
        if command_exists adduser; then
            adduser --system --no-create-home --group \
                --home "${IONA_DATA_DIR}" \
                --shell /usr/sbin/nologin \
                "${IONA_SERVICE_USER}" 2>/dev/null \
            || useradd --system --no-create-home \
                --home-dir "${IONA_DATA_DIR}" \
                --shell /usr/sbin/nologin \
                "${IONA_SERVICE_USER}"
        else
            useradd --system --no-create-home \
                --home-dir "${IONA_DATA_DIR}" \
                --shell /usr/sbin/nologin \
                "${IONA_SERVICE_USER}"
        fi
        ok "System user '${IONA_SERVICE_USER}' created"
    else
        ok "System user '${IONA_SERVICE_USER}' already exists"
    fi

    # Create directories with correct permissions
    sub_section "Creating directories"
    for dir in "${IONA_DATA_DIR}" "${IONA_CONFIG_DIR}" "${IONA_LOG_DIR}"; do
        mkdir -p "${dir}"
        chown "${IONA_SERVICE_USER}:${IONA_SERVICE_USER}" "${dir}"
        chmod 0750 "${dir}"
        ok "Directory: ${dir}"
    done

    # Install default config (do not overwrite existing)
    if [[ -f "${IONA_CONFIG_DIR}/config.toml" ]]; then
        # Backup existing config
        cp "${IONA_CONFIG_DIR}/config.toml" "${BACKUP_DIR}/config.toml"
        ok "Existing config backed up to ${BACKUP_DIR}"
    fi

    if [[ ! -f "${IONA_CONFIG_DIR}/config.toml" ]]; then
        if [[ -f "${EXTRACT_DIR}/config.toml.default" ]]; then
            install -m 0640 \
                -o "${IONA_SERVICE_USER}" -g "${IONA_SERVICE_USER}" \
                "${EXTRACT_DIR}/config.toml.default" \
                "${IONA_CONFIG_DIR}/config.toml"
            ok "Default config installed: ${IONA_CONFIG_DIR}/config.toml"
        else
            warn "Default config file not found in tarball"
        fi
    else
        ok "Config already exists — not overwriting: ${IONA_CONFIG_DIR}/config.toml"
    fi

    # Install systemd service
    if [[ "${IONA_SKIP_SERVICE}" != 1 ]] && command_exists systemctl; then
        sub_section "Installing systemd service"
        SERVICE_FILE="/lib/systemd/system/iona-node.service"
        cat > "$SERVICE_FILE" << SERVICE
[Unit]
Description=IONA Blockchain Node v${VERSION_CLEAN}
Documentation=https://github.com/ionablokchain/Iona-protocol
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=exec
User=${IONA_SERVICE_USER}
Group=${IONA_SERVICE_USER}
WorkingDirectory=${IONA_DATA_DIR}
ExecStartPre=${IONA_INSTALL_DIR}/iona-node --check-compat --config ${IONA_CONFIG_DIR}/config.toml
ExecStart=${IONA_INSTALL_DIR}/iona-node --config ${IONA_CONFIG_DIR}/config.toml --profile prod
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
TimeoutStartSec=90
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM

# Security hardening (systemd >= 232)
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${IONA_DATA_DIR} ${IONA_LOG_DIR}
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
SERVICE
        systemctl daemon-reload
        systemctl enable iona-node
        ok "systemd service installed and enabled: iona-node.service"
    fi
fi

# ── Post-install verification ─────────────────────────────────────────────────
section "Post-install verification"

VERIFICATION_FAILED=0

if command_exists "${IONA_INSTALL_DIR}/iona-node"; then
    INSTALLED_VER="$("${IONA_INSTALL_DIR}/iona-node" --version 2>/dev/null || echo "${IONA_VERSION}")"
    ok "iona-node: ${INSTALLED_VER}"
else
    fail_check "iona-node binary not found in ${IONA_INSTALL_DIR}"
    VERIFICATION_FAILED=1
fi

if command_exists "${IONA_INSTALL_DIR}/iona-cli"; then
    ok "iona-cli: available"
else
    warn "iona-cli not found (optional)"
fi

# ── Start service ─────────────────────────────────────────────────────────────
if [[ "${IONA_SKIP_SERVICE}" != 1 ]] && command_exists systemctl; then
    if [[ "${IONA_NO_START}" != 1 ]]; then
        sub_section "Starting service"
        if systemctl start iona-node 2>/dev/null; then
            ok "iona-node service started"
        else
            warn "Service failed to start — this is normal if config.toml is not yet configured."
            warn "Configure first: sudo nano ${IONA_CONFIG_DIR}/config.toml"
            warn "Then start:      sudo systemctl start iona-node"
        fi
        sleep 2
        if systemctl is-active iona-node &>/dev/null; then
            ok "Service status: active (running)"
        else
            warn "Service status: not running (configure then start)"
        fi
    else
        info "IONA_NO_START set — service not started."
        info "To start: sudo systemctl start iona-node"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
section "Installation complete"

echo -e "
  ${BOLD}IONA ${IONA_VERSION} installed successfully!${NC}

  ${CYAN}Binaries${NC}
    ${IONA_INSTALL_DIR}/iona-node
    ${IONA_INSTALL_DIR}/iona-cli
    ${IONA_INSTALL_DIR}/iona-remote-signer

  ${CYAN}Directories${NC}
    Config  : ${IONA_CONFIG_DIR}/config.toml
    Data    : ${IONA_DATA_DIR}/
    Logs    : ${IONA_LOG_DIR}/
    Backup  : ${BACKUP_DIR}/

  ${CYAN}Next steps${NC}
    1. Edit config   : sudo nano ${IONA_CONFIG_DIR}/config.toml
    2. Run doctor    : sudo ${IONA_INSTALL_DIR}/iona-cli doctor
    3. Start service : sudo systemctl start iona-node
    4. View logs     : sudo journalctl -u iona-node -f
    5. Check status  : sudo systemctl status iona-node

  ${CYAN}Verification${NC}
    ${IONA_INSTALL_DIR}/iona-node --version
    ${IONA_INSTALL_DIR}/iona-cli --help

  ${CYAN}Documentation${NC}
    https://github.com/ionablokchain/Iona-protocol/blob/main/README.md
    https://github.com/ionablokchain/Iona-protocol/blob/main/docs/VALIDATOR_KEYS.md

  ${YELLOW}Security issues${NC}
    security@iona.example.com
"

if [[ $VERIFICATION_FAILED -eq 1 ]]; then
    warn "Some post-install checks failed. Review the output above."
    exit 1
fi

exit 0
