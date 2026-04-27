#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IONA SBOM & Hash Generator                                                ║
# ║                                                                             ║
# ║  Generates a CycloneDX SBOM (Software Bill of Materials) and SHA256        ║
# ║  hashes for all release artifacts.                                         ║
# ║                                                                             ║
# ║  Usage:                                                                     ║
# ║    ./scripts/sbom.sh [SBOM_OUT] [DIST_DIR]                                 ║
# ║                                                                             ║
# ║  Environment variables:                                                    ║
# ║    SBOM_OUT       - output path for SBOM (default: sbom.cdx.json)          ║
# ║    DIST_DIR       - directory containing release artifacts (default: dist) ║
# ║    BIN_NAME       - name of the binary to build (default: iona-node)       ║
# ║    SKIP_BUILD     - set to 1 to skip building if dist dir exists           ║
# ║    VERBOSE        - set to 1 for detailed output                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ── Configuration ────────────────────────────────────────────────────────────

SBOM_OUT="${1:-${SBOM_OUT:-sbom.cdx.json}}"
DIST_DIR="${2:-${DIST_DIR:-dist}}"
BIN_NAME="${BIN_NAME:-iona-node}"
SKIP_BUILD="${SKIP_BUILD:-0}"
VERBOSE="${VERBOSE:-0}"

PASS=0
FAIL=0
START_TIME=$(date +%s)

# Colors for better readability (if terminal supports)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    NC='\033[0m' # No Color
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''
fi

# ── Helper functions ─────────────────────────────────────────────────────────

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASS=$((PASS + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1" >&2
    FAIL=$((FAIL + 1))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_verbose() {
    if [[ "$VERBOSE" -eq 1 ]]; then
        echo -e "[DEBUG] $1"
    fi
}

# Check if a command exists
require_cmd() {
    if ! command -v "$1" &> /dev/null; then
        log_warn "$1 not installed; skipping related operation"
        return 1
    fi
    return 0
}

# ── Main ─────────────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  IONA SBOM & Hash Generator                                         ║"
echo "║  Started at: $(date '+%Y-%m-%d %H:%M:%S')                           ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

# 1. Ensure dist directory exists
if [[ ! -d "$DIST_DIR" ]]; then
    log_info "Creating dist directory: $DIST_DIR"
    mkdir -p "$DIST_DIR"
fi

# 2. Build the binary if dist directory is empty or SKIP_BUILD is not set
NEED_BUILD=0
if [[ "$SKIP_BUILD" -eq 1 ]]; then
    log_info "SKIP_BUILD is set; skipping build"
elif [[ -z "$(ls -A "$DIST_DIR" 2>/dev/null)" ]]; then
    NEED_BUILD=1
else
    log_info "Dist directory already contains files; skipping build (use SKIP_BUILD=0 to force rebuild)"
fi

if [[ $NEED_BUILD -eq 1 ]]; then
    log_info "Building release binary..."
    if cargo build --release --locked --bin "$BIN_NAME" 2>&1; then
        cp "target/release/$BIN_NAME" "$DIST_DIR/"
        log_pass "Binary built and copied to $DIST_DIR/$BIN_NAME"
    else
        log_fail "Release build failed"
        exit 1
    fi
fi

# 3. Generate SBOM (CycloneDX)
log_info "Generating SBOM (CycloneDX)..."
if require_cmd "cargo-cyclonedx" && cargo cyclonedx --help &>/dev/null 2>&1; then
    if cargo cyclonedx --format json --output "$SBOM_OUT" 2>&1; then
        log_pass "SBOM generated: $SBOM_OUT"
        # Optionally copy to dist directory
        cp "$SBOM_OUT" "$DIST_DIR/" 2>/dev/null && log_verbose "Copied SBOM to $DIST_DIR/"
    else
        log_fail "SBOM generation failed"
    fi
else
    log_warn "cargo-cyclonedx not installed; skipping SBOM generation"
    log_info "Install with: cargo install cargo-cyclonedx"
fi

# 4. Generate SHA256SUMS.txt
log_info "Generating SHA256 hashes..."
if [[ -d "$DIST_DIR" && -n "$(ls -A "$DIST_DIR" 2>/dev/null)" ]]; then
    (
        cd "$DIST_DIR"
        # Use either sha256sum (Linux) or shasum -a 256 (macOS)
        if command -v sha256sum &> /dev/null; then
            sha256sum * > SHA256SUMS.txt 2>/dev/null
        elif command -v shasum &> /dev/null; then
            shasum -a 256 * > SHA256SUMS.txt
        else
            log_fail "Neither sha256sum nor shasum found"
            exit 1
        fi
    )
    log_pass "SHA256SUMS.txt generated in $DIST_DIR/"
    if [[ "$VERBOSE" -eq 1 ]]; then
        echo ""
        echo "Contents of $DIST_DIR/SHA256SUMS.txt:"
        cat "$DIST_DIR/SHA256SUMS.txt"
    fi
else
    log_warn "No artifacts found in $DIST_DIR; cannot generate SHA256SUMS"
fi

# 5. Summary
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "  SBOM & Hash Generation Completed"
echo "  Duration: ${DURATION}s"
echo "  Artifacts directory: $DIST_DIR"
echo "  SBOM: $SBOM_OUT"
if [[ -f "$DIST_DIR/SHA256SUMS.txt" ]]; then
    echo "  Hashes: $DIST_DIR/SHA256SUMS.txt"
fi
echo "  Total failures: $FAIL"
if [[ $FAIL -gt 0 ]]; then
    echo "  STATUS: COMPLETED WITH ERRORS"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    exit 1
else
    echo "  STATUS: SUCCESS"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    exit 0
fi
