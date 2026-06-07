#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IONA Reproducible Build Check — Production‑Grade v2                       ║
# ║                                                                             ║
# ║  Builds the release binary twice in separate, isolated target directories  ║
# ║  and compares the SHA‑256 hashes. If they match, the build is reproducible.║
# ║                                                                             ║
# ║  Usage:                                                                     ║
# ║    ./scripts/repro_check.sh [OPTIONS]                                       ║
# ║                                                                             ║
# ║  Options:                                                                   ║
# ║    --keep            Keep build directories after check (default: remove)  ║
# ║    --verbose         Show detailed cargo output                            ║
# ║    --bin NAME        Binary name to build (default: iona-node)             ║
# ║    --features LIST   Comma-separated cargo features to enable              ║
# ║    --json            Output final result as JSON (for CI/CD)               ║
# ║    --help            Show this help                                        ║
# ║                                                                             ║
# ║  Environment variables (fallback):                                          ║
# ║    BIN_NAME, EXTRA_FEATURES, VERBOSE, KEEP_DIRS, JSON_OUTPUT              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ── Configuration ────────────────────────────────────────────────────────────

BIN_NAME="${BIN_NAME:-iona-node}"
KEEP_DIRS="${KEEP_DIRS:-0}"
VERBOSE="${VERBOSE:-0}"
EXTRA_FEATURES="${EXTRA_FEATURES:-}"
JSON_OUTPUT="${JSON_OUTPUT:-0}"
START_TIME=$(date +%s)

DIR_A="target_repro_a"
DIR_B="target_repro_b"

# Colors for better readability (if terminal supports)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

# ── Helper functions ─────────────────────────────────────────────────────────

log_info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
log_pass()    { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail()    { echo -e "${RED}[FAIL]${NC} $*" >&2; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
log_section() { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}"; }

log_verbose() {
    if [[ "$VERBOSE" -eq 1 ]]; then
        echo -e "[DEBUG] $*"
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

# Detect SHA256 tool (cross-platform)
detect_sha_tool() {
    if command_exists sha256sum; then
        echo "sha256sum"
    elif command_exists shasum; then
        echo "shasum -a 256"
    else
        echo ""
    fi
}

# Cleanup function
cleanup() {
    if [[ "$KEEP_DIRS" -eq 0 ]]; then
        log_verbose "Cleaning up build directories"
        rm -rf "$DIR_A" "$DIR_B"
    else
        log_info "Build directories preserved: $DIR_A, $DIR_B"
    fi
}

# Compute SHA256 of a file
compute_sha() {
    local file="$1"
    local sha_tool="$2"
    if [[ "$sha_tool" == "sha256sum" ]]; then
        sha256sum "$file" | awk '{print $1}'
    else
        shasum -a 256 "$file" | awk '{print $1}'
    fi
}

# ── Parse arguments ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep)        KEEP_DIRS=1; shift ;;
        --verbose)     VERBOSE=1; shift ;;
        --bin)         BIN_NAME="$2"; shift 2 ;;
        --bin=*)       BIN_NAME="${1#*=}"; shift ;;
        --features)    EXTRA_FEATURES="$2"; shift 2 ;;
        --features=*)  EXTRA_FEATURES="${1#*=}"; shift ;;
        --json)        JSON_OUTPUT=1; shift ;;
        --help|-h)
            sed -n '/^# Usage:/,/^# ╚═/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            log_warn "Unknown option: $1"
            shift
            ;;
    esac
done

# ── Trap cleanup ─────────────────────────────────────────────────────────────
trap cleanup EXIT

# ── Main banner ──────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║  IONA Reproducible Build Check v2                                          ║"
echo "║  Started at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')                               ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

# ── Pre-flight checks ────────────────────────────────────────────────────────
log_section "Pre-flight checks"

# Verify we are in the correct directory
if [[ ! -f "Cargo.toml" ]]; then
    log_fail "Cargo.toml not found. Run this script from the project root."
    exit 1
fi
log_verbose "Project root verified (Cargo.toml found)"

# Check dependencies
log_info "Checking dependencies..."
MISSING_DEPS=0
for cmd in cargo; do
    if command_exists "$cmd"; then
        log_verbose "$cmd found"
    else
        log_fail "Required tool not found: $cmd"
        MISSING_DEPS=1
    fi
done

SHA_TOOL=$(detect_sha_tool)
if [[ -z "$SHA_TOOL" ]]; then
    log_fail "No SHA256 tool found (sha256sum or shasum required)"
    exit 1
fi
log_verbose "SHA256 tool: $SHA_TOOL"

if [[ $MISSING_DEPS -eq 1 ]]; then
    exit 1
fi
log_pass "All required tools available"

# Display build info
log_info "Binary name: $BIN_NAME"
log_info "Rust version: $(rustc --version 2>/dev/null || echo 'unknown')"
log_info "Cargo version: $(cargo --version 2>/dev/null || echo 'unknown')"
if [[ -d .git ]]; then
    log_info "Git commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
fi

if [[ -n "$EXTRA_FEATURES" ]]; then
    log_info "Extra features: $EXTRA_FEATURES"
fi

# ── Build feature flags ──────────────────────────────────────────────────────
BUILD_FLAGS="--release --locked --bin \"$BIN_NAME\""
if [[ -n "$EXTRA_FEATURES" ]]; then
    BUILD_FLAGS="$BUILD_FLAGS --features \"$EXTRA_FEATURES\""
fi

# ── Clean previous build directories ─────────────────────────────────────────
log_section "Preparing build directories"

if [[ -d "$DIR_A" ]]; then
    log_info "Removing existing $DIR_A"
    rm -rf "$DIR_A"
fi
if [[ -d "$DIR_B" ]]; then
    log_info "Removing existing $DIR_B"
    rm -rf "$DIR_B"
fi
log_pass "Build directories cleaned"

# ── Build first binary ───────────────────────────────────────────────────────
log_section "Building first binary"

log_info "Building in target directory: $DIR_A"
BUILD_A_START=$(date +%s)

if [[ "$VERBOSE" -eq 1 ]]; then
    CARGO_TARGET_DIR="$DIR_A" cargo build $BUILD_FLAGS
else
    CARGO_TARGET_DIR="$DIR_A" cargo build $BUILD_FLAGS >/dev/null 2>&1
fi

BUILD_A_END=$(date +%s)
BUILD_A_DURATION=$((BUILD_A_END - BUILD_A_START))

if [[ ! -f "$DIR_A/release/$BIN_NAME" ]]; then
    log_fail "First build failed: binary not found at $DIR_A/release/$BIN_NAME"
    exit 1
fi
log_pass "First build completed (${BUILD_A_DURATION}s)"

# ── Build second binary ──────────────────────────────────────────────────────
log_section "Building second binary"

log_info "Building in target directory: $DIR_B"
BUILD_B_START=$(date +%s)

if [[ "$VERBOSE" -eq 1 ]]; then
    CARGO_TARGET_DIR="$DIR_B" cargo build $BUILD_FLAGS
else
    CARGO_TARGET_DIR="$DIR_B" cargo build $BUILD_FLAGS >/dev/null 2>&1
fi

BUILD_B_END=$(date +%s)
BUILD_B_DURATION=$((BUILD_B_END - BUILD_B_START))

if [[ ! -f "$DIR_B/release/$BIN_NAME" ]]; then
    log_fail "Second build failed: binary not found at $DIR_B/release/$BIN_NAME"
    exit 1
fi
log_pass "Second build completed (${BUILD_B_DURATION}s)"

# ── Compute and compare SHA‑256 hashes ───────────────────────────────────────
log_section "Comparing build artifacts"

log_info "Computing SHA‑256 hashes..."
SHA_A=$(compute_sha "$DIR_A/release/$BIN_NAME" "$SHA_TOOL")
SHA_B=$(compute_sha "$DIR_B/release/$BIN_NAME" "$SHA_TOOL")

echo ""
echo "  Build A ($DIR_A): $SHA_A"
echo "  Build B ($DIR_B): $SHA_B"
echo ""

# Compare file sizes as a secondary check
SIZE_A=$(stat -c %s "$DIR_A/release/$BIN_NAME" 2>/dev/null || stat -f %z "$DIR_A/release/$BIN_NAME" 2>/dev/null || echo "0")
SIZE_B=$(stat -c %s "$DIR_B/release/$BIN_NAME" 2>/dev/null || stat -f %z "$DIR_B/release/$BIN_NAME" 2>/dev/null || echo "0")

END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

# ── Result ───────────────────────────────────────────────────────────────────
log_section "Result"

REPRODUCIBLE=false
if [[ "$SHA_A" == "$SHA_B" ]]; then
    REPRODUCIBLE=true
    log_pass "Reproducible build check PASSED — both builds produced identical binary"
    log_pass "Hash: $SHA_A"
    log_pass "Size: $SIZE_A bytes"
else
    log_fail "Reproducible build check FAILED — hashes differ"
    log_fail "Build A: $SHA_A (${SIZE_A} bytes)"
    log_fail "Build B: $SHA_B (${SIZE_B} bytes)"
fi

echo ""
log_info "Build A duration: ${BUILD_A_DURATION}s"
log_info "Build B duration: ${BUILD_B_DURATION}s"
log_info "Total duration: ${TOTAL_DURATION}s"

# ── JSON output (for CI/CD) ─────────────────────────────────────────────────
if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    if command_exists jq; then
        jq -n \
            --arg reproducible "$REPRODUCIBLE" \
            --arg sha_a "$SHA_A" \
            --arg sha_b "$SHA_B" \
            --arg size_a "$SIZE_A" \
            --arg size_b "$SIZE_B" \
            --argjson build_a_duration "$BUILD_A_DURATION" \
            --argjson build_b_duration "$BUILD_B_DURATION" \
            --argjson total_duration "$TOTAL_DURATION" \
            --arg bin_name "$BIN_NAME" \
            --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
            '{
                reproducible: $reproducible,
                hash_a: $sha_a,
                hash_b: $sha_b,
                size_a: $size_a,
                size_b: $size_b,
                build_a_duration_s: $build_a_duration,
                build_b_duration_s: $build_b_duration,
                total_duration_s: $total_duration,
                bin_name: $bin_name,
                timestamp: $timestamp
            }'
    else
        # Fallback JSON without jq
        cat <<EOF
{
  "reproducible": $REPRODUCIBLE,
  "hash_a": "$SHA_A",
  "hash_b": "$SHA_B",
  "size_a": $SIZE_A,
  "size_b": $SIZE_B,
  "build_a_duration_s": $BUILD_A_DURATION,
  "build_b_duration_s": $BUILD_B_DURATION,
  "total_duration_s": $TOTAL_DURATION,
  "bin_name": "$BIN_NAME",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}
EOF
    fi
fi

# ── Exit ─────────────────────────────────────────────────────────────────────
if [[ "$REPRODUCIBLE" == true ]]; then
    exit 0
else
    exit 2
fi
