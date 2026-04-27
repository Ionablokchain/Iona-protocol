#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IONA Reproducible Build Check                                             ║
# ║                                                                             ║
# ║  Builds the release binary twice in separate target directories and        ║
# ║  compares the SHA‑256 hashes. If they match, the build is reproducible.    ║
# ║                                                                             ║
# ║  Usage:                                                                     ║
# ║    ./scripts/repro_check.sh [--keep] [--verbose] [--bin NAME]              ║
# ║                                                                             ║
# ║  Options:                                                                   ║
# ║    --keep       Keep build directories after check (default: remove)       ║
# ║    --verbose    Show detailed cargo output                                 ║
# ║    --bin NAME   Binary name to build (default: iona-node)                  ║
# ║    --help       Show this help                                             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ── Configuration ────────────────────────────────────────────────────────────

BIN_NAME="${BIN_NAME:-iona-node}"
KEEP_DIRS=false
VERBOSE=false
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
    echo -e "${CYAN}[INFO]${NC} $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "[DEBUG] $*"
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

# ── Parse arguments ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep)        KEEP_DIRS=true; shift ;;
        --verbose)     VERBOSE=true; shift ;;
        --bin)         BIN_NAME="$2"; shift 2 ;;
        --bin=*)       BIN_NAME="${1#*=}"; shift ;;
        --help|-h)     sed -n '/^# Usage:/,/^# ──/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)             log_warn "Unknown option: $1"; shift ;;
    esac
done

# ── Dependency checks ────────────────────────────────────────────────────────

log_info "Checking dependencies..."
for cmd in cargo sha256sum; do
    if command_exists "$cmd"; then
        log_verbose "$cmd found"
    else
        log_fail "Required tool not found: $cmd"
        exit 1
    fi
done
log_pass "All required tools available"

# ── Clean previous build directories ─────────────────────────────────────────

DIR_A="target_repro_a"
DIR_B="target_repro_b"

if [[ -d "$DIR_A" ]]; then
    log_verbose "Removing existing $DIR_A"
    rm -rf "$DIR_A"
fi
if [[ -d "$DIR_B" ]]; then
    log_verbose "Removing existing $DIR_B"
    rm -rf "$DIR_B"
fi

# ── Build first binary ───────────────────────────────────────────────────────

log_info "Building first binary (target directory: $DIR_A)..."
if [[ "$VERBOSE" == true ]]; then
    CARGO_TARGET_DIR="$DIR_A" cargo build --release --locked --bin "$BIN_NAME"
else
    CARGO_TARGET_DIR="$DIR_A" cargo build --release --locked --bin "$BIN_NAME" 2>&1 >/dev/null
fi

if [[ ! -f "$DIR_A/release/$BIN_NAME" ]]; then
    log_fail "First build failed: binary not found at $DIR_A/release/$BIN_NAME"
    exit 1
fi
log_pass "First build completed"

# ── Build second binary ──────────────────────────────────────────────────────

log_info "Building second binary (target directory: $DIR_B)..."
if [[ "$VERBOSE" == true ]]; then
    CARGO_TARGET_DIR="$DIR_B" cargo build --release --locked --bin "$BIN_NAME"
else
    CARGO_TARGET_DIR="$DIR_B" cargo build --release --locked --bin "$BIN_NAME" 2>&1 >/dev/null
fi

if [[ ! -f "$DIR_B/release/$BIN_NAME" ]]; then
    log_fail "Second build failed: binary not found at $DIR_B/release/$BIN_NAME"
    exit 1
fi
log_pass "Second build completed"

# ── Compute and compare SHA‑256 hashes ───────────────────────────────────────

log_info "Computing SHA‑256 hashes..."
SHA_A=$(sha256sum "$DIR_A/release/$BIN_NAME" | awk '{print $1}')
SHA_B=$(sha256sum "$DIR_B/release/$BIN_NAME" | awk '{print $1}')

echo ""
echo "  Build A (target_repro_a): $SHA_A"
echo "  Build B (target_repro_b): $SHA_B"
echo ""

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

if [[ "$SHA_A" != "$SHA_B" ]]; then
    log_fail "Reproducible build check FAILED — hashes differ"
    log_fail "Duration: ${DURATION}s"
    if [[ "$KEEP_DIRS" == false ]]; then
        log_info "Cleaning up build directories (use --keep to preserve)"
        rm -rf "$DIR_A" "$DIR_B"
    else
        log_info "Build directories preserved: $DIR_A, $DIR_B"
    fi
    exit 2
else
    log_pass "Reproducible build check PASSED — both builds produced identical binary"
    log_pass "Duration: ${DURATION}s"
    if [[ "$KEEP_DIRS" == false ]]; then
        log_info "Cleaning up build directories"
        rm -rf "$DIR_A" "$DIR_B"
    else
        log_info "Build directories preserved: $DIR_A, $DIR_B"
    fi
    exit 0
fi
