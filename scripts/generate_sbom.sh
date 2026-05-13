#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
#  IONA SBOM & Hash Generator — Production‑Grade
# =============================================================================
#  Generates a CycloneDX SBOM (Software Bill of Materials) and SHA256
#  hashes for all release artifacts.
#
#  Usage:
#    ./scripts/sbom.sh [OPTIONS]
#
#  Options:
#    --sbom-out FILE     Output path for SBOM (default: sbom.cdx.json)
#    --dist-dir DIR      Directory containing release artifacts (default: dist)
#    --bin-name NAME     Name of the binary (default: iona-node)
#    --skip-build        Skip building even if dist directory is empty
#    --verbose           Enable detailed output
#    --help              Show this help
#
#  Environment variables (fallback):
#    SBOM_OUT, DIST_DIR, BIN_NAME, SKIP_BUILD, VERBOSE
# =============================================================================

# ── Configuration ────────────────────────────────────────────────────────────
SBOM_OUT="${SBOM_OUT:-sbom.cdx.json}"
DIST_DIR="${DIST_DIR:-dist}"
BIN_NAME="${BIN_NAME:-iona-node}"
SKIP_BUILD="${SKIP_BUILD:-0}"
VERBOSE="${VERBOSE:-0}"

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sbom-out)     SBOM_OUT="$2"; shift 2 ;;
    --dist-dir)     DIST_DIR="$2"; shift 2 ;;
    --bin-name)     BIN_NAME="$2"; shift 2 ;;
    --skip-build)   SKIP_BUILD=1; shift ;;
    --verbose)      VERBOSE=1; shift ;;
    --help)         cat <<EOF; exit 0 ;;
Usage: $0 [OPTIONS]

Options:
  --sbom-out FILE     Output path for SBOM (default: sbom.cdx.json)
  --dist-dir DIR      Directory containing release artifacts (default: dist)
  --bin-name NAME     Name of the binary (default: iona-node)
  --skip-build        Skip building even if dist directory is empty
  --verbose           Enable detailed output
  --help              Show this help
EOF
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

PASS=0
FAIL=0
START_TIME=$(date +%s)

# ── Colours (safe for non‑TTY) ──────────────────────────────────────────────
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''
fi

# ── Helper functions ────────────────────────────────────────────────────────
log_info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $*"; PASS=$((PASS + 1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAIL=$((FAIL + 1)); }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
log_verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "[DEBUG] $*"; }

cmd_exists() { command -v "$1" &>/dev/null; }

# Run a command with optional verbose output
run_cmd() {
  local desc="$1"
  local cmd="$2"
  log_verbose "Running: $cmd"
  if [[ "$VERBOSE" -eq 1 ]]; then
    eval "$cmd" 2>&1
  else
    eval "$cmd" >/dev/null 2>&1
  fi
  local ret=$?
  if [[ $ret -eq 0 ]]; then
    log_pass "$desc"
    return 0
  else
    log_fail "$desc"
    return 1
  fi
}

# ── Main banner ─────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  IONA SBOM & Hash Generator                                         ║"
echo "║  Started at: $(date '+%Y-%m-%d %H:%M:%S')                           ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

# 1. Prepare dist directory
if [[ ! -d "$DIST_DIR" ]]; then
  log_info "Creating dist directory: $DIST_DIR"
  mkdir -p "$DIST_DIR"
fi

# 2. Build binary if needed
NEED_BUILD=0
if [[ "$SKIP_BUILD" -eq 1 ]]; then
  log_info "Skipping build (SKIP_BUILD=1)"
elif [[ -z "$(ls -A "$DIST_DIR" 2>/dev/null)" ]]; then
  NEED_BUILD=1
else
  log_info "Dist directory already contains files; skipping build"
fi

if [[ $NEED_BUILD -eq 1 ]]; then
  log_info "Building release binary..."
  if run_cmd "release build" "cargo build --release --locked --bin \"$BIN_NAME\""; then
    cp "target/release/$BIN_NAME" "$DIST_DIR/"
    log_info "Copied binary to $DIST_DIR/$BIN_NAME"
  else
    log_fail "Binary build failed"
    exit 1
  fi
fi

# 3. Generate SBOM (CycloneDX)
log_info "Generating SBOM (CycloneDX)..."
SBOM_GENERATED=0
if cmd_exists cargo-cyclonedx && cargo cyclonedx --help &>/dev/null 2>&1; then
  if run_cmd "SBOM generation (cargo-cyclonedx)" "cargo cyclonedx --format json --output \"$SBOM_OUT\""; then
    cp "$SBOM_OUT" "$DIST_DIR/" 2>/dev/null && log_verbose "Copied SBOM to $DIST_DIR/"
    SBOM_GENERATED=1
  fi
elif cmd_exists cargo-sbom && cargo sbom --help &>/dev/null 2>&1; then
  # Alternative tool: cargo-sbom
  if run_cmd "SBOM generation (cargo-sbom)" "cargo sbom --output-format cyclonedx --output \"$SBOM_OUT\""; then
    cp "$SBOM_OUT" "$DIST_DIR/" 2>/dev/null && log_verbose "Copied SBOM to $DIST_DIR/"
    SBOM_GENERATED=1
  fi
elif cmd_exists cargo-deny && cargo deny --help &>/dev/null 2>&1; then
  # cargo deny can produce a licence report but not native SBOM. We'll try a fallback.
  log_warn "cargo-deny found but does not produce SBOM directly; install cargo-cyclonedx or cargo-sbom"
fi

if [[ $SBOM_GENERATED -eq 0 ]]; then
  log_warn "No SBOM tool found. Install cargo-cyclonedx: cargo install cargo-cyclonedx"
fi

# 4. Generate SHA256 checksums
log_info "Generating SHA256 checksums..."
if [[ -d "$DIST_DIR" && -n "$(ls -A "$DIST_DIR" 2>/dev/null)" ]]; then
  (
    cd "$DIST_DIR"
    # Determine checksum command
    if cmd_exists sha256sum; then
      SHACMD="sha256sum"
    elif cmd_exists shasum; then
      SHACMD="shasum -a 256"
    else
      log_fail "No SHA256 tool found (sha256sum or shasum)"
      exit 1
    fi
    log_verbose "Using checksum command: $SHACMD"
    # Generate checksums, skipping the SHA256SUMS.txt file itself
    for file in *; do
      [[ "$file" == "SHA256SUMS.txt" ]] && continue
      if [[ -f "$file" ]]; then
        $SHACMD "$file" >> SHA256SUMS.txt
      fi
    done
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
