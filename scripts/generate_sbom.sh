#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
#  IONA SBOM & Hash Generator — Production‑Grade v2
# =============================================================================
#  Generates a CycloneDX or SPDX SBOM (Software Bill of Materials) and
#  SHA256 hashes for all release artifacts. Supports multiple SBOM tools
#  and provides integrity verification.
#
#  Usage:
#    ./scripts/sbom.sh [OPTIONS]
#
#  Options:
#    --sbom-out FILE       Output path for SBOM (default: sbom.cdx.json)
#    --sbom-format FORMAT  SBOM format: cyclonedx | spdx (default: cyclonedx)
#    --dist-dir DIR        Directory containing release artifacts (default: dist)
#    --bin-name NAME       Name of the binary (default: iona-node)
#    --cargo-lock PATH     Path to Cargo.lock (default: ./Cargo.lock)
#    --include-cargo-lock  Include Cargo.lock in the dist directory
#    --verify              Verify generated checksums after creation
#    --skip-build          Skip building even if dist directory is empty
#    --verbose             Enable detailed output
#    --json                Output final summary as JSON
#    --help                Show this help
#
#  Environment variables (fallback):
#    SBOM_OUT, SBOM_FORMAT, DIST_DIR, BIN_NAME, CARGO_LOCK,
#    SKIP_BUILD, VERBOSE, INCLUDE_CARGO_LOCK
# =============================================================================

# ── Configuration ────────────────────────────────────────────────────────────
SBOM_OUT="${SBOM_OUT:-sbom.cdx.json}"
SBOM_FORMAT="${SBOM_FORMAT:-cyclonedx}"
DIST_DIR="${DIST_DIR:-dist}"
BIN_NAME="${BIN_NAME:-iona-node}"
CARGO_LOCK="${CARGO_LOCK:-Cargo.lock}"
SKIP_BUILD="${SKIP_BUILD:-0}"
VERBOSE="${VERBOSE:-0}"
INCLUDE_CARGO_LOCK="${INCLUDE_CARGO_LOCK:-0}"
VERIFY="${VERIFY:-0}"
JSON_OUTPUT="${JSON_OUTPUT:-0}"

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sbom-out)          SBOM_OUT="$2"; shift 2 ;;
    --sbom-format)       SBOM_FORMAT="$2"; shift 2 ;;
    --dist-dir)          DIST_DIR="$2"; shift 2 ;;
    --bin-name)          BIN_NAME="$2"; shift 2 ;;
    --cargo-lock)        CARGO_LOCK="$2"; shift 2 ;;
    --include-cargo-lock) INCLUDE_CARGO_LOCK=1; shift ;;
    --verify)            VERIFY=1; shift ;;
    --skip-build)        SKIP_BUILD=1; shift ;;
    --verbose)           VERBOSE=1; shift ;;
    --json)              JSON_OUTPUT=1; shift ;;
    --help)
      sed -n '2,/^$/p' "$0" | sed 's/^# //'
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Initialize counters ──────────────────────────────────────────────────────
PASS=0
FAIL=0
WARN=0
START_TIME=$(date +%s)
SBOM_TOOL=""
SBOM_GENERATED=0
HASHES_GENERATED=0

# ── Colours (safe for non‑TTY) ──────────────────────────────────────────────
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''
fi

# ── Helper functions ────────────────────────────────────────────────────────
log_info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
log_pass()    { echo -e "${GREEN}[PASS]${NC} $*"; PASS=$((PASS + 1)); }
log_fail()    { echo -e "${RED}[FAIL]${NC} $*" >&2; FAIL=$((FAIL + 1)); }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*" >&2; WARN=$((WARN + 1)); }
log_verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "[DEBUG] $*"; }

cmd_exists() { command -v "$1" &>/dev/null; }

# Run a command with optional verbose output capture
run_cmd() {
  local desc="$1"
  local cmd="$2"
  local logfile=""
  log_verbose "Running: $cmd"
  if [[ "$VERBOSE" -eq 1 ]]; then
    logfile="/tmp/iona_sbom_${RANDOM}.log"
    echo "  → Log: $logfile"
    if eval "$cmd" >"$logfile" 2>&1; then
      log_pass "$desc"
      rm -f "$logfile"
      return 0
    else
      log_fail "$desc"
      echo "  Log saved: $logfile"
      return 1
    fi
  else
    if eval "$cmd" >/dev/null 2>&1; then
      log_pass "$desc"
      return 0
    else
      log_fail "$desc"
      return 1
    fi
  fi
}

# Detect available SHA256 tool
detect_sha_tool() {
  if cmd_exists sha256sum; then
    echo "sha256sum"
  elif cmd_exists shasum; then
    echo "shasum -a 256"
  else
    echo ""
  fi
}

# Validate SBOM format
validate_sbom_format() {
  case "$SBOM_FORMAT" in
    cyclonedx|cdx|json) SBOM_FORMAT="cyclonedx" ;;
    spdx)               SBOM_FORMAT="spdx" ;;
    *)
      log_fail "Unsupported SBOM format: $SBOM_FORMAT (use cyclonedx or spdx)"
      exit 1
      ;;
  esac
}

# ── Main banner ─────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  IONA SBOM & Hash Generator v2                                      ║"
echo "║  Started at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')                       ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

# ── Pre-flight checks ───────────────────────────────────────────────────────
log_info "Running pre-flight checks..."

# Validate SBOM format
validate_sbom_format

# Check Cargo.lock existence
if [[ ! -f "$CARGO_LOCK" ]]; then
  log_fail "Cargo.lock not found at $CARGO_LOCK"
  exit 1
fi
log_verbose "Cargo.lock found: $CARGO_LOCK"

# Check for required tools
if ! cmd_exists cargo; then
  log_fail "cargo is required but not installed"
  exit 1
fi

# 1. Prepare dist directory
log_info "Preparing distribution directory: $DIST_DIR"
if [[ ! -d "$DIST_DIR" ]]; then
  mkdir -p "$DIST_DIR"
  log_verbose "Created directory: $DIST_DIR"
fi

# 2. Build binary if needed
NEED_BUILD=0
if [[ "$SKIP_BUILD" -eq 1 ]]; then
  log_info "Skipping build (SKIP_BUILD=1)"
elif [[ -z "$(ls -A "$DIST_DIR" 2>/dev/null)" ]]; then
  NEED_BUILD=1
  log_info "Dist directory is empty; will build"
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

# 3. Include Cargo.lock if requested
if [[ "$INCLUDE_CARGO_LOCK" -eq 1 ]]; then
  if [[ -f "$CARGO_LOCK" ]]; then
    cp "$CARGO_LOCK" "$DIST_DIR/Cargo.lock"
    log_info "Included Cargo.lock in $DIST_DIR/"
  fi
fi

# 4. Generate SBOM
log_info "Generating SBOM (format: $SBOM_FORMAT)..."

# Determine output filename based on format
case "$SBOM_FORMAT" in
  cyclonedx)
    SBOM_EXT="cdx.json"
    ;;
  spdx)
    SBOM_EXT="spdx.json"
    ;;
esac

# If SBOM_OUT doesn't have the right extension, adjust it
if [[ ! "$SBOM_OUT" =~ \.${SBOM_EXT}$ ]]; then
  SBOM_OUT="${SBOM_OUT%.*}.${SBOM_EXT}"
  log_verbose "Adjusted SBOM output to: $SBOM_OUT"
fi

# Try cargo-cyclonedx (preferred)
if cmd_exists cargo-cyclonedx; then
  SBOM_TOOL="cargo-cyclonedx"
  if [[ "$SBOM_FORMAT" == "spdx" ]]; then
    log_warn "cargo-cyclonedx does not support SPDX; falling back to CycloneDX"
    SBOM_FORMAT="cyclonedx"
  fi
  if run_cmd "SBOM generation ($SBOM_TOOL)" \
    "cargo cyclonedx --format json --output \"$SBOM_OUT\""; then
    SBOM_GENERATED=1
  fi

# Try cargo-sbom
elif cmd_exists cargo-sbom; then
  SBOM_TOOL="cargo-sbom"
  local format_flag="--output-format"
  if [[ "$SBOM_FORMAT" == "spdx" ]]; then
    format_flag="--output-format spdx"
  else
    format_flag="--output-format cyclonedx"
  fi
  if run_cmd "SBOM generation ($SBOM_TOOL)" \
    "cargo sbom $format_flag --output \"$SBOM_OUT\""; then
    SBOM_GENERATED=1
  fi

# Try cargo-deny (limited SBOM)
elif cmd_exists cargo-deny; then
  SBOM_TOOL="cargo-deny"
  log_warn "cargo-deny provides limited SBOM; consider installing cargo-cyclonedx"
  if run_cmd "SBOM generation ($SBOM_TOOL)" \
    "cargo deny check licenses --format json > \"$SBOM_OUT\""; then
    SBOM_GENERATED=1
  fi
fi

if [[ $SBOM_GENERATED -eq 1 ]]; then
  log_info "SBOM generated with $SBOM_TOOL"
  # Copy to dist directory
  cp "$SBOM_OUT" "$DIST_DIR/" 2>/dev/null && log_verbose "Copied SBOM to $DIST_DIR/"
else
  log_warn "No SBOM tool found. Install one of: cargo-cyclonedx, cargo-sbom"
  log_warn "  cargo install cargo-cyclonedx"
fi

# 5. Generate SHA256 checksums
log_info "Generating SHA256 checksums..."

SHA_TOOL=$(detect_sha_tool)
if [[ -z "$SHA_TOOL" ]]; then
  log_fail "No SHA256 tool found (sha256sum or shasum required)"
  exit 1
fi
log_verbose "Using checksum tool: $SHA_TOOL"

if [[ -d "$DIST_DIR" && -n "$(ls -A "$DIST_DIR" 2>/dev/null)" ]]; then
  CHECKSUM_FILE="$DIST_DIR/SHA256SUMS.txt"
  # Remove old checksum file if exists
  rm -f "$CHECKSUM_FILE"

  (
    cd "$DIST_DIR"
    for file in *; do
      # Skip the checksum file itself and directories
      [[ "$file" == "SHA256SUMS.txt" ]] && continue
      [[ -d "$file" ]] && continue
      if [[ -f "$file" ]]; then
        $SHA_TOOL "$file" >> "$CHECKSUM_FILE"
      fi
    done
  )

  if [[ -f "$CHECKSUM_FILE" ]]; then
    HASHES_GENERATED=1
    log_pass "SHA256SUMS.txt generated in $DIST_DIR/"
    if [[ "$VERBOSE" -eq 1 ]]; then
      echo ""
      echo "Contents of $CHECKSUM_FILE:"
      cat "$CHECKSUM_FILE"
    fi
  else
    log_fail "Failed to create SHA256SUMS.txt"
  fi
else
  log_warn "No artifacts found in $DIST_DIR; cannot generate SHA256SUMS"
fi

# 6. Verify checksums (if requested)
if [[ "$VERIFY" -eq 1 && "$HASHES_GENERATED" -eq 1 ]]; then
  log_info "Verifying checksums..."
  CHECKSUM_FILE="$DIST_DIR/SHA256SUMS.txt"
  if [[ -f "$CHECKSUM_FILE" ]]; then
    (
      cd "$DIST_DIR"
      if cmd_exists sha256sum; then
        if sha256sum -c "$CHECKSUM_FILE" >/dev/null 2>&1; then
          log_pass "checksum verification passed"
        else
          log_fail "checksum verification failed"
        fi
      elif cmd_exists shasum; then
        if shasum -a 256 -c "$CHECKSUM_FILE" >/dev/null 2>&1; then
          log_pass "checksum verification passed"
        else
          log_fail "checksum verification failed"
        fi
      fi
    )
  fi
fi

# 7. Generate metadata file
log_info "Generating release metadata..."
METADATA_FILE="$DIST_DIR/release-metadata.json"
cat > "$METADATA_FILE" << EOF
{
  "project": "IONA",
  "version": "$(cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r '.packages[] | select(.name == "iona-node") | .version' 2>/dev/null || echo 'unknown')",
  "build_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "binary": "$BIN_NAME",
  "sbom_tool": "${SBOM_TOOL:-none}",
  "sbom_format": "$SBOM_FORMAT",
  "checksum_algorithm": "SHA256"
}
EOF
log_pass "metadata generated: $METADATA_FILE"

# 8. List artifacts
log_info "Release artifacts:"
if [[ -d "$DIST_DIR" ]]; then
  for file in "$DIST_DIR"/*; do
    if [[ -f "$file" ]]; then
      size=$(du -h "$file" 2>/dev/null | awk '{print $1}' || echo "?")
      echo "  $file ($size)"
    fi
  done
fi

# ── Summary ─────────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                       SBOM & HASH SUMMARY                           ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  %-20s %3d                                              ║\n" "Passed:" "$PASS"
printf "║  %-20s %3d                                              ║\n" "Failed:" "$FAIL"
printf "║  %-20s %3d                                              ║\n" "Warnings:" "$WARN"
printf "║  %-20s %3ds                                            ║\n" "Duration:" "$DURATION"
printf "║  %-20s %s                                             ║\n" "Dist dir:" "$DIST_DIR"
printf "║  %-20s %s                                             ║\n" "SBOM:" "$([[ $SBOM_GENERATED -eq 1 ]] && echo "$SBOM_OUT" || echo 'not generated')"
printf "║  %-20s %s                                             ║\n" "Hashes:" "$([[ $HASHES_GENERATED -eq 1 ]] && echo "$DIST_DIR/SHA256SUMS.txt" || echo 'not generated')"
if [[ $FAIL -gt 0 ]]; then
  echo "╠══════════════════════════════════════════════════════════════════════╣"
  echo "║  STATUS: COMPLETED WITH ERRORS                                      ║"
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    jq -n \
      --arg status "FAIL" \
      --argjson pass "$PASS" \
      --argjson fail "$FAIL" \
      --argjson warn "$WARN" \
      --argjson duration "$DURATION" \
      --arg sbom "$SBOM_OUT" \
      --arg sbom_generated "$SBOM_GENERATED" \
      --arg hashes_generated "$HASHES_GENERATED" \
      '{status: $status, passed: $pass, failed: $fail, warnings: $warn, duration_s: $duration, sbom: $sbom, sbom_generated: $sbom_generated, hashes_generated: $hashes_generated}'
  fi
  exit 1
else
  echo "╠══════════════════════════════════════════════════════════════════════╣"
  echo "║  STATUS: SUCCESS                                                    ║"
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    jq -n \
      --arg status "SUCCESS" \
      --argjson pass "$PASS" \
      --argjson fail "$FAIL" \
      --argjson warn "$WARN" \
      --argjson duration "$DURATION" \
      --arg sbom "$SBOM_OUT" \
      --arg sbom_generated "$SBOM_GENERATED" \
      --arg hashes_generated "$HASHES_GENERATED" \
      '{status: $status, passed: $pass, failed: $fail, warnings: $warn, duration_s: $duration, sbom: $sbom, sbom_generated: $sbom_generated, hashes_generated: $hashes_generated}'
  fi
  exit 0
fi
