#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
#  IONA Release Checklist — Production‑Grade v2
# =============================================================================
#  Run this script before every push / zip / release.
#  All critical steps must pass — if any fail, the build is NOT safe to ship.
#
#  Environment variables:
#    BIN_NAME              - name of the binary to build (default: iona-node)
#    SKIP_*                - set to 1 to skip a section (e.g., SKIP_AUDIT=1)
#    SKIP_ALL_OPTIONAL     - set to 1 to skip all optional checks
#    RUSTFLAGS             - passed to cargo (default: "-D warnings")
#    RUSTDOCFLAGS          - passed to cargo doc (default: "-D warnings")
#    VERBOSE               - set to 1 for detailed output
#    CI                    - set to 1 in CI environments (disables interactive prompts)
#    CARGO_TERM_COLOR      - set to always/never for coloured cargo output
#    EXTRA_FEATURES        - additional cargo features to enable (space-separated)
#    TARGET_DIR            - custom target directory (default: target)
#
#  Usage:
#    ./scripts/release_checklist.sh [OPTIONS]
#
#  Options:
#    --quick          skip optional checks (audit, deny, fuzz, outdated)
#    --verbose        enable detailed output
#    --json           output final summary as JSON (for CI integration)
#    --step <name>    run only a specific step (can be repeated)
#    --list-steps     list all available steps and exit
#    --help           show this help
# =============================================================================

# ── Configuration ────────────────────────────────────────────────────────────
BIN_NAME="${BIN_NAME:-iona-node}"
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"
export RUSTDOCFLAGS="${RUSTDOCFLAGS:--D warnings}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
VERBOSE="${VERBOSE:-0}"
CI="${CI:-0}"
QUICK=0
JSON_OUTPUT=0
ONLY_STEPS=()
EXTRA_FEATURES="${EXTRA_FEATURES:-}"
TARGET_DIR="${TARGET_DIR:-target}"

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)     QUICK=1; shift ;;
    --verbose)   VERBOSE=1; shift ;;
    --json)      JSON_OUTPUT=1; shift ;;
    --step)      ONLY_STEPS+=("$2"); shift 2 ;;
    --list-steps) list_steps; exit 0 ;;
    --help)      usage; exit 0 ;;
    -*)          echo "Unknown option: $1"; usage >&2; exit 1 ;;
    *)           echo "Unexpected argument: $1"; usage >&2; exit 1 ;;
  esac
done

# ── Usage ────────────────────────────────────────────────────────────────────
usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# //'
}

# ── List all steps ──────────────────────────────────────────────────────────
list_steps() {
  echo "Available steps:"
  echo "  fmt          - cargo fmt --check"
  echo "  clippy       - cargo clippy"
  echo "  test         - cargo test --locked"
  echo "  doc          - cargo doc --no-deps"
  echo "  audit        - cargo audit (security vulnerabilities)"
  echo "  deny         - cargo deny check (licenses, dependencies)"
  echo "  fuzz         - cargo fuzz build"
  echo "  outdated     - cargo outdated (informational)"
  echo "  build        - cargo build --release"
  echo "  binary       - verify binary exists"
  echo "  determinism  - determinism golden vector tests"
  echo "  version      - protocol version tests"
  echo "  clean        - check for uncommitted changes"
  echo "  miri         - cargo miri test (optional, requires nightly)"
  echo "  bench        - cargo bench (compile check only)"
}

# Check if a step should run
should_run() {
  local step="$1"
  if [[ ${#ONLY_STEPS[@]} -eq 0 ]]; then
    return 0
  fi
  for s in "${ONLY_STEPS[@]}"; do
    if [[ "$s" == "$step" ]]; then
      return 0
    fi
  done
  return 1
}

# ── Colours (safe for non‑TTY) ──────────────────────────────────────────────
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; BLUE=''; NC=''
fi

# ── Helper functions ────────────────────────────────────────────────────────
info()    { echo -e "${BLUE}[INFO]${NC}   $*"; }
pass()    { echo -e "${GREEN}[PASS]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}   $*" >&2; }
fail()    { echo -e "${RED}[FAIL]${NC}   $*" >&2; }

step() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ${BLUE}STEP: $1${NC}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo "  (verbose output follows)"
  fi
}

# Check if a command exists
cmd_exists() { command -v "$1" &>/dev/null; }

# Run a command with optional verbose output capture
run_cmd() {
  local cmd="$1"
  local msg="$2"
  local logfile=""
  if [[ "$VERBOSE" -eq 1 ]]; then
    logfile="/tmp/iona_release_${RANDOM}.log"
    echo "  → $cmd (log: $logfile)"
    if eval "$cmd" >"$logfile" 2>&1; then
      pass "$msg"
      rm -f "$logfile"
      return 0
    else
      fail "$msg"
      echo "  Log: $logfile"
      return 1
    fi
  else
    if eval "$cmd" >/dev/null 2>&1; then
      pass "$msg"
      return 0
    else
      fail "$msg"
      return 1
    fi
  fi
}

# Run an optional check (skip if command missing or SKIP_* set)
optional_check() {
  local name="$1"
  local cmd="$2"
  local skip_var="$3"
  local required_cmd="$4"

  if [[ "${!skip_var:-0}" -eq 1 ]] || [[ "${SKIP_ALL_OPTIONAL:-0}" -eq 1 ]]; then
    warn "Skipping $name (${skip_var}=1 or SKIP_ALL_OPTIONAL=1)"
    return 0
  fi
  if [[ "$QUICK" -eq 1 ]]; then
    warn "Skipping $name (quick mode)"
    return 0
  fi
  if [[ -n "$required_cmd" ]] && ! cmd_exists "$required_cmd"; then
    warn "Skipping $name ($required_cmd not installed)"
    return 0
  fi

  if run_cmd "$cmd" "$name"; then
    return 0
  else
    return 1
  fi
}

# Build feature flags for cargo commands
build_features() {
  if [[ -n "$EXTRA_FEATURES" ]]; then
    echo "--features $EXTRA_FEATURES"
  else
    echo ""
  fi
}

# ── Initialise counters ──────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0
FAILED_STEPS=()
START_TIME=$(date +%s)

# ── Trap for cleanup ────────────────────────────────────────────────────────
cleanup() {
  local exit_code=$?
  if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "────────────────────────────────────────────────────────────────────"
    warn "Release checklist incomplete. $FAIL failure(s) recorded."
  fi
  # Clean temp logs
  rm -f /tmp/iona_release_*.log
  exit $exit_code
}
trap cleanup EXIT

# ── Verify we are in the correct directory ──────────────────────────────────
if [[ ! -f "Cargo.toml" ]]; then
  fail "Cargo.toml not found. Run this script from the project root."
  exit 1
fi

# ── Verify required tools ───────────────────────────────────────────────────
for tool in cargo rustc; do
  if ! cmd_exists "$tool"; then
    fail "$tool is required but not installed."
    exit 1
  fi
done

info "Rust version: $(rustc --version)"
info "Cargo version: $(cargo --version)"
if [[ -d .git ]]; then
  info "Git commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
fi

FEATURES=$(build_features)
if [[ -n "$FEATURES" ]]; then
  info "Extra features: $EXTRA_FEATURES"
fi

# ═════════════════════════════════════════════════════════════════════════════
# A. Code formatting
# ═════════════════════════════════════════════════════════════════════════════
if should_run "fmt"; then
  step "A. cargo fmt --check"
  if run_cmd "cargo fmt --check" "code formatting"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo fmt")
    if [[ "$CI" -ne 1 ]]; then
      warn "Run 'cargo fmt' to fix formatting issues."
    fi
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# B. Lint (clippy)
# ═════════════════════════════════════════════════════════════════════════════
if should_run "clippy"; then
  step "B. cargo clippy --locked $FEATURES"
  if run_cmd "cargo clippy --locked $FEATURES -- -D warnings" "clippy warnings"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo clippy")
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# C. Tests (full suite)
# ═════════════════════════════════════════════════════════════════════════════
if should_run "test"; then
  step "C. cargo test --locked $FEATURES"
  if run_cmd "cargo test --locked $FEATURES" "all tests"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo test")
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# D. Documentation build
# ═════════════════════════════════════════════════════════════════════════════
if should_run "doc"; then
  if [[ "${SKIP_DOC:-0}" -eq 1 ]]; then
    warn "Skipping documentation build (SKIP_DOC=1)"
    SKIP=$((SKIP+1))
  else
    step "D. cargo doc --no-deps --document-private-items $FEATURES"
    if run_cmd "cargo doc --no-deps --document-private-items $FEATURES" "documentation"; then
      PASS=$((PASS+1))
    else
      FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo doc")
    fi
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# E. Security audit (cargo audit)
# ═════════════════════════════════════════════════════════════════════════════
if should_run "audit"; then
  if optional_check "cargo audit" \
    "cargo audit --deny warnings" \
    "SKIP_AUDIT" \
    "cargo-audit"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo audit")
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# F. License & dependency checks (cargo deny)
# ═════════════════════════════════════════════════════════════════════════════
if should_run "deny"; then
  if optional_check "cargo deny check" \
    "cargo deny check licenses advisories sources" \
    "SKIP_DENY" \
    "cargo-deny"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo deny")
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# G. Fuzzing (compile only)
# ═════════════════════════════════════════════════════════════════════════════
if should_run "fuzz"; then
  if optional_check "fuzz targets (compile)" \
    "cargo fuzz build --all" \
    "SKIP_FUZZ" \
    "cargo-fuzz"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo fuzz")
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# H. Outdated dependencies (cargo outdated) – optional, informational
# ═════════════════════════════════════════════════════════════════════════════
if should_run "outdated"; then
  if [[ "${SKIP_OUTDATED:-0}" -eq 1 ]] || [[ "$QUICK" -eq 1 ]]; then
    warn "Skipping cargo outdated"
    SKIP=$((SKIP+1))
  elif cmd_exists cargo-outdated; then
    if run_cmd "cargo outdated --exit-code 1" "cargo outdated (check for updates)"; then
      pass "all dependencies up to date"
      PASS=$((PASS+1))
    else
      warn "Some dependencies have newer versions (informational, not a blocker)"
      PASS=$((PASS+1)) # not a failure
    fi
  else
    warn "Skipping cargo outdated (cargo-outdated not installed)"
    SKIP=$((SKIP+1))
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# I. Miri (optional, requires nightly)
# ═════════════════════════════════════════════════════════════════════════════
if should_run "miri"; then
  if [[ "${SKIP_MIRI:-0}" -eq 1 ]] || [[ "$QUICK" -eq 1 ]]; then
    warn "Skipping miri"
    SKIP=$((SKIP+1))
  elif rustup which miri &>/dev/null; then
    step "I. cargo miri test"
    if run_cmd "cargo miri test --locked" "miri tests"; then
      PASS=$((PASS+1))
    else
      FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo miri")
    fi
  else
    warn "Skipping miri (not installed; install with: rustup +nightly component add miri)"
    SKIP=$((SKIP+1))
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# J. Benchmarks (compile check only)
# ═════════════════════════════════════════════════════════════════════════════
if should_run "bench"; then
  if [[ "${SKIP_BENCH:-0}" -eq 1 ]] || [[ "$QUICK" -eq 1 ]]; then
    warn "Skipping benchmarks"
    SKIP=$((SKIP+1))
  else
    step "J. cargo bench --no-run (compile only)"
    if run_cmd "cargo bench --no-run --locked" "benchmarks compile"; then
      PASS=$((PASS+1))
    else
      FAIL=$((FAIL+1)); FAILED_STEPS+=("cargo bench")
    fi
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# K. Release build
# ═════════════════════════════════════════════════════════════════════════════
if should_run "build"; then
  step "K. cargo build --release --locked --bin $BIN_NAME $FEATURES"
  if run_cmd "cargo build --release --locked --bin \"$BIN_NAME\" $FEATURES" "release build"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1)); FAILED_STEPS+=("release build")
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# L. Binary sanity
# ═════════════════════════════════════════════════════════════════════════════
if should_run "binary"; then
  step "L. Binary exists and is executable"
  BINARY="$TARGET_DIR/release/$BIN_NAME"
  if [[ -x "$BINARY" ]]; then
    SIZE=$(du -h "$BINARY" 2>/dev/null | awk '{print $1}' || echo "unknown")
    SHA=$(sha256sum "$BINARY" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$BINARY" 2>/dev/null | awk '{print $1}' || echo "unknown")
    info "Binary: $BINARY ($SIZE)"
    info "SHA256: $SHA"
    pass "binary sanity"
    PASS=$((PASS+1))

    # Optional: check for stripped symbols (release builds should be stripped)
    if cmd_exists file && cmd_exists nm; then
      if file "$BINARY" | grep -q "not stripped"; then
        warn "Binary is not stripped. Consider adding 'strip = true' to Cargo.toml [profile.release]"
      fi
    fi
  else
    fail "binary not found at $BINARY"
    FAIL=$((FAIL+1)); FAILED_STEPS+=("binary exists")
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# M. Determinism golden vectors
# ═════════════════════════════════════════════════════════════════════════════
if should_run "determinism"; then
  step "M. Determinism tests (golden vectors)"
  if run_cmd "cargo test --locked determinism $FEATURES" "determinism golden vectors"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1)); FAILED_STEPS+=("determinism")
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# N. Protocol version tests
# ═════════════════════════════════════════════════════════════════════════════
if should_run "version"; then
  step "N. Protocol version tests"
  if run_cmd "cargo test --locked test_version_for_height test_validate_block_version test_is_supported $FEATURES" "protocol version"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1)); FAILED_STEPS+=("protocol version")
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# O. Working directory clean (git)
# ═════════════════════════════════════════════════════════════════════════════
if should_run "clean"; then
  if [[ -d .git ]]; then
    step "O. Check for uncommitted changes"
    if [[ -z "$(git status --porcelain)" ]]; then
      pass "working directory clean"
      PASS=$((PASS+1))
    else
      warn "Uncommitted changes detected:"
      if [[ "$VERBOSE" -eq 1 ]]; then
        git status --short
      fi
      warn "Not a blocker for release, but recommended to commit before tagging."
      PASS=$((PASS+1)) # not a failure
    fi

    # Check for unpushed commits
    if git rev-parse @{u} &>/dev/null; then
      UNPUSHED=$(git log @{u}..HEAD --oneline 2>/dev/null | wc -l)
      if [[ $UNPUSHED -gt 0 ]]; then
        warn "$UNPUSHED unpushed commit(s) detected."
      fi
    fi
  else
    warn "Not a git repository, skipping uncommitted changes check"
    SKIP=$((SKIP+1))
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                       RELEASE CHECKLIST SUMMARY                     ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  %-20s %3d                                              ║\n" "Passed:" "$PASS"
printf "║  %-20s %3d                                              ║\n" "Failed:" "$FAIL"
printf "║  %-20s %3d                                              ║\n" "Skipped:" "$SKIP"
printf "║  %-20s %3ds                                            ║\n" "Duration:" "$DURATION"
if [[ $FAIL -gt 0 ]]; then
  echo "╠══════════════════════════════════════════════════════════════════════╣"
  echo "║  ❌ STATUS: NOT READY FOR RELEASE                                  ║"
  echo "║  Failed steps:                                                     ║"
  for step in "${FAILED_STEPS[@]}"; do
    printf "║    - %-60s ║\n" "$step"
  done
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    jq -n \
      --arg status "FAIL" \
      --argjson pass "$PASS" \
      --argjson fail "$FAIL" \
      --argjson skip "$SKIP" \
      --argjson duration "$DURATION" \
      --argjson steps "$(printf '%s\n' "${FAILED_STEPS[@]}" | jq -R . | jq -s .)" \
      '{status: $status, passed: $pass, failed: $fail, skipped: $skip, duration_s: $duration, failed_steps: $steps}'
  fi
  exit 1
else
  echo "╠══════════════════════════════════════════════════════════════════════╣"
  echo "║  ✅ STATUS: READY FOR RELEASE                                      ║"
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    jq -n \
      --arg status "PASS" \
      --argjson pass "$PASS" \
      --argjson fail "$FAIL" \
      --argjson skip "$SKIP" \
      --argjson duration "$DURATION" \
      '{status: $status, passed: $pass, failed: $fail, skipped: $skip, duration_s: $duration}'
  fi
  exit 0
fi
