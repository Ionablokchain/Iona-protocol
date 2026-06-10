#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# IONA Testnet Setup Script — Production‑Grade v30
# =============================================================================
# Creates directories, generates ed25519 validator keys, and initialises
# genesis state for a local or CI‑driven testnet.
#
# Usage:
#   ./setup.sh [OPTIONS]
#
# Options:
#   --validators N    Number of validators (default: 4, max: 100)
#   --base-dir DIR    Root directory for all data (default: ./data)
#   --configs-dir DIR Directory containing config templates + genesis.json
#   --force           Overwrite existing data directories and keys
#   --keep-artifacts  Do not delete intermediate files
#   --json            Output final summary as JSON (for CI/CD)
#   --verbose         Enable detailed output
#   --help            Show this help
#
# Environment variables (fallback):
#   IONA_VALIDATORS, IONA_DATA_DIR, IONA_CONFIGS_DIR, IONA_FORCE, IONA_VERBOSE
# =============================================================================

# ── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${IONA_DATA_DIR:-$SCRIPT_DIR/data}"
CONFIGS_DIR="${IONA_CONFIGS_DIR:-$SCRIPT_DIR/configs}"
NUM_VALIDATORS="${IONA_VALIDATORS:-4}"
FORCE="${IONA_FORCE:-0}"
VERBOSE="${IONA_VERBOSE:-0}"
KEEP_ARTIFACTS=0
JSON_OUTPUT=0

# Colours for output (safe for non‑TTY)
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''
fi

# ── Helper functions ────────────────────────────────────────────────────────
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }
verbose() { [[ $VERBOSE -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $*"; }

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --validators)   NUM_VALIDATORS="$2"; shift 2 ;;
    --base-dir)     DATA_DIR="$2"; shift 2 ;;
    --configs-dir)  CONFIGS_DIR="$2"; shift 2 ;;
    --force)        FORCE=1; shift ;;
    --keep-artifacts) KEEP_ARTIFACTS=1; shift ;;
    --json)         JSON_OUTPUT=1; shift ;;
    --verbose)      VERBOSE=1; shift ;;
    --help)
      sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

# Validate number of validators
if [[ ! "$NUM_VALIDATORS" =~ ^[0-9]+$ ]] || [[ $NUM_VALIDATORS -lt 1 ]] || [[ $NUM_VALIDATORS -gt 100 ]]; then
  die "Number of validators must be between 1 and 100 (got $NUM_VALIDATORS)"
fi

# ── Validate dependencies ───────────────────────────────────────────────────
REQUIRED_CMDS=("openssl" "jq" "chmod" "mkdir" "cp" "rm" "find")
for cmd in "${REQUIRED_CMDS[@]}"; do
  if ! command -v "$cmd" &>/dev/null; then
    die "Required command '$cmd' not found. Please install it."
  fi
done

# Check for iona-cli (preferred for ed25519 key generation)
IONA_CLI_AVAILABLE=0
if command -v iona-cli &>/dev/null; then
  IONA_CLI_AVAILABLE=1
  info "iona-cli found – will use it for ed25519 key generation"
else
  warn "iona-cli not found – falling back to openssl for ed25519 keys"
  # Verify openssl supports ed25519
  if ! openssl genpkey -algorithm ed25519 2>/dev/null | head -1 &>/dev/null; then
    die "OpenSSL does not support Ed25519 (requires OpenSSL 1.1.1+). Please install iona-cli or upgrade OpenSSL."
  fi
fi

# ── Validate configuration files ────────────────────────────────────────────
if [[ ! -d "$CONFIGS_DIR" ]]; then
  die "Config directory not found: $CONFIGS_DIR"
fi

if [[ ! -f "$CONFIGS_DIR/genesis.json" ]]; then
  die "genesis.json not found at $CONFIGS_DIR/genesis.json"
fi

# Validate genesis.json format
if ! jq empty "$CONFIGS_DIR/genesis.json" 2>/dev/null; then
  die "genesis.json is not valid JSON"
fi

# Validate genesis has validators section
if ! jq -e '.validators' "$CONFIGS_DIR/genesis.json" >/dev/null 2>&1; then
  die "genesis.json missing 'validators' field"
fi

# Check that genesis validators count matches
GENESIS_VAL_COUNT=$(jq '.validators | length' "$CONFIGS_DIR/genesis.json")
if [[ "$GENESIS_VAL_COUNT" -ne "$NUM_VALIDATORS" ]]; then
  warn "genesis.json has $GENESIS_VAL_COUNT validators but --validators=$NUM_VALIDATORS"
  warn "Using genesis.json count ($GENESIS_VAL_COUNT)"
  NUM_VALIDATORS="$GENESIS_VAL_COUNT"
fi

# ── Create data directories ─────────────────────────────────────────────────
if [[ -d "$DATA_DIR" && $FORCE -eq 0 ]]; then
  warn "Data directory already exists: $DATA_DIR"
  warn "Use --force to overwrite (will delete existing chain data)"
  echo -n "Continue without overwriting? [y/N] "
  read -r answer
  if [[ ! "$answer" =~ ^[Yy]$ ]]; then
    die "Aborted by user"
  fi
else
  if [[ -d "$DATA_DIR" && $FORCE -eq 1 ]]; then
    info "Removing existing data directory (--force)"
    rm -rf "$DATA_DIR"
  fi
  mkdir -p "$DATA_DIR"
fi

# Ensure secure permissions
umask 0077

for i in $(seq 1 "$NUM_VALIDATORS"); do
  node_dir="$DATA_DIR/validator-$i"
  if [[ -d "$node_dir" && $FORCE -eq 0 ]]; then
    warn "Directory $node_dir already exists – skipping (use --force to overwrite)"
  else
    if [[ -d "$node_dir" ]]; then
      rm -rf "$node_dir"
    fi
    mkdir -p "$node_dir"
    chmod 0700 "$node_dir"
  fi
done

# ── Copy genesis files ─────────────────────────────────────────────────────
info "Copying genesis.json to each validator directory..."
for i in $(seq 1 "$NUM_VALIDATORS"); do
  dest="$DATA_DIR/validator-$i/genesis.json"
  if [[ ! -f "$dest" || $FORCE -eq 1 ]]; then
    cp "$CONFIGS_DIR/genesis.json" "$dest"
    chmod 644 "$dest"
    verbose "  Copied genesis to validator-$i"
  else
    verbose "  Genesis already exists for validator-$i (skipping)"
  fi
done

# ── Generate ed25519 validator keys ─────────────────────────────────────────
info "Generating ed25519 validator keys..."

KEYS_GENERATED=0
for i in $(seq 1 "$NUM_VALIDATORS"); do
  node_dir="$DATA_DIR/validator-$i"
  key_file="$node_dir/validator_key.json"
  pub_file="$node_dir/validator_key.pub"
  seed=$((1000 + i))

  if [[ -f "$key_file" && $FORCE -eq 0 ]]; then
    verbose "  Key already exists for validator-$i (skipping)"
    continue
  fi

  if [[ $IONA_CLI_AVAILABLE -eq 1 ]]; then
    # Use iona-cli for proper key generation
    if ! iona-cli keygen --seed "$seed" --output "$key_file" 2>/dev/null; then
      error "Failed to generate key for validator-$i using iona-cli"
      exit 1
    fi
    # Extract public key
    if iona-cli keys show "$key_file" --public-only > "$pub_file" 2>/dev/null; then
      verbose "  Extracted public key for validator-$i"
    fi
    info "  Generated ed25519 key for validator-$i (iona-cli)"
  else
    # Fallback to OpenSSL with Ed25519
    openssl genpkey -algorithm ed25519 -out "$node_dir/validator_key.pem" 2>/dev/null || die "openssl ed25519 generation failed for validator-$i"
    openssl pkey -in "$node_dir/validator_key.pem" -pubout -out "$pub_file" 2>/dev/null
    
    # Convert to JSON format expected by IONA
    local priv_hex
    priv_hex=$(openssl pkey -in "$node_dir/validator_key.pem" -text -noout 2>/dev/null | grep -A1 "priv:" | tail -1 | tr -d ' \n:' || echo "")
    cat > "$key_file" <<EOF
{
  "type": "ed25519",
  "seed32": "$(printf "%032d" "$seed" | cut -c1-32)",
  "private_key_hex": "$priv_hex"
}
EOF
    info "  Generated ed25519 key for validator-$i (openssl)"
  fi
  chmod 0600 "$key_file"
  chmod 644 "$pub_file"
  KEYS_GENERATED=$((KEYS_GENERATED + 1))
done

info "Keys generated: $KEYS_GENERATED"

# ── Copy configuration files ───────────────────────────────────────────────
info "Copying configuration files..."
for i in $(seq 1 "$NUM_VALIDATORS"); do
  config_file="$CONFIGS_DIR/validator-$i.toml"
  dest="$DATA_DIR/validator-$i/config.toml"
  
  if [[ ! -f "$config_file" ]]; then
    warn "Missing config template: $config_file (skipping)"
    continue
  fi
  
  if [[ ! -f "$dest" || $FORCE -eq 1 ]]; then
    cp "$config_file" "$dest"
    chmod 644 "$dest"
    verbose "  Copied config to validator-$i"
  else
    verbose "  Config already exists for validator-$i (skipping)"
  fi
done

# ── Verify setup ────────────────────────────────────────────────────────────
info "Verifying setup..."
ERRORS=0
for i in $(seq 1 "$NUM_VALIDATORS"); do
  node_dir="$DATA_DIR/validator-$i"
  # Check essential files
  for f in genesis.json validator_key.json config.toml; do
    if [[ ! -f "$node_dir/$f" ]]; then
      error "Missing $f in validator-$i"
      ERRORS=$((ERRORS + 1))
    fi
  done
done

if [[ $ERRORS -gt 0 ]]; then
  die "Setup verification failed with $ERRORS error(s). See above."
fi
info "All validators have required files"

# ── Compute genesis hash ────────────────────────────────────────────────────
GENESIS_HASH=$(sha256sum "$CONFIGS_DIR/genesis.json" 2>/dev/null | awk '{print $1}' || echo "unknown")
verbose "Genesis hash: $GENESIS_HASH"

# ── Final summary ──────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "  IONA Testnet v30.0.0 Setup Complete"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

info "Data directory: $DATA_DIR"
info "Configuration directory: $CONFIGS_DIR"
info "Validators: $NUM_VALIDATORS"
info "Keys generated: $KEYS_GENERATED"
echo ""

echo "Quick Start:"
echo "  1. Start the testnet:"
echo "     cd $SCRIPT_DIR && ./run_nodes_local.sh --nodes $NUM_VALIDATORS --base-dir $DATA_DIR"
echo ""
echo "  2. Check health of validators:"
for i in $(seq 1 "$NUM_VALIDATORS"); do
  port=$((8540 + i))
  echo "     curl http://localhost:${port}/health"
done
echo ""
echo "  3. Get chain status:"
echo "     curl http://localhost:8541/status | jq"
echo ""
echo "  Configuration files:"
echo "    $DATA_DIR/validator-{1..$NUM_VALIDATORS}/config.toml"
echo ""
echo "  Reset chain data and start fresh:"
echo "    rm -rf $DATA_DIR && $0 --force"
echo ""

# ── JSON output (for CI/CD) ────────────────────────────────────────────────
if [[ $JSON_OUTPUT -eq 1 ]]; then
  jq -n \
    --arg status "ok" \
    --argjson validators "$NUM_VALIDATORS" \
    --arg data_dir "$DATA_DIR" \
    --arg configs_dir "$CONFIGS_DIR" \
    --arg genesis_hash "$GENESIS_HASH" \
    --argjson keys_generated "$KEYS_GENERATED" \
    --arg timestamp "$(date -Iseconds)" \
    '{
      status: $status,
      validators: $validators,
      data_dir: $data_dir,
      configs_dir: $configs_dir,
      genesis_hash: $genesis_hash,
      keys_generated: $keys_generated,
      timestamp: $timestamp
    }'
fi

# Safety: restore umask
umask 0022
