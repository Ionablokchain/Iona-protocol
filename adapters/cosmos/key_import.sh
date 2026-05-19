#!/usr/bin/env bash
# =============================================================================
# IONA Cosmos Adapter: Key Import Script
#
# Converts a CometBFT priv_validator_key.json to IONA-compatible hex format.
# Supports both raw ed25519 private keys (32 bytes) and expanded keys (64 bytes).
#
# Usage:
#   ./key_import.sh [OPTIONS] <priv_validator_key.json>
#
# Options:
#   --output FILE   Write hex-encoded private key to FILE instead of stdout
#   --help          Show this help
#
# Exit codes:
#   0   Success
#   1   Usage or input error
#   2   Dependency missing
#   3   Cryptographic error (invalid length, encoding)
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Colours (only when stdout is a terminal)
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

print_error()   { echo -e "${RED}✗ ERROR${NC}: $*" >&2; }
print_success() { echo -e "${GREEN}✓${NC} $*"; }
print_info()    { echo -e "${BLUE}[*]${NC} $*"; }
print_warn()    { echo -e "${YELLOW}⚠${NC} $*"; }

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
SUPPORTED_KEY_TYPE="ed25519"
# ed25519 private key is 32 bytes → 44 chars base64 (without padding).
# Some CometBFT keys are 64 bytes (seed + pub) → 88 chars base64.
VALID_B64_LENGTHS=(44 88)

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# //'
    exit 0
}

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
check_deps() {
    local missing=0
    for cmd in jq openssl; do
        if ! command -v "$cmd" &>/dev/null; then
            print_error "Required command not found: $cmd"
            missing=1
        fi
    done
    if [[ $missing -ne 0 ]]; then
        exit 2
    fi
}

# -----------------------------------------------------------------------------
# Base64 → hex conversion (strict, using openssl)
# -----------------------------------------------------------------------------
base64_to_hex() {
    local b64="$1"
    # Remove any whitespace or newlines
    b64="${b64//[$' \t\n\r']/}"
    if [[ -z "$b64" ]]; then
        return 1
    fi
    openssl enc -d -base64 -A <<< "$b64" 2>/dev/null | od -An -tx1 | tr -d ' \n'
}

# -----------------------------------------------------------------------------
# Validate base64 length
# -----------------------------------------------------------------------------
validate_b64_length() {
    local b64="$1" context="$2"
    local len=${#b64}
    for valid in "${VALID_B64_LENGTHS[@]}"; do
        if [[ $len -eq $valid ]]; then
            return 0
        fi
    done
    print_error "$context length is $len chars; expected one of ${VALID_B64_LENGTHS[*]}"
    return 1
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
OUTPUT_FILE=""
KEYFILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            OUTPUT_FILE="$2"; shift 2 ;;
        --help)
            usage ;;
        -*)
            print_error "Unknown option: $1"
            echo "Try '$0 --help'" >&2
            exit 1 ;;
        *)
            if [[ -z "$KEYFILE" ]]; then
                KEYFILE="$1"
            else
                print_error "Unexpected argument: $1"
                exit 1
            fi
            shift ;;
    esac
done

if [[ -z "$KEYFILE" ]]; then
    print_error "Missing required argument: priv_validator_key.json"
    echo "Usage: $0 [--output FILE] <priv_validator_key.json>" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Input file validation
# -----------------------------------------------------------------------------
if [[ ! -f "$KEYFILE" ]]; then
    print_error "File not found: $KEYFILE"
    exit 1
fi
if [[ ! -r "$KEYFILE" ]]; then
    print_error "File not readable: $KEYFILE"
    exit 1
fi

check_deps

# -----------------------------------------------------------------------------
# JSON validation
# -----------------------------------------------------------------------------
if ! jq empty "$KEYFILE" 2>/dev/null; then
    print_error "Invalid JSON in $KEYFILE"
    exit 1
fi

# -----------------------------------------------------------------------------
# Key type check
# -----------------------------------------------------------------------------
key_type=$(jq -r '.type // empty' "$KEYFILE" 2>/dev/null || true)
if [[ -z "$key_type" ]]; then
    print_warn "Key type field missing; assuming $SUPPORTED_KEY_TYPE"
    key_type="$SUPPORTED_KEY_TYPE"
fi
if [[ "$key_type" != "$SUPPORTED_KEY_TYPE" ]]; then
    print_error "Unsupported key type '$key_type' (expected '$SUPPORTED_KEY_TYPE')"
    exit 1
fi
print_success "Key type verified: $key_type"

# -----------------------------------------------------------------------------
# Extract private key
# -----------------------------------------------------------------------------
priv_key_b64=$(jq -r '.priv_key.value // .priv_key // empty' "$KEYFILE" 2>/dev/null || true)
if [[ -z "$priv_key_b64" ]]; then
    print_error "Could not extract private key from $KEYFILE"
    echo "Expected JSON structure:"
    echo '  {"type": "ed25519", "priv_key": {"value": "<base64>"}}'
    exit 1
fi

validate_b64_length "$priv_key_b64" "Private key" || exit 3
print_success "Private key extracted (${#priv_key_b64} chars base64)"

# -----------------------------------------------------------------------------
# Convert to hex
# -----------------------------------------------------------------------------
priv_key_hex=$(base64_to_hex "$priv_key_b64") || {
    print_error "Failed to decode base64 private key"
    exit 3
}

hex_len=${#priv_key_hex}
# Ed25519: 32 bytes → 64 hex chars; 64 bytes → 128 hex chars
if [[ $hex_len -ne 64 && $hex_len -ne 128 ]]; then
    print_error "Unexpected hex length $hex_len (expected 64 or 128)"
    exit 3
fi
print_success "Hex conversion successful (${hex_len} chars)"

# -----------------------------------------------------------------------------
# Extract public key (if present)
# -----------------------------------------------------------------------------
pub_key_b64=$(jq -r '.pub_key.value // .pub_key // empty' "$KEYFILE" 2>/dev/null || true)
if [[ -n "$pub_key_b64" ]]; then
    if validate_b64_length "$pub_key_b64" "Public key"; then
        pub_key_hex=$(base64_to_hex "$pub_key_b64") || true
        if [[ ${#pub_key_hex} -eq 64 ]]; then
            print_success "Public key extracted and verified"
        else
            print_warn "Public key hex length is ${#pub_key_hex} (expected 64)"
        fi
    fi
fi

# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------
if [[ -n "$OUTPUT_FILE" ]]; then
    # Write only the hex private key to the output file
    echo -n "$priv_key_hex" > "$OUTPUT_FILE"
    chmod 600 "$OUTPUT_FILE"
    print_success "Private key written to $OUTPUT_FILE"
else
    # Display full report
    echo ""
    echo "=========================================="
    echo "  Conversion Results"
    echo "=========================================="
    echo ""
    echo -e "${BLUE}Private Key (base64):${NC}"
    echo "  $priv_key_b64"
    echo ""
    echo -e "${BLUE}Private Key (hex):${NC}"
    echo "  $priv_key_hex"
    echo ""

    if [[ -n "${pub_key_b64:-}" ]]; then
        echo -e "${BLUE}Public Key (base64):${NC}"
        echo "  $pub_key_b64"
        echo ""
        if [[ -n "${pub_key_hex:-}" ]]; then
            echo -e "${BLUE}Public Key (hex):${NC}"
            echo "  $pub_key_hex"
            echo ""
        fi
    fi

    echo "=========================================="
    echo "  Next Steps"
    echo "=========================================="
    echo ""
    echo "1. Verify the keys above match your expectations"
    echo ""
    echo "2. Encrypt with IONA:"
    echo ""
    echo "   ${YELLOW}iona keys import $KEYFILE --output keys.enc${NC}"
    echo ""
    echo "3. Verify encryption:"
    echo ""
    echo "   ${YELLOW}iona keys check keys.enc${NC}"
    echo ""
    echo "4. Display public key:"
    echo ""
    echo "   ${YELLOW}iona keys show keys.enc --public-only${NC}"
    echo ""

    echo "=========================================="
    echo "  Security Warnings"
    echo "=========================================="
    echo ""
    print_warn "Private key data was displayed on screen."
    print_warn "Do NOT share, commit, email, or store these values in plaintext."
    print_warn "After encrypting with IONA, securely delete the original JSON file:"
    echo ""
    echo "   ${YELLOW}shred -vfz -n 10 $KEYFILE${NC}"
    echo ""
fi

print_success "Key import script completed successfully"
