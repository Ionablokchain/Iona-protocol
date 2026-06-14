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
#   --output FILE      Write hex-encoded private key to FILE instead of stdout
#   --force            Overwrite output file if it exists
#   --quiet            Suppress non‑error output
#   --privkey-file     Read private key base64 from a plaintext file (instead of JSON)
#   --help             Show this help
#
# Exit codes:
#   0   Success
#   1   Usage or input error
#   2   Dependency missing
#   3   Cryptographic error (invalid length, encoding)
#   4   Permission error (cannot write output)
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Colours
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
print_debug()   { if [[ ${VERBOSE:-0} -eq 1 ]]; then echo -e "[DEBUG] $*" >&2; fi; }

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
SUPPORTED_KEY_TYPE="ed25519"
VALID_B64_LENGTHS=(44 88)   # 32 bytes → 44 chars, 64 bytes → 88 chars (without padding)
VALID_HEX_LENGTHS=(64 128)   # 32 bytes → 64 hex, 64 bytes → 128 hex

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
OUTPUT_FILE=""
FORCE=0
QUIET=0
VERBOSE=0
PRIVKEY_FILE=""

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
    if ! command -v jq &>/dev/null; then
        print_error "Required command 'jq' not found."
        echo "  Install: apt install jq / brew install jq" >&2
        missing=1
    fi
    if ! command -v openssl &>/dev/null; then
        print_error "Required command 'openssl' not found."
        echo "  Install: apt install openssl / brew install openssl" >&2
        missing=1
    fi
    if [[ $missing -ne 0 ]]; then
        exit 2
    fi
}

# -----------------------------------------------------------------------------
# Base64 → hex conversion (strict, using openssl)
# -----------------------------------------------------------------------------
base64_to_hex() {
    local b64="$1"
    b64="${b64//[$' \t\n\r']/}"   # remove whitespace
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
# Validate hex length
# -----------------------------------------------------------------------------
validate_hex_length() {
    local hex="$1" context="$2"
    local len=${#hex}
    for valid in "${VALID_HEX_LENGTHS[@]}"; do
        if [[ $len -eq $valid ]]; then
            return 0
        fi
    done
    print_error "$context hex length is $len chars; expected one of ${VALID_HEX_LENGTHS[*]}"
    return 1
}

# -----------------------------------------------------------------------------
# Cleanup output file on error
# -----------------------------------------------------------------------------
cleanup_output() {
    if [[ -n "$OUTPUT_FILE" && -f "$OUTPUT_FILE" ]]; then
        rm -f "$OUTPUT_FILE"
        print_debug "Removed incomplete output file $OUTPUT_FILE"
    fi
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --output)
                OUTPUT_FILE="$2"; shift 2 ;;
            --force)
                FORCE=1; shift ;;
            --quiet)
                QUIET=1; shift ;;
            --verbose)
                VERBOSE=1; shift ;;
            --privkey-file)
                PRIVKEY_FILE="$2"; shift 2 ;;
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

    if [[ -z "$KEYFILE" && -z "$PRIVKEY_FILE" ]]; then
        print_error "Missing required argument: <priv_validator_key.json> or --privkey-file <file>"
        echo "Usage: $0 [OPTIONS] <priv_validator_key.json> | $0 --privkey-file <key.b64>"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    parse_args "$@"
    check_deps

    local priv_key_b64=""
    local pub_key_b64=""

    # Extract from JSON or direct base64 file
    if [[ -n "$PRIVKEY_FILE" ]]; then
        if [[ ! -f "$PRIVKEY_FILE" ]]; then
            print_error "Private key file not found: $PRIVKEY_FILE"
            exit 1
        fi
        if [[ ! -r "$PRIVKEY_FILE" ]]; then
            print_error "Private key file not readable: $PRIVKEY_FILE"
            exit 1
        fi
        priv_key_b64=$(cat "$PRIVKEY_FILE" | tr -d ' \t\n\r')
        if [[ -z "$priv_key_b64" ]]; then
            print_error "Private key file is empty"
            exit 1
        fi
        print_info "Private key loaded from $PRIVKEY_FILE"
    else
        # Validate JSON file
        if [[ ! -f "$KEYFILE" ]]; then
            print_error "File not found: $KEYFILE"
            exit 1
        fi
        if [[ ! -r "$KEYFILE" ]]; then
            print_error "File not readable: $KEYFILE"
            exit 1
        fi
        if ! jq empty "$KEYFILE" 2>/dev/null; then
            print_error "Invalid JSON in $KEYFILE"
            exit 1
        fi

        # Extract key type
        local key_type=$(jq -r '.type // empty' "$KEYFILE" 2>/dev/null || true)
        if [[ -z "$key_type" ]]; then
            print_warn "Key type field missing; assuming $SUPPORTED_KEY_TYPE"
            key_type="$SUPPORTED_KEY_TYPE"
        fi
        if [[ "$key_type" != "$SUPPORTED_KEY_TYPE" ]]; then
            print_error "Unsupported key type '$key_type' (expected '$SUPPORTED_KEY_TYPE')"
            exit 1
        fi
        print_success "Key type verified: $key_type"

        # Extract private key
        priv_key_b64=$(jq -r '.priv_key.value // .priv_key // empty' "$KEYFILE" 2>/dev/null || true)
        if [[ -z "$priv_key_b64" ]]; then
            print_error "Could not extract private key from $KEYFILE"
            echo "Expected JSON structure:"
            echo '  {"type": "ed25519", "priv_key": {"value": "<base64>"}}'
            exit 1
        fi
        print_success "Private key extracted (${#priv_key_b64} chars base64)"

        # Extract public key (optional)
        pub_key_b64=$(jq -r '.pub_key.value // .pub_key // empty' "$KEYFILE" 2>/dev/null || true)
        if [[ -n "$pub_key_b64" ]]; then
            print_info "Public key found in JSON"
        fi
    fi

    # Validate private key length
    validate_b64_length "$priv_key_b64" "Private key" || exit 3

    # Convert to hex
    local priv_key_hex
    priv_key_hex=$(base64_to_hex "$priv_key_b64") || {
        print_error "Failed to decode base64 private key"
        exit 3
    }
    validate_hex_length "$priv_key_hex" "Private key" || exit 3
    print_success "Hex conversion successful (${#priv_key_hex} chars)"

    # Convert public key if available
    local pub_key_hex=""
    if [[ -n "$pub_key_b64" ]]; then
        if validate_b64_length "$pub_key_b64" "Public key" 2>/dev/null; then
            pub_key_hex=$(base64_to_hex "$pub_key_b64") || true
            if [[ ${#pub_key_hex} -eq 64 ]]; then
                print_success "Public key extracted and verified"
            else
                print_warn "Public key hex length is ${#pub_key_hex} (expected 64)"
            fi
        fi
    fi

    # Handle output
    if [[ -n "$OUTPUT_FILE" ]]; then
        if [[ -e "$OUTPUT_FILE" && $FORCE -eq 0 ]]; then
            print_error "Output file $OUTPUT_FILE already exists. Use --force to overwrite."
            exit 4
        fi
        trap cleanup_output EXIT
        echo -n "$priv_key_hex" > "$OUTPUT_FILE" || {
            print_error "Failed to write to $OUTPUT_FILE"
            exit 4
        }
        chmod 600 "$OUTPUT_FILE"
        trap - EXIT
        print_success "Private key written to $OUTPUT_FILE (${#priv_key_hex} hex chars)"
        if [[ $QUIET -eq 0 ]]; then
            echo ""
            print_info "You can now encrypt this key:"
            echo "  iona keys import $OUTPUT_FILE --output keys.enc"
        fi
    else
        if [[ $QUIET -eq 0 ]]; then
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

            if [[ -n "$pub_key_b64" ]]; then
                echo -e "${BLUE}Public Key (base64):${NC}"
                echo "  $pub_key_b64"
                echo ""
                if [[ -n "$pub_key_hex" ]]; then
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
            echo "   ${YELLOW}iona keys import $OUTPUT_FILE --output keys.enc${NC}"
            echo ""
            echo "3. Verify encryption:"
            echo "   ${YELLOW}iona keys check keys.enc${NC}"
            echo ""
            echo "4. Display public key:"
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
            echo "   ${YELLOW}shred -vfz -n 10 \"${KEYFILE:-$PRIVKEY_FILE}\"${NC}"
            echo ""
        else
            # Quiet mode: just output the hex key
            echo -n "$priv_key_hex"
        fi
    fi

    print_success "Key import completed successfully"
}

main "$@"
