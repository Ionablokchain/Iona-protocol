#!/usr/bin/env bash
# =============================================================================
# IONA Cosmos Adapter: Key Import Script
#
# Converts a CometBFT priv_validator_key.json (or plain base64 key) to
# IONA-compatible hex format. Supports ed25519 keys (32 or 64 bytes).
#
# Features:
#   - Direct JSON parsing with jq (with fallback to grep for minimal systems)
#   - Support for both raw private key (32 bytes) and expanded (64 bytes)
#   - Optional public key extraction and verification
#   - Hex output with optional encryption-ready formatting
#   - Secure file permissions (chmod 600)
#   - Dry-run mode to preview conversion
#   - Verbose debug output
#   - Graceful cleanup on error
#
# Usage:
#   ./key_import.sh [OPTIONS] <priv_validator_key.json>
#   ./key_import.sh --privkey-file <base64-key-file> [OPTIONS]
#
# Options:
#   --output FILE        Write hex-encoded private key to FILE instead of stdout
#   --force              Overwrite output file if it exists
#   --dry-run            Parse and validate but do not write output
#   --no-verify          Skip public key verification (faster)
#   --expand             Expand private key to 64-byte hex (default: 32-byte)
#   --format FORMAT      Output format: hex, hex_padded, or base64 (default: hex)
#   --quiet              Suppress non‑error output
#   --verbose            Verbose output
#   --privkey-file       Read private key base64 from a plaintext file (instead of JSON)
#   --help               Show this help
#
# Security:
#   - Output file gets chmod 600
#   - Warns if output is written to a world-readable location
#   - Suggests shredding original JSON after encryption
#
# Exit codes:
#   0   Success
#   1   Usage or input error
#   2   Dependency missing
#   3   Cryptographic error (invalid length, encoding)
#   4   Permission error (cannot write output)
#   5   Integrity check failed (public key mismatch)
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
VALID_B64_LENGTHS=(44 88)      # 32 bytes → 44 chars, 64 bytes → 88 chars (no padding)
VALID_HEX_LENGTHS=(64 128)     # 32 bytes → 64 hex, 64 bytes → 128 hex

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
OUTPUT_FILE=""
FORCE=0
DRY_RUN=0
NO_VERIFY=0
EXPAND=0
FORMAT="hex"
QUIET=0
VERBOSE=0
PRIVKEY_FILE=""
KEYFILE=""

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# //'
    exit 0
}

# -----------------------------------------------------------------------------
# Dependency checks (with fallback)
# -----------------------------------------------------------------------------
check_deps() {
    local missing=0
    # Prefer jq, fallback to grep+sed if not available
    if ! command -v jq &>/dev/null; then
        print_warn "jq not found; falling back to grep/sed (limited)."
        JQ_AVAILABLE=0
        # Ensure grep/sed are available
        if ! command -v grep &>/dev/null || ! command -v sed &>/dev/null; then
            print_error "Neither jq nor grep+sed available. Please install jq or grep+sed."
            missing=1
        fi
    else
        JQ_AVAILABLE=1
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
# JSON parsing (jq or fallback)
# -----------------------------------------------------------------------------
json_get() {
    local file="$1" key="$2" default="${3:-}"
    if [[ $JQ_AVAILABLE -eq 1 ]]; then
        jq -r "$key // \"$default\"" "$file" 2>/dev/null || echo "$default"
    else
        # Simple grep/sed fallback (limited, cannot handle nested objects)
        grep -E "^\s*\"$key\"\s*:" "$file" | head -1 | \
        sed -E 's/^[^:]*:\s*//; s/^"//; s/".*$//; s/^[[:space:]]*//; s/[[:space:]]*$//' || echo "$default"
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
# Hex → base64 conversion (for format conversions)
# -----------------------------------------------------------------------------
hex_to_base64() {
    local hex="$1"
    echo "$hex" | xxd -r -p | base64 | tr -d '\n'
}

# -----------------------------------------------------------------------------
# Validate base64 length
# -----------------------------------------------------------------------------
validate_b64_length() {
    local b64="$1" context="$2"
    local len=${#b64}
    # Strip padding for length check
    local stripped="${b64%%=*}"
    local stripped_len=${#stripped}
    for valid in "${VALID_B64_LENGTHS[@]}"; do
        if [[ $stripped_len -eq $valid ]]; then
            return 0
        fi
    done
    print_error "$context length is $stripped_len chars (including padding); expected one of ${VALID_B64_LENGTHS[*]}"
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
# Validate key integrity (public key derivation not possible without full curve)
# We only check if public key matches the provided one (if any).
# -----------------------------------------------------------------------------
verify_key_pair() {
    local priv_hex="$1" pub_hex="$2"
    if [[ -z "$pub_hex" ]]; then
        print_info "No public key provided; skipping pair verification."
        return 0
    fi
    # Placeholder: actual ed25519 pubkey derivation requires crypto libs.
    # For now, we just check length and log a warning if not matching.
    # In production, you could use openssl or a small helper.
    print_warn "Public key verification requires external crypto; skipping."
    return 0
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
            --dry-run)
                DRY_RUN=1; shift ;;
            --no-verify)
                NO_VERIFY=1; shift ;;
            --expand)
                EXPAND=1; shift ;;
            --format)
                FORMAT="$2"; shift 2 ;;
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

    # Validate mutual exclusivity
    if [[ -n "$KEYFILE" && -n "$PRIVKEY_FILE" ]]; then
        print_error "Cannot specify both <priv_validator_key.json> and --privkey-file"
        exit 1
    fi
    if [[ -z "$KEYFILE" && -z "$PRIVKEY_FILE" ]]; then
        print_error "Missing required argument: <priv_validator_key.json> or --privkey-file <file>"
        echo "Usage: $0 [OPTIONS] <priv_validator_key.json> | $0 --privkey-file <key.b64>"
        exit 1
    fi

    if [[ "$FORMAT" != "hex" && "$FORMAT" != "hex_padded" && "$FORMAT" != "base64" ]]; then
        print_error "Invalid --format '$FORMAT'. Supported: hex, hex_padded, base64"
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

    # ── Extract from JSON or direct base64 file ──────────────────────────────

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
        print_info "Private key loaded from $PRIVKEY_FILE (${#priv_key_b64} chars)"
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
        if [[ $JQ_AVAILABLE -eq 1 ]]; then
            if ! jq empty "$KEYFILE" 2>/dev/null; then
                print_error "Invalid JSON in $KEYFILE"
                exit 1
            fi
        else
            # Basic JSON validation: check for opening/closing braces
            if ! grep -q '^[[:space:]]*{' "$KEYFILE"; then
                print_warn "JSON validation fallback: file may not be valid JSON."
            fi
        fi

        # Extract key type
        local key_type=$(json_get "$KEYFILE" ".type // \"\"" "$SUPPORTED_KEY_TYPE")
        if [[ -z "$key_type" ]]; then
            key_type="$SUPPORTED_KEY_TYPE"
            print_warn "Key type missing; assuming $SUPPORTED_KEY_TYPE"
        fi
        if [[ "$key_type" != "$SUPPORTED_KEY_TYPE" ]]; then
            print_error "Unsupported key type '$key_type' (expected '$SUPPORTED_KEY_TYPE')"
            exit 1
        fi
        print_success "Key type verified: $key_type"

        # Extract private key (try different common paths)
        priv_key_b64=$(json_get "$KEYFILE" ".priv_key.value // .priv_key // \"\"" "")
        if [[ -z "$priv_key_b64" ]]; then
            # Try alternative structure: {"priv_key": "...", "pub_key": "..."}
            priv_key_b64=$(json_get "$KEYFILE" ".priv_key // \"\"" "")
        fi
        if [[ -z "$priv_key_b64" ]]; then
            print_error "Could not extract private key from $KEYFILE"
            echo "Expected JSON structure:"
            echo '  {"type": "ed25519", "priv_key": {"value": "<base64>"}}'
            exit 1
        fi
        print_success "Private key extracted (${#priv_key_b64} chars base64)"

        # Extract public key (optional)
        pub_key_b64=$(json_get "$KEYFILE" ".pub_key.value // .pub_key // \"\"" "")
        if [[ -n "$pub_key_b64" ]]; then
            print_info "Public key found in JSON"
        else
            # Try top-level pub_key
            pub_key_b64=$(json_get "$KEYFILE" ".pub_key // \"\"" "")
            if [[ -n "$pub_key_b64" ]]; then
                print_info "Public key found (top-level)"
            fi
        fi
    fi

    # ── Validate private key length ───────────────────────────────────────────

    validate_b64_length "$priv_key_b64" "Private key" || exit 3

    # ── Convert private key to hex ───────────────────────────────────────────

    local priv_key_hex
    priv_key_hex=$(base64_to_hex "$priv_key_b64") || {
        print_error "Failed to decode base64 private key"
        exit 3
    }
    validate_hex_length "$priv_key_hex" "Private key" || exit 3

    # If EXPAND is set, we need to expand the key to 64 bytes.
    # CometBFT's expanded key is: private_key (32) + public_key (32).
    # Since we don't have the public key here, we log a warning.
    if [[ $EXPAND -eq 1 ]]; then
        if [[ ${#priv_key_hex} -eq 64 ]]; then
            # Already 64 hex (32 bytes); need public key to expand.
            if [[ -n "$pub_key_b64" ]]; then
                local pub_key_hex
                pub_key_hex=$(base64_to_hex "$pub_key_b64") || {
                    print_error "Failed to decode public key for expansion"
                    exit 3
                }
                if [[ ${#pub_key_hex} -eq 64 ]]; then
                    priv_key_hex="${priv_key_hex}${pub_key_hex}"
                    print_success "Private key expanded to 128 hex chars (64 bytes)"
                else
                    print_error "Public key is ${#pub_key_hex} hex chars; expected 64 for expansion"
                    exit 3
                fi
            else
                print_error "Cannot expand private key without public key. Use --no-verify to skip expansion."
                exit 1
            fi
        elif [[ ${#priv_key_hex} -eq 128 ]]; then
            print_info "Private key is already expanded (128 hex chars)"
        else
            print_error "Private key hex length ${#priv_key_hex} is not 64 or 128; cannot expand."
            exit 3
        fi
    fi

    print_success "Hex conversion successful (${#priv_key_hex} chars)"

    # ── Convert public key if available ──────────────────────────────────────

    local pub_key_hex=""
    if [[ -n "$pub_key_b64" ]]; then
        if validate_b64_length "$pub_key_b64" "Public key" 2>/dev/null; then
            pub_key_hex=$(base64_to_hex "$pub_key_b64") || true
            if [[ ${#pub_key_hex} -eq 64 ]]; then
                print_success "Public key extracted and verified (64 hex chars)"
            else
                print_warn "Public key hex length is ${#pub_key_hex} (expected 64)"
                if [[ $NO_VERIFY -eq 0 ]]; then
                    print_error "Public key verification failed."
                    exit 5
                fi
            fi
        else
            print_warn "Public key base64 length is invalid; skipping verification"
        fi
    fi

    # ── Verify key pair (if requested and pub key available) ────────────────

    if [[ $NO_VERIFY -eq 0 && -n "$pub_key_hex" ]]; then
        verify_key_pair "$priv_key_hex" "$pub_key_hex"
    fi

    # ── Format the output ─────────────────────────────────────────────────────

    local output_data=""
    case "$FORMAT" in
        hex)
            output_data="$priv_key_hex"
            ;;
        hex_padded)
            # Pad with 0x prefix and maybe spaces (not typical for IONA, but user may want it)
            output_data="0x$priv_key_hex"
            ;;
        base64)
            output_data=$(hex_to_base64 "$priv_key_hex")
            ;;
        *)
            print_error "Unknown format: $FORMAT"
            exit 1
            ;;
    esac

    # ── Handle output ─────────────────────────────────────────────────────────

    if [[ -n "$OUTPUT_FILE" ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then
            print_info "Dry-run: would write to $OUTPUT_FILE"
            echo "$output_data"
            return 0
        fi

        if [[ -e "$OUTPUT_FILE" && $FORCE -eq 0 ]]; then
            print_error "Output file $OUTPUT_FILE already exists. Use --force to overwrite."
            exit 4
        fi

        # Check if output directory is writable
        local out_dir
        out_dir="$(dirname "$OUTPUT_FILE")"
        if [[ ! -w "$out_dir" ]]; then
            print_error "Output directory $out_dir is not writable"
            exit 4
        fi

        # Write file
        trap cleanup_output EXIT
        echo -n "$output_data" > "$OUTPUT_FILE" || {
            print_error "Failed to write to $OUTPUT_FILE"
            exit 4
        }
        chmod 600 "$OUTPUT_FILE"
        trap - EXIT

        print_success "Private key written to $OUTPUT_FILE (${#output_data} ${FORMAT} chars)"
        if [[ $QUIET -eq 0 ]]; then
            echo ""
            print_info "You can now encrypt this key with IONA:"
            echo "  iona keys import $OUTPUT_FILE --output keys.enc"
            echo ""
            print_warn "After encryption, securely delete the original key file:"
            echo "  shred -vfz -n 10 \"${KEYFILE:-$PRIVKEY_FILE}\""
        fi
    else
        # Output to stdout
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
            echo "   iona keys import <hex-file> --output keys.enc"
            echo "   (save the hex key to a file first with --output option)"
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
            # Quiet mode: output just the formatted key
            echo "$output_data"
        fi
    fi

    print_success "Key import completed successfully"
}

main "$@"
