#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# IONA APT Repository Setup Script — Robust Edition
# ─────────────────────────────────────────────────────────────────────────────
# Sets up a self-hosted APT repository using dpkg-scanpackages / apt-ftparchive.
# Suitable for hosting on GitHub Pages, S3, or any static file server.
#
# Usage:
#   ./setup-apt-repo.sh --debs /path/to/deb/files --output /path/to/repo [--sign-key <KEY_ID>]
#
# After running, the repo is at --output. Point apt to it with:
#   echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/iona.gpg] \
#     https://YOUR_URL/apt stable main" | sudo tee /etc/apt/sources.list.d/iona.list
#   sudo apt-get update
#   sudo apt-get install iona-node
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colours for output (safe for non‑TTY) ───────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''
fi

info()  { echo -e "${GREEN}[INFO]${NC}  $*" >&2; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Defaults ─────────────────────────────────────────────────────────────────
DEBS_DIR=""
OUTPUT_DIR=""
SIGN_KEY=""
CODENAME="stable"
COMPONENT="main"
ARCH="amd64"
GPG_HOMEDIR=""          # optional: use a dedicated GPG home
REQUIRED_CMDS=(dpkg-scanpackages gzip bzip2 md5sum sha1sum sha256sum)

# ── Help ─────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $0 --debs <dir> --output <dir> [--sign-key <KEY_ID>] [--codename <name>] [--component <name>] [--arch <arch>] [--gpg-home <dir>]

Required:
  --debs       Directory containing .deb files to include.
  --output     Output directory for the APT repository.

Optional:
  --sign-key   GPG key ID or email to sign the Release file.
  --codename   Distribution codename (default: stable).
  --component  Repository component (default: main).
  --arch       Architecture (default: amd64).
  --gpg-home   GPG home directory (e.g., --gpg-home /path/to/.gnupg).
  --help       Show this help.

Example:
  $0 --debs ./debs --output ./apt-repo --sign-key 0xDEADBEEF --codename focal
EOF
  exit 0
}

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --debs)       DEBS_DIR="$2";   shift 2 ;;
    --output)     OUTPUT_DIR="$2"; shift 2 ;;
    --sign-key)   SIGN_KEY="$2";   shift 2 ;;
    --codename)   CODENAME="$2";   shift 2 ;;
    --component)  COMPONENT="$2";  shift 2 ;;
    --arch)       ARCH="$2";       shift 2 ;;
    --gpg-home)   GPG_HOMEDIR="$2"; shift 2 ;;
    --help)       usage ;;
    *)            die "Unknown option: $1 (use --help)" ;;
  esac
done

# ── Validate arguments ───────────────────────────────────────────────────────
[[ -z "$DEBS_DIR" ]] && die "--debs is required"
[[ -z "$OUTPUT_DIR" ]] && die "--output is required"

if [[ ! -d "$DEBS_DIR" ]]; then
  die "Debian packages directory does not exist: $DEBS_DIR"
fi

# Check for .deb files (even with spaces)
deb_files=()
while IFS= read -r -d '' file; do
  deb_files+=("$file")
done < <(find "$DEBS_DIR" -maxdepth 1 -type f -name '*.deb' -print0 2>/dev/null || true)

if [[ ${#deb_files[@]} -eq 0 ]]; then
  die "No .deb files found in $DEBS_DIR"
fi
info "Found ${#deb_files[@]} .deb file(s)."

# ── Check dependencies ───────────────────────────────────────────────────────
missing=()
for cmd in "${REQUIRED_CMDS[@]}"; do
  if ! command -v "$cmd" &>/dev/null; then
    missing+=("$cmd")
  fi
done
if [[ ${#missing[@]} -gt 0 ]]; then
  die "Missing required commands: ${missing[*]}. Install with: sudo apt-get install dpkg-dev gzip bzip2 coreutils"
fi

if [[ -n "$SIGN_KEY" ]]; then
  if ! command -v gpg &>/dev/null; then
    die "GPG is required for signing but not installed. Install gnupg."
  fi
  if [[ -n "$GPG_HOMEDIR" ]]; then
    if [[ ! -d "$GPG_HOMEDIR" ]]; then
      mkdir -p "$GPG_HOMEDIR" || die "Cannot create GPG home: $GPG_HOMEDIR"
    fi
    export GNUPGHOME="$GPG_HOMEDIR"
    info "Using GPG home: $GNUPGHOME"
  fi
  # Verify key exists
  if ! gpg --list-keys "$SIGN_KEY" &>/dev/null; then
    die "GPG key $SIGN_KEY not found. Available keys:"
    gpg --list-keys
  fi
fi

# ── Create repository structure ──────────────────────────────────────────────
info "Creating repository at: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

POOL_DIR="$OUTPUT_DIR/pool/$COMPONENT"
DISTS_DIR="$OUTPUT_DIR/dists/$CODENAME"
BIN_DIR="$DISTS_DIR/$COMPONENT/binary-$ARCH"
mkdir -p "$POOL_DIR" "$BIN_DIR"

# ── Copy .deb files (preserve names, handle spaces) ─────────────────────────
info "Copying .deb files to pool..."
for deb in "${deb_files[@]}"; do
  cp -v "$deb" "$POOL_DIR/" || warn "Failed to copy: $deb"
done
info "Copied ${#deb_files[@]} package(s)."

# ── Generate Packages index ─────────────────────────────────────────────────
info "Generating Packages index..."
(
  cd "$OUTPUT_DIR"
  # dpkg-scanpackages expects relative paths; we run from repo root.
  dpkg-scanpackages "pool/$COMPONENT" /dev/null > "$BIN_DIR/Packages"
) || die "dpkg-scanpackages failed"

# Compress Packages
gzip -k -f "$BIN_DIR/Packages"
bzip2 -k -f "$BIN_DIR/Packages"
info "Packages index written: $BIN_DIR/Packages (and .gz/.bz2)"

# ── Generate Release file ────────────────────────────────────────────────────
info "Generating Release file..."
cat > "$DISTS_DIR/Release" <<EOF
Origin: IONA
Label: IONA Blockchain Node
Suite: $CODENAME
Codename: $CODENAME
Version: 1.0
Architectures: $ARCH
Components: $COMPONENT
Description: IONA blockchain node official package repository
Date: $(date -u '+%a, %d %b %Y %H:%M:%S UTC')
EOF

# Append checksums for all index files
{
  echo "MD5Sum:"
  find "$COMPONENT" -type f \( -name "Packages*" \) -print0 | sort -z | while IFS= read -r -d '' file; do
    size=$(stat -c %s "$file" 2>/dev/null || wc -c < "$file")
    printf " %s %8s %s\n" "$(md5sum "$file" | cut -d' ' -f1)" "$size" "$file"
  done
  echo "SHA1:"
  find "$COMPONENT" -type f \( -name "Packages*" \) -print0 | sort -z | while IFS= read -r -d '' file; do
    size=$(stat -c %s "$file" 2>/dev/null || wc -c < "$file")
    printf " %s %8s %s\n" "$(sha1sum "$file" | cut -d' ' -f1)" "$size" "$file"
  done
  echo "SHA256:"
  find "$COMPONENT" -type f \( -name "Packages*" \) -print0 | sort -z | while IFS= read -r -d '' file; do
    size=$(stat -c %s "$file" 2>/dev/null || wc -c < "$file")
    printf " %s %8s %s\n" "$(sha256sum "$file" | cut -d' ' -f1)" "$size" "$file"
  done
} >> "$DISTS_DIR/Release"

# ── Sign Release file ───────────────────────────────────────────────────────
if [[ -n "$SIGN_KEY" ]]; then
  info "Signing Release file with GPG key: $SIGN_KEY"
  gpg --default-key "$SIGN_KEY" \
    --armor --detach-sign \
    --output "$DISTS_DIR/Release.gpg" \
    "$DISTS_DIR/Release"
  gpg --default-key "$SIGN_KEY" \
    --armor --clearsign \
    --output "$DISTS_DIR/InRelease" \
    "$DISTS_DIR/Release"
  info "Signed: Release.gpg and InRelease"

  # Export public key for users
  gpg --armor --export "$SIGN_KEY" > "$OUTPUT_DIR/iona-archive-keyring.gpg"
  info "Public key exported: $OUTPUT_DIR/iona-archive-keyring.gpg"
else
  warn "No signing key provided. Repository will be unsigned (apt will require [trusted=yes])."
fi

# ── Summary ──────────────────────────────────────────────────────────────────
info "Repository successfully created at: $OUTPUT_DIR"
echo ""
echo "─── Repository layout ─────────────────────────────────────"
find "$OUTPUT_DIR" -type f | sort | sed "s|$OUTPUT_DIR/||"
echo "───────────────────────────────────────────────────────────"
echo ""
info "To use this repository, on each client:"
echo ""
if [[ -n "$SIGN_KEY" ]]; then
  echo "  # Import GPG key"
  echo "  curl -fsSL https://YOUR_REPO_URL/iona-archive-keyring.gpg \\"
  echo "    | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/iona.gpg"
  echo ""
  echo "  # Add repository"
  echo "  echo \"deb [arch=${ARCH} signed-by=/etc/apt/trusted.gpg.d/iona.gpg] \\"
  echo "    https://YOUR_REPO_URL/apt ${CODENAME} ${COMPONENT}\" \\"
  echo "    | sudo tee /etc/apt/sources.list.d/iona.list"
else
  echo "  # Add repository (unsigned)"
  echo "  echo \"deb [arch=${ARCH} trusted=yes] https://YOUR_REPO_URL/apt ${CODENAME} ${COMPONENT}\" \\"
  echo "    | sudo tee /etc/apt/sources.list.d/iona.list"
fi
echo ""
echo "  # Install"
echo "  sudo apt-get update && sudo apt-get install iona-node"
