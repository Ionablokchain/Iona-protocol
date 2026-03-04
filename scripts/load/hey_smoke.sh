#!/usr/bin/env bash
set -euo pipefail
URL="${1:-http://127.0.0.1:8080/health}"
DUR="${2:-30s}"
CONC="${3:-50}"
if ! command -v hey >/dev/null 2>&1; then
  echo "Install hey first: go install github.com/rakyll/hey@latest" >&2
  exit 1
fi
hey -z "${DUR}" -c "${CONC}" "${URL}"
