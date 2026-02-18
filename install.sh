#!/usr/bin/env bash
set -euo pipefail

# Compatibility entrypoint: delegate to install-go.sh.
# Supported args:
#   $1: repo slug (e.g. fengzhanhuaer/VpsHelper) or GitHub repo URL
#   $2: install dir (optional)

DEFAULT_REPO_SLUG="fengzhanhuaer/VpsHelper"
RAW_REPO_INPUT="${1:-${REPO_SLUG:-${DEFAULT_REPO_SLUG}}}"
INSTALL_DIR_ARG="${2:-${INSTALL_DIR:-}}"

normalize_repo_slug() {
    local input="$1"
    local slug="$input"
    slug="${slug#https://github.com/}"
    slug="${slug#http://github.com/}"
    slug="${slug%.git}"
    slug="${slug%/}"
    printf "%s" "$slug"
}

REPO_SLUG_VALUE="$(normalize_repo_slug "${RAW_REPO_INPUT}")"

if [[ -f "$(dirname "$0")/install-go.sh" ]]; then
    exec bash "$(dirname "$0")/install-go.sh" "${REPO_SLUG_VALUE}" "${INSTALL_DIR_ARG}"
fi

INSTALL_GO_URL="https://github.com/${REPO_SLUG_VALUE}/raw/refs/heads/main/install-go.sh"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${INSTALL_GO_URL}" | bash -s -- "${REPO_SLUG_VALUE}" "${INSTALL_DIR_ARG}"
    exit 0
elif command -v wget >/dev/null 2>&1; then
    wget -qO- "${INSTALL_GO_URL}" | bash -s -- "${REPO_SLUG_VALUE}" "${INSTALL_DIR_ARG}"
    exit 0
else
    echo "curl or wget is required"
    exit 1
fi
