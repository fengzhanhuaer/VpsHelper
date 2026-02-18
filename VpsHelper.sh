#!/usr/bin/env bash
set -euo pipefail

echo "Starting VpsHelper (Go)..."

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
GOAPP_DIR="${ROOT_DIR}/goapp"
PORT=15018

if [[ ! -d "${GOAPP_DIR}" ]]; then
    echo "goapp directory not found: ${GOAPP_DIR}"
    exit 1
fi

if ! command -v go >/dev/null 2>&1; then
    echo "Go is required. Install Go first: https://go.dev/dl/"
    exit 1
fi

echo "Checking old process on port ${PORT}..."
if command -v lsof >/dev/null 2>&1; then
    OLD_PIDS="$(lsof -ti tcp:${PORT} || true)"
    if [[ -n "${OLD_PIDS}" ]]; then
        echo "Stopping PIDs: ${OLD_PIDS}"
        kill -9 ${OLD_PIDS} >/dev/null 2>&1 || true
    fi
elif command -v fuser >/dev/null 2>&1; then
    fuser -k "${PORT}/tcp" >/dev/null 2>&1 || true
fi

export TGHELPER_DEV=1
if [[ -z "${TZ:-}" ]]; then
    export TZ=Asia/Shanghai
fi

cd "${GOAPP_DIR}"
exec go run ./cmd/server
