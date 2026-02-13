#!/bin/bash
echo "Starting VpsHelper..."
cd "$(dirname "$0")"
PORT=15018
echo "Checking old process on port ${PORT}..."
if command -v lsof >/dev/null 2>&1; then
    OLD_PIDS=$(lsof -ti tcp:${PORT})
    if [ -n "${OLD_PIDS}" ]; then
        echo "Stopping PIDs: ${OLD_PIDS}"
        kill -9 ${OLD_PIDS} >/dev/null 2>&1
    fi
elif command -v fuser >/dev/null 2>&1; then
    fuser -k ${PORT}/tcp >/dev/null 2>&1
fi
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q -r requirements.txt
export TGHELPER_DEV=1
python3 VpsHelper.py
