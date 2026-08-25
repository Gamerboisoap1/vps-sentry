#!/usr/bin/env bash
# Run Sentinel against the generated demo logs instead of the real system logs.
set -euo pipefail
cd "$(dirname "$0")"

export SENTINEL_AUTH_LOG="${SENTINEL_AUTH_LOG:-$PWD/data/demo/auth.log}"
export SENTINEL_UFW_LOG="${SENTINEL_UFW_LOG:-$PWD/data/demo/ufw.log}"
export SENTINEL_POLL_SECONDS="${SENTINEL_POLL_SECONDS:-5}"

if [ ! -f "$SENTINEL_AUTH_LOG" ]; then
  echo "No demo logs yet -- generating them first."
  ./.venv/bin/python -m tools.seed
fi

exec ./.venv/bin/python -m uvicorn sentinel.api:app --host 127.0.0.1 --port "${PORT:-8787}"
