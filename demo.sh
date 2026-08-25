#!/usr/bin/env bash
# Run Sentinel against the generated demo logs instead of the real system logs.
set -euo pipefail

# A launcher may hand us a working directory we cannot resolve -- macOS keeps
# ~/Desktop owner-only, so getcwd() fails there for any process that was not
# granted access. Anchor every path to this script's own location instead of
# to $PWD, which is unreliable (or empty) in that situation.
HERE="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)" || HERE=""
if [ -z "$HERE" ]; then
  echo "demo.sh: cannot resolve its own directory; invoke it by absolute path." >&2
  exit 1
fi
cd "$HERE"

export SENTINEL_AUTH_LOG="${SENTINEL_AUTH_LOG:-$HERE/data/demo/auth.log}"
export SENTINEL_UFW_LOG="${SENTINEL_UFW_LOG:-$HERE/data/demo/ufw.log}"
export SENTINEL_POLL_SECONDS="${SENTINEL_POLL_SECONDS:-5}"

if [ ! -f "$SENTINEL_AUTH_LOG" ]; then
  echo "No demo logs yet -- generating them first."
  "$HERE/.venv/bin/python" -m tools.seed
fi

exec "$HERE/.venv/bin/python" -m uvicorn sentinel.api:app \
  --host 127.0.0.1 --port "${PORT:-8787}"
