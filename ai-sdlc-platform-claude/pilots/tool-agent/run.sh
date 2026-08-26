#!/usr/bin/env sh
# Run pilot 3 (tool-agent) end to end, offline, with the dry runner.
# Usage: ./run.sh [--workdir DIR] [--no-sync-back] [--quiet]
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
if [ -x "$repo/.venv/bin/python" ]; then py="$repo/.venv/bin/python"; else py="python3"; fi
exec "$py" "$here/pilot_tool_agent.py" "$@"
