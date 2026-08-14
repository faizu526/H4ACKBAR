#!/usr/bin/env bash
# H4ACKBAR launcher (Linux/macOS)
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

if [[ ! -d ".venv" ]]; then
  echo "[+] creating venv"
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

if ! python -c "import PyQt6" 2>/dev/null; then
  echo "[+] installing deps"
  pip install -e . >/dev/null
fi

exec python -m h4ackbar "$@"
