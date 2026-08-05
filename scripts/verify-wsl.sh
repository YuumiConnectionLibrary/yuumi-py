#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv="${YUUMI_PY_WSL_VENV:-$repository/.venv-wsl}"

python3 -m venv "$venv"
"$venv/bin/python" -m pip install --disable-pip-version-check --editable "$repository"
"$venv/bin/python" "$repository/integration/run.py"

