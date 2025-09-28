#!/usr/bin/env bash
set -euo pipefail

python3 -m venv .venv
. .venv/bin/activate
python -m pip install -q -r core/requirements.txt -c constraints.txt
python -m pip install -q -c constraints.txt black flake8 mypy pytest pytest-cov pytest-asyncio
# Editable installs
python -m pip install -e sdk/python || true
python -m pip install -e tools/cli || true
echo "Dev bootstrap complete."

