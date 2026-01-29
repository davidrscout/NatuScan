#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv_path="$root/.venv"
requirements="$root/requirements.txt"
python_exe="$venv_path/bin/python"

if command -v uv >/dev/null 2>&1; then
  if [ ! -d "$venv_path" ]; then
    uv venv "$venv_path"
  fi
  if [ -f "$requirements" ]; then
    uv pip install -r "$requirements"
  fi
else
  if [ ! -d "$venv_path" ]; then
    if command -v python3 >/dev/null 2>&1; then
      python3 -m venv "$venv_path"
    elif command -v python >/dev/null 2>&1; then
      python -m venv "$venv_path"
    else
      echo "No se encontro ni uv ni python."
      exit 1
    fi
  fi
  if [ -f "$requirements" ]; then
    "$python_exe" -m pip install -r "$requirements"
  fi
fi

"$python_exe" "$root/tool.py"
