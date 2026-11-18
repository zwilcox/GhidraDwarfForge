#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then
    echo "usage: $0 <ghidra-dir>" >&2
    exit 2
fi
exec python3 "$(dirname "$0")/external-function-declarations-export.py" "$1"
