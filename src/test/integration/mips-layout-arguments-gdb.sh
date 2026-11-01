#!/usr/bin/env bash
set -euo pipefail
case_dir=$(realpath "$1")
mode=$2
gdb_command=${3:-gdb-multiarch}
script_dir=$(cd "$(dirname "$0")" && pwd)
source "$script_dir/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
mapfile -t config < <(python3 - "$case_dir/metadata.json" <<'PY_CONFIG'
import json,sys
metadata=json.load(open(sys.argv[1]))
print(metadata['emulator'])
print(metadata['sysroot'])
PY_CONFIG
)
gdb_args=()
if [[ -n "${4:-}" ]]; then
    gdb_args+=("--data-directory=$4")
fi
qemu_socket_start "$case_dir/$mode-qemu" "${config[0]}" "${config[1]}" "$case_dir/input"
MIPS_LAYOUT_CASE="$case_dir" MIPS_LAYOUT_MODE="$mode" MIPS_LAYOUT_REMOTE="$qemu_socket_path" \
    timeout 90s "$gdb_command" "${gdb_args[@]}" -q -nx -batch \
    -ex 'set python print-stack full' -x "$script_dir/mips-layout-arguments-gdb.py"
qemu_socket_wait
