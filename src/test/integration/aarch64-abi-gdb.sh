#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
    echo 'usage: aarch64-abi-gdb.sh <case-directory> <compiler|forge>' >&2
    exit 64
fi
script_directory=$(cd "$(dirname "$0")" && pwd)
case_directory=$(realpath "$1")
mode=$2
[[ "$mode" == compiler || "$mode" == forge ]] || exit 64
source "$script_directory/qemu-socket.sh"
source "$script_directory/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
qemu_socket_start "$case_directory/$mode.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$case_directory/abi.input"
FORGE_AARCH64_ABI_MODE="$mode" FORGE_AARCH64_ABI_CASE="$case_directory" \
    FORGE_AARCH64_ABI_REMOTE="$qemu_socket_path" \
    timeout 90s gdb-multiarch -q -nx -batch -ex 'set python print-stack full' \
        -x "$script_directory/aarch64-abi-gdb.py" 2>&1 | tee "$case_directory/$mode-runtime-gdb.log"
qemu_socket_wait
layout_validate_gdb_diagnostics "$case_directory/$mode-runtime-gdb.log" "$case_directory/abi.input" \
    "$mode" aarch64 "$case_directory/compiler-runtime-gdb.log"
