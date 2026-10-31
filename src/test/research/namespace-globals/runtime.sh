#!/usr/bin/env bash
set -euo pipefail
case_dir=$(realpath "$1")
target=$2
mode=$3
directory=$(realpath "$(dirname "$0")")
source "$directory/../../integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
remote=
options=()
if [[ "$target" == aarch64 ]]; then
    qemu_socket_start "$case_dir/$mode.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$case_dir/input"
    remote=$qemu_socket_path
    options+=(-ex 'set sysroot /usr/aarch64-linux-gnu')
fi
symbols="$case_dir/root-qualified-import.dbg"
if [[ "$mode" == compiler ]]; then symbols="$case_dir/reference"; fi
GLOBAL_CASE="$case_dir" GLOBAL_MODE="$mode" GLOBAL_TARGET="$target" GLOBAL_REMOTE="$remote" \
    timeout 90s gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set auto-solib-add off' -ex 'set disable-randomization off' "${options[@]}" \
    -ex "file \"$case_dir/input\"" -ex "symbol-file \"$symbols\"" -x "$directory/runtime.py"
if [[ -n "$remote" ]]; then qemu_socket_wait; fi
