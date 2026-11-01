#!/usr/bin/env bash
set -euo pipefail
repository=$(realpath "$(dirname "$0")/../../..")
case_dir=$(realpath "$1")
target=$2
mode=$3
symbols=$4
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
remote=
options=()
if [[ "$target" == aarch64 ]]; then
    qemu_socket_start "$case_dir/$mode.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$case_dir/stripped"
    remote=$qemu_socket_path
    options+=(-ex 'set sysroot /usr/aarch64-linux-gnu')
fi
FORGE_OBJECT_CASE="$case_dir" FORGE_OBJECT_MODE="$mode" FORGE_OBJECT_REMOTE="$remote" \
    timeout 90s gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set auto-solib-add off' -ex 'set disable-randomization off' "${options[@]}" \
    -ex "file \"$case_dir/stripped\"" -ex "symbol-file \"$symbols\"" \
    -x "$repository/src/test/integration/object-parameter-gdb.py"
if [[ -n "$remote" ]]; then qemu_socket_wait; fi
