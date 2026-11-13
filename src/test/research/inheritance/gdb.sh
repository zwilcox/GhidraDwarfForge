#!/usr/bin/env bash
set -euo pipefail
repository=$(realpath "$(dirname "$0")/../../../..")
case_dir=$(realpath "$1")
target=$2
variant=$3
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
remote=
options=()
if [[ "$target" == aarch64 ]]; then
    qemu_socket_start "$case_dir/$variant.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$case_dir/runtime.elf"
    remote=$qemu_socket_path
    options+=(-ex 'set sysroot /usr/aarch64-linux-gnu')
fi
INHERITANCE_REMOTE="$remote" INHERITANCE_VARIANT="$variant" INHERITANCE_RESULT="$case_dir/$variant.gdb.json" \
    timeout 90s gdb-multiarch -q -nx -nh -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set auto-load off' \
    -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex 'set disable-randomization off' "${options[@]}" \
    -ex "file \"$case_dir/runtime.elf\"" -ex "symbol-file \"$case_dir/$variant.dbg\"" \
    -x "$repository/src/test/research/inheritance/gdb.py"
if [[ -n "$remote" ]]; then qemu_socket_wait; fi
