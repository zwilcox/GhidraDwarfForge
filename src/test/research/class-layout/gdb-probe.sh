#!/usr/bin/env bash
set -euo pipefail
repository=$(realpath "$(dirname "$0")/../../../..")
case_dir=$(realpath "$1")
target=$2
variant=$3
export CLASS_LAYOUT_STOP=$4 CLASS_LAYOUT_OUT="$case_dir/$variant.gdb.json" CLASS_LAYOUT_VARIANT="$variant"
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
remote=
options=()
if [[ "$target" == aarch64 ]]; then
    qemu_socket_start "$case_dir/$variant.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$case_dir/stripped"
    remote=$qemu_socket_path
    options+=(-ex 'set sysroot /usr/aarch64-linux-gnu')
fi
CLASS_LAYOUT_REMOTE="$remote" timeout 90s gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set auto-solib-add off' -ex 'set disable-randomization off' "${options[@]}" \
    -ex "set substitute-path $repository/src/test/research/scopes $case_dir" \
    -ex "file \"$case_dir/stripped\"" -ex "symbol-file \"$case_dir/$variant.dbg\"" \
    -x "$repository/src/test/research/class-layout/gdb-probe.py"
if [[ -n "$remote" ]]; then qemu_socket_wait; fi
