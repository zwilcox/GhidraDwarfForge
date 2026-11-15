#!/usr/bin/env bash
set -euo pipefail
case_dir=$(realpath "$1")
target=$2
variant=$3
directory=$(realpath "$(dirname "$0")")
source "$directory/../../integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
binary="$case_dir/input"
symbols="$case_dir/$variant.dbg"
if [[ "$variant" == compiler ]]; then symbols="$case_dir/reference"; fi
remote=
if [[ "$target" == aarch64 ]]; then
    qemu_socket_start "$case_dir/$variant.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$binary"
    remote=$qemu_socket_path
fi
RELATION_CASE="$case_dir" RELATION_TARGET="$target" RELATION_VARIANT="$variant" RELATION_REMOTE="$remote" \
    timeout 90s gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set auto-solib-add off' -ex 'set disable-randomization off' \
    -ex "file \"$binary\"" -ex "symbol-file \"$symbols\"" -x "$directory/gdb-probe.py"
if [[ -n "$remote" ]]; then qemu_socket_wait; fi
