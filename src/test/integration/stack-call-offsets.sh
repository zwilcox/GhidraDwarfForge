#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
target=$3
source "$repository/src/test/integration/qemu-socket.sh"
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
remote=
if [[ "$target" == aarch64 ]]; then
    qemu_socket_start "$case_dir/offsets.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$case_dir/local.reference"
    remote=$qemu_socket_path
fi
LOCAL_CASE="$case_dir" LOCAL_TARGET="$target" LOCAL_REMOTE="$remote" \
    gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
    -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex 'set disable-randomization off' -ex 'set python print-stack full' \
    -x "$repository/src/test/integration/stack-call-offsets.py" > "$case_dir/offsets-gdb.log" 2>&1
if [[ "$target" == aarch64 ]]; then qemu_socket_wait; fi
layout_validate_gdb_diagnostics "$case_dir/offsets-gdb.log" "$case_dir/local.reference" compiler "$target" "$case_dir/offsets-gdb.log"
grep -Fxq 'stack-call-offsets=PASS' "$case_dir/offsets-gdb.log"
