#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
variants=(compiler fixed)
if [[ -f "$case_dir/previous.dbg" ]]; then variants+=(previous); fi
for variant in "${variants[@]}"; do
    input="$case_dir/control.input"
    if [[ "$variant" == compiler ]]; then input="$case_dir/control.reference"; fi
    remote=
    if [[ "$THUNK_TARGET" == aarch64 ]]; then
        qemu_socket_start "$case_dir/$variant.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$input"
        remote=$qemu_socket_path
    fi
    THUNK_CASE="$case_dir" THUNK_VARIANT="$variant" THUNK_REMOTE="$remote" \
        gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' -ex 'set python print-stack full' \
        -x "$repository/src/test/integration/curated-thunk-gdb.py" \
        > "$case_dir/$variant-gdb.log" 2>&1
    if [[ "$THUNK_TARGET" == aarch64 ]]; then qemu_socket_wait; fi
    grep -Fxq "curated-thunk-gdb=$variant PASS" "$case_dir/$variant-gdb.log"
done
