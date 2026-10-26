#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
target=$3
source "$repository/src/test/integration/qemu-socket.sh"
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
for variant in compiler forge ${SPILL_PREVIOUS:-}; do
    if [[ "$variant" == compiler ]]; then input="$case_dir/spill.reference"; else input="$case_dir/spill.input"; fi
    remote=
    if [[ "$target" == aarch64 ]]; then
        qemu_socket_start "$case_dir/$variant.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$input"
        remote=$qemu_socket_path
    fi
    SPILL_CASE="$case_dir" SPILL_VARIANT="$variant" SPILL_TARGET="$target" SPILL_REMOTE="$remote" \
        gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' -ex 'set python print-stack full' \
        -x "$repository/src/test/integration/stack-spill-gdb.py" \
        > "$case_dir/$variant-gdb.log" 2>&1
    if [[ "$target" == aarch64 ]]; then qemu_socket_wait; fi
    layout_validate_gdb_diagnostics "$case_dir/$variant-gdb.log" "$input" "$variant" "$target" "$case_dir/compiler-gdb.log"
    grep -Fxq "stack-spill-gdb=$variant PASS" "$case_dir/$variant-gdb.log"
done
