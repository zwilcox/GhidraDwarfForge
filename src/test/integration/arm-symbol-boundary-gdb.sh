#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
source "$repository/src/test/integration/qemu-socket.sh"
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
for variant in reference fixed; do
    input=$case_dir/sectionless.elf
    if [[ "$variant" == reference ]]; then input=$case_dir/reference.elf; fi
    qemu_socket_start "$case_dir/$variant.qemu" qemu-arm-static / "$input"
    BOUNDARY_VARIANT="$variant" BOUNDARY_CASE="$case_dir" BOUNDARY_REMOTE="$qemu_socket_path" \
        timeout 30s gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set python print-stack full' -x "$repository/src/test/integration/arm-symbol-boundary-gdb.py" \
        > "$case_dir/$variant-gdb.log" 2>&1
    qemu_socket_wait
    layout_validate_gdb_diagnostics "$case_dir/$variant-gdb.log" "$input" "$variant" arm32 "$case_dir/reference-gdb.log"
    grep -Fxq "ARM_BOUNDARY_RUNTIME_PASS $variant" "$case_dir/$variant-gdb.log"
done
