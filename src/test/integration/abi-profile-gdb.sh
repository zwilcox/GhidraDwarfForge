#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
source "$repository/src/test/integration/qemu-socket.sh"
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
# Pin the LP64/NEON runtime; SVE debugger transport requires separate validation.
export QEMU_CPU=${ABI_PROFILE_QEMU_CPU:-cortex-a53}
for variant in compiler fixed; do
    input="$case_dir/call.input"
    symbols="$case_dir/$variant.dbg"
    if [[ "$variant" == compiler ]]; then symbols="$case_dir/call.reference"; fi
    qemu_socket_start "$case_dir/$variant-qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$input"
    ABI_PROFILE_CASE="$case_dir" ABI_PROFILE_VARIANT="$variant" timeout 60s gdb-multiarch -q -nx -batch \
        -ex 'set debuginfod enabled off' -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set auto-solib-add off' -ex 'set python print-stack full' \
        -ex "file $input" -ex "symbol-file $symbols" -ex 'set sysroot /usr/aarch64-linux-gnu' \
        -ex "target remote $qemu_socket_path" -x "$repository/src/test/integration/abi-profile-gdb.py" \
        > "$case_dir/$variant-gdb.log" 2>&1
    qemu_socket_wait
    python3 "$repository/src/test/integration/abi-profile-diagnostics.py" "$case_dir" "$variant"
    layout_validate_gdb_diagnostics "$case_dir/$variant-gdb-accounted.log" "$input" "$variant" aarch64 "$case_dir/compiler-gdb-accounted.log"
    grep -Fxq "abi-profile-gdb=$variant PASS" "$case_dir/$variant-gdb.log"
done
