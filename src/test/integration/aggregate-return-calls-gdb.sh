#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
target=$3
source "$repository/src/test/integration/qemu-socket.sh"
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
emulator=
sysroot=
case "$target" in
    x86_64|i386) ;;
    aarch64) emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
    arm32) emulator=qemu-arm-static; sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf} ;;
    mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
    mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
    *) exit 64 ;;
esac
for variant in compiler forge; do
    remote=
    if [[ -n "$emulator" ]]; then
        qemu_socket_start "$case_dir/$variant.qemu" "$emulator" "$sysroot" "$case_dir/calls.input"
        remote=$qemu_socket_path
    fi
    AGGREGATE_CASE="$case_dir" AGGREGATE_VARIANT="$variant" AGGREGATE_REMOTE="$remote" AGGREGATE_SYSROOT="$sysroot" \
        timeout 90s gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' -ex 'set disable-randomization off' \
        -ex 'set python print-stack full' -x "$repository/src/test/integration/aggregate-return-calls-gdb.py" \
        > "$case_dir/$variant-gdb.log" 2>&1
    if [[ -n "$emulator" ]]; then qemu_socket_wait; fi
    layout_validate_gdb_diagnostics "$case_dir/$variant-gdb.log" "$case_dir/calls.input" "$variant" "$target" "$case_dir/compiler-gdb.log"
    grep -Fxq "AGGREGATE_RETURN_CALLS_PASS $variant" "$case_dir/$variant-gdb.log"
done
