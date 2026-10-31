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
    mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
    mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
    *) echo "unsupported alias target: $target" >&2; exit 64 ;;
esac
for variant in compiler forge; do
    if [[ "$variant" == compiler ]]; then input="$case_dir/aliases.reference"; else input="$case_dir/aliases.input"; fi
    remote=
    if [[ -n "$emulator" ]]; then
        qemu_socket_start "$case_dir/$variant.qemu" "$emulator" "$sysroot" "$input"
        remote=$qemu_socket_path
    fi
    ALIAS_CASE="$case_dir" ALIAS_VARIANT="$variant" ALIAS_TARGET="$target" ALIAS_REMOTE="$remote" ALIAS_SYSROOT="$sysroot" \
        gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' -ex 'set python print-stack full' \
        -x "$repository/src/test/integration/retained-function-aliases-gdb.py" \
        > "$case_dir/$variant-gdb.log" 2>&1
    if [[ -n "$remote" ]]; then qemu_socket_wait; fi
    layout_validate_gdb_diagnostics "$case_dir/$variant-gdb.log" "$input" "$variant" "$target" "$case_dir/compiler-gdb.log"
    grep -Fxq "retained-function-aliases-gdb=$variant PASS" "$case_dir/$variant-gdb.log"
done
