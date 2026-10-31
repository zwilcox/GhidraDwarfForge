#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
target=$3
compiler_log=$4
source "$repository/src/test/integration/qemu-socket.sh"
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
remote=
emulator=
sysroot=
case "$target" in
    x86_64) ;;
    aarch64) emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
    mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
    mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
    *) echo "unsupported alias target: $target" >&2; exit 64 ;;
esac
if [[ -n "$emulator" ]]; then
    qemu_socket_start "$case_dir/runtime.qemu" "$emulator" "$sysroot" "$case_dir/aliases.input"
    remote=$qemu_socket_path
fi
ALIAS_CASE="$case_dir" ALIAS_VARIANT=forge ALIAS_TARGET="$target" ALIAS_REMOTE="$remote" ALIAS_SYSROOT="$sysroot" \
    gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
    -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex 'set disable-randomization off' -ex 'set python print-stack full' \
    -x "$repository/src/test/integration/local-symbol-merge-gdb.py" \
    > "$case_dir/forge-gdb.log" 2>&1
if [[ -n "$remote" ]]; then qemu_socket_wait; fi
layout_validate_gdb_diagnostics "$case_dir/forge-gdb.log" "$case_dir/aliases.input" forge "$target" "$compiler_log"
grep -Fxq 'retained-function-aliases-gdb=forge PASS' "$case_dir/forge-gdb.log"
