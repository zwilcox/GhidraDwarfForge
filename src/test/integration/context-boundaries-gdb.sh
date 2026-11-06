#!/usr/bin/env bash
set -euo pipefail
repository=$(realpath "$(dirname "$0")/../../..")
case_dir=$(realpath "$1")
target=$2
mode=$3
symbols="$case_dir/$mode.dbg"
if [[ "$mode" == compiler ]]; then symbols="$case_dir/reference"; fi
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
case "$target" in
    arm32) emulator=qemu-arm-static; sysroot=${ARM32_SYSROOT:-/usr/arm-linux-gnueabihf} ;;
    mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
    mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
    *) exit 64 ;;
esac
qemu_socket_start "$case_dir/$mode.qemu" "$emulator" "$sysroot" "$case_dir/original"
FORGE_BOUNDARY_CASE="$case_dir" FORGE_BOUNDARY_TARGET="$target" FORGE_BOUNDARY_MODE="$mode" \
    timeout 90s gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set auto-solib-add off' -ex "set sysroot $sysroot" \
    -ex "file $case_dir/original" -ex "symbol-file $symbols" \
    -ex "target remote $qemu_socket_path" -x "$repository/src/test/integration/context-boundaries-gdb.py"
qemu_socket_wait
