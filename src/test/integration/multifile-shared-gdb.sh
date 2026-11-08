#!/usr/bin/env bash
set -euo pipefail
case_dir=$(realpath "$1")
target=$2
mode=$3
symbols=$(realpath "$4")
scripts=$(realpath "$(dirname "$0")")
source "$scripts/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
remote=
options=(-ex "set solib-search-path $case_dir")
case "$target" in
    x86_64) emulator=; sysroot= ;;
    aarch64) emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
    arm32) emulator=qemu-arm-static; sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf} ;;
    mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
    mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
    *) exit 64 ;;
esac
if [[ -n "$emulator" ]]; then
    qemu_socket_start "$case_dir/$mode.qemu" "$emulator" "$sysroot" "$case_dir/driver" "$case_dir/original"
    remote=$qemu_socket_path
    options+=(-ex "set sysroot $sysroot")
fi
FORGE_SHARED_CASE="$case_dir" FORGE_SHARED_MODE="$mode" FORGE_SHARED_SYMBOLS="$symbols" FORGE_SHARED_REMOTE="$remote" \
    timeout 90s gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set auto-solib-add off' -ex 'set disable-randomization off' "${options[@]}" \
    -ex "file \"$case_dir/driver\"" -ex "set args $case_dir/original" \
    -x "$scripts/multifile-shared-gdb.py"
if [[ -n "$remote" ]]; then qemu_socket_wait; fi
