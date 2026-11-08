#!/usr/bin/env bash
set -euo pipefail
repository=$(realpath "$(dirname "$0")/../../..")
case_dir=$(realpath "$1")
target=$2
mode=$3
symbols=$4
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
remote=
options=()
emulator= sysroot=
case "$target" in
    x86_64) ;;
    aarch64) emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
    arm32) emulator=qemu-arm-static; sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf} ;;
    mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
    mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
    *) echo "unsupported target: $target" >&2; exit 64 ;;
esac
if [[ -n "$emulator" ]]; then
    qemu_socket_start "$case_dir/$mode.qemu" "$emulator" "$sysroot" "$case_dir/original"
    remote=$qemu_socket_path
    options+=(-ex "set sysroot $sysroot")
fi
FORGE_MULTI_CASE="$case_dir" FORGE_MULTI_MODE="$mode" FORGE_MULTI_SYMBOLS="$symbols" FORGE_MULTI_REMOTE="$remote" \
    timeout 90s gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set auto-solib-add off' -ex 'set disable-randomization off' "${options[@]}" \
    -ex "file \"$case_dir/original\"" -ex "symbol-file \"$symbols\"" \
    -x "$repository/src/test/integration/multifile-target-gdb.py"
if [[ -n "$remote" ]]; then qemu_socket_wait; fi
