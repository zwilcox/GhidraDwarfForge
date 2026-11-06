#!/usr/bin/env bash
set -euo pipefail
repository=$(realpath "$(dirname "$0")/../../..")
case_dir=$(realpath "$1")
reference=$(realpath "$2")
target=$3
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
remote=
options=()
case "$target" in
    x86_64) ;;
    aarch64) emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
    mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
    mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
    *) exit 64 ;;
esac
if [[ "$target" != x86_64 ]]; then
    qemu_socket_start "$case_dir/export.qemu" "$emulator" "$sysroot" "$reference/stripped"
    remote=$qemu_socket_path
    options+=(-ex "set sysroot $sysroot")
fi
FORGE_ANNOTATION_CASE="$case_dir" FORGE_ANNOTATION_REFERENCE="$reference" FORGE_ANNOTATION_REMOTE="$remote" \
    timeout 90s gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set auto-solib-add off' -ex 'set disable-randomization off' "${options[@]}" \
    -x "$repository/src/test/integration/annotation-default-gdb.py"
if [[ -n "$remote" ]]; then qemu_socket_wait; fi
