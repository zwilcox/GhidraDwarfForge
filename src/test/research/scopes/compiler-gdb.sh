#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 3 ]]; then
    echo 'usage: compiler-gdb.sh <repository> <case-directory> <x86_64|aarch64>' >&2
    exit 2
fi
repository=$(realpath "$1")
case_directory=$(realpath "$2")
export TARGET=$3 SCOPE_OUT="$case_directory/compiler-gdb.json"
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
remote=()
case "$TARGET" in
    x86_64) ;;
    aarch64)
        qemu_socket_start "$case_directory/qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$case_directory/reference"
        remote=(-ex 'set sysroot /usr/aarch64-linux-gnu' -ex "target remote $qemu_socket_path")
        ;;
    *) exit 2 ;;
esac
gdb-multiarch -nx -q -batch "$case_directory/reference" "${remote[@]}" \
    -ex "source $repository/src/test/research/scopes/compiler-gdb.py"
test -f "$SCOPE_OUT"
if [[ $TARGET == aarch64 ]]; then qemu_socket_wait; fi
