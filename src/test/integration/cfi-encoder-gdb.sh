#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 5 ]]; then
    echo 'usage: cfi-encoder-gdb.sh target mode symbols original prefix' >&2
    exit 2
fi
export FORGE_FRAME_TARGET=$1 FORGE_FRAME_MODE=$2
symbols=$(realpath "$3")
original=$(realpath "$4")
prefix=$(realpath -m "$5")
export FORGE_FRAME_RESULT="$prefix.json" FORGE_FRAME_REMOTE=
scripts=$(realpath "$(dirname "$0")")
source "$scripts/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
options=()
case "$FORGE_FRAME_TARGET" in
    x86_64) debugger=gdb ;;
    aarch64)
        debugger=gdb-multiarch
        qemu_socket_start "$prefix.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$original"
        export FORGE_FRAME_REMOTE=$qemu_socket_path
        options=(-ex 'set sysroot /usr/aarch64-linux-gnu')
        ;;
    *) exit 2 ;;
esac
timeout --kill-after=5 90 "$debugger" -q -nx -batch "${options[@]}" \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set disable-randomization off' -ex 'set auto-solib-add off' \
    -ex "file \"$original\"" -ex "symbol-file \"$symbols\"" \
    -x "$scripts/cfi-encoder-gdb.py" > "$prefix.log" 2>&1
if [[ "$FORGE_FRAME_TARGET" == aarch64 ]]; then qemu_socket_wait; fi
