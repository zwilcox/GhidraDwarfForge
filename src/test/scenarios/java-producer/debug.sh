#!/usr/bin/env bash
# Run GDB from a directory other than the generated source directory.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export EVAL_CASE=$1 EVAL_INPUT=$2 EVAL_SIDECAR=$3 EVAL_MODEL=$4
export EVAL_START=$5 EVAL_SIZE=$6 EVAL_SPLIT=$7 EVAL_FIRST=$8 EVAL_SECOND=$9
boot=${10}
export EVAL_CALLER=${11}
cd "$(dirname "$EVAL_INPUT")"
export EVAL_SOCKET=
case "$EVAL_CASE" in
    x86_64) debugger=gdb ;;
    mips32be)
        debugger=gdb-multiarch
        source "$here/../../integration/qemu-socket.sh"
        trap qemu_socket_cleanup EXIT
        qemu_socket_start "$(dirname "$EVAL_SIDECAR")/qemu" qemu-mips-static /usr/mips-linux-gnu "$EVAL_INPUT"
        EVAL_SOCKET=$qemu_socket_path
        ;;
    mips64high)
        debugger=gdb-multiarch
        sockets=$(mktemp -d /tmp/forge-malta.XXXXXXXX)
        EVAL_SOCKET=$sockets/gdb
        qemu-system-mips64 -M malta -cpu MIPS64R2-generic -m 128 -display none -vga none \
            -serial none -monitor none -nic none -device "loader,file=$EVAL_INPUT" \
            -device "loader,addr=0x$boot,cpu-num=0" -S -gdb "unix:$EVAL_SOCKET,server=on,wait=off" \
            > "$(dirname "$EVAL_SIDECAR")/qemu.log" 2>&1 &
        process=$!
        cleanup() {
            kill "$process" 2>/dev/null || true
            wait "$process" 2>/dev/null || true
            rm -f -- "$EVAL_SOCKET"
            rmdir -- "$sockets"
        }
        trap cleanup EXIT
        for ((i=0; i<100; i++)); do
            if [[ -S $EVAL_SOCKET ]]; then break; fi
            kill -0 "$process"
            sleep 0.05
        done
        test -S "$EVAL_SOCKET"
        ;;
    *) exit 2 ;;
esac
export EVAL_GDB_SCRIPT=$here/observe.py
timeout 45s "$debugger" -q -nx -batch -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex 'python import os, runpy; runpy.run_path(os.environ["EVAL_GDB_SCRIPT"], run_name="__main__")'
if [[ $EVAL_CASE == mips32be ]]; then qemu_socket_wait; fi
