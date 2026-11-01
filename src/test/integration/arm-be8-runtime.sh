#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
case_dir=$(realpath "${1:?case directory}")
variant=${2:?compiler or curated}
phase=${3:-instructions}
data_order=${4:-big}
case "$data_order" in
    big) emulator=qemu-armeb-static ;;
    little) emulator=qemu-arm-static ;;
    *) exit 64 ;;
esac
case "$variant" in
    compiler) symbols="$case_dir/be8.reference" ;;
    curated) symbols="$case_dir/curated.dbg" ;;
    *) exit 64 ;;
esac
qemu_socket_start "$case_dir/$variant-$phase.qemu" "$emulator" / "$case_dir/be8.stripped"
BE8_CASE="$case_dir" BE8_VARIANT="$variant" BE8_PHASE="$phase" BE8_ENDIAN="$data_order" BE8_REMOTE="$qemu_socket_path" \
    timeout 45s gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set auto-solib-add off' -ex "file $case_dir/be8.stripped" -ex "symbol-file $symbols" \
    -x "$(dirname "$0")/arm-be8-gdb.py"
qemu_socket_wait
