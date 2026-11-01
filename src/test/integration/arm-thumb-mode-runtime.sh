#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 3 ]]; then
    echo 'usage: arm-thumb-mode-runtime.sh <case-dir> <compiler|forge> <calls|from-arm>' >&2
    exit 2
fi
repository=$(realpath "$(dirname "$0")/../../..")
case_dir=$(realpath "$1")
variant=$2
phase=$3
sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf}
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
input="$case_dir/thumb.stripped"
case "$variant" in
    compiler) symbols="$case_dir/thumb.reference" ;;
    forge) symbols="$case_dir/thumb.dbg" ;;
    *) exit 2 ;;
esac
qemu_socket_start "$case_dir/$variant-$phase.qemu" qemu-arm-static "$sysroot" "$input"
FORGE_THUMB_CASE="$case_dir" FORGE_THUMB_VARIANT="$variant" FORGE_THUMB_PHASE="$phase" \
FORGE_THUMB_REMOTE="$qemu_socket_path" timeout 60s gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex 'set auto-solib-add off' -ex "set debug-file-directory $case_dir/empty-debug" \
    -ex "set sysroot $sysroot" -ex "file $input" -ex "symbol-file $symbols" \
    -x "$repository/src/test/integration/arm-thumb-mode-gdb.py" \
    >"$case_dir/$variant-$phase.stdout" 2>"$case_dir/$variant-$phase.stderr"
grep -Fq "arm-thumb-mode-gdb=$variant/$phase PASS" "$case_dir/$variant-$phase.stdout"
qemu_socket_wait
