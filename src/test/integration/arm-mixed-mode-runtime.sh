#!/usr/bin/env bash
set -euo pipefail
case_directory=$(realpath "${1:?case directory}")
variant=${2:?compiler, curated or experiment}
phase=${3:-instructions}
source_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$source_directory/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf}
case "$variant" in
    compiler) symbols="$case_directory/mixed.reference" ;;
    curated|experiment) symbols="$case_directory/$variant.dbg" ;;
    *) exit 2 ;;
esac
runtime_input="$case_directory/mixed.stripped"
if [[ -f "$case_directory/mixed.driver" ]]; then runtime_input="$case_directory/mixed.driver"; fi
qemu_socket_start "$case_directory/$variant-$phase.qemu" qemu-arm-static "$sysroot" "$runtime_input"
status=0
FORGE_MIXED_CASE="$case_directory" FORGE_MIXED_VARIANT="$variant" FORGE_MIXED_PHASE="$phase" FORGE_MIXED_REMOTE="$qemu_socket_path" \
    timeout 60s gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
    -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex "set sysroot $sysroot" -ex "file $case_directory/mixed.stripped" \
    -ex "symbol-file $symbols" -x "$source_directory/arm-mixed-mode-gdb.py" || status=$?
qemu_socket_wait
exit "$status"
