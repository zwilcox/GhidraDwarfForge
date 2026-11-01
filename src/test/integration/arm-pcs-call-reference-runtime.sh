#!/usr/bin/env bash
# Run one compiler reference in a private QEMU process; never patch its registers.
set -euo pipefail
repository=$(cd "$(dirname "$0")/../../.." && pwd)
case_dir=$1
operation=$2
mode=$3
emulator=$4
gdb=$5
data=$6
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
qemu_socket_start "$case_dir/$operation-$mode.qemu" "$emulator" / "$case_dir/reference"
FORGE_CALL_CASE=$case_dir FORGE_CALL_MODE=$mode FORGE_CALL_OPERATION=$operation \
    FORGE_CALL_REMOTE=$qemu_socket_path timeout 30s "$gdb" --data-directory="$data" -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set auto-solib-add off' \
    -ex 'set debuginfod enabled off' -ex "file $case_dir/reference" \
    -x "$repository/src/test/integration/arm-pcs-call-reference-gdb.py" \
    >"$case_dir/$operation-$mode.stdout" 2>"$case_dir/$operation-$mode.stderr"
qemu_socket_wait
