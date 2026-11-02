#!/usr/bin/env bash
set -euo pipefail
repository=$(cd "$(dirname "$0")/../../.." && pwd)
case_dir=$1
variant=$2
emulator=$3
gdb=$4
data=$5
script=${6:-$repository/src/test/integration/arm-pcs-profile-gdb.py}
symbols="$case_dir/calls.dbg"
if [[ "$variant" == compiler ]]; then symbols="$case_dir/calls.reference"; fi
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
qemu_socket_start "$case_dir/$variant.qemu" "$emulator" / "$case_dir/calls.input"
FORGE_PCS_CASE=$case_dir FORGE_PCS_VARIANT=$variant FORGE_PCS_REMOTE=$qemu_socket_path \
    timeout 60s "$gdb" --data-directory="$data" -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set auto-solib-add off' \
    -ex 'set debuginfod enabled off' -ex "file $case_dir/calls.input" -ex "symbol-file $symbols" \
    -x "$script" \
    >"$case_dir/$variant.stdout" 2>"$case_dir/$variant.stderr"
qemu_socket_wait
