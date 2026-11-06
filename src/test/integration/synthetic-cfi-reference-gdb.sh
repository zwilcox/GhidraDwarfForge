#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 5 ]]; then
    echo "usage: $0 <x86_64|aarch64> <compiler|absent|disabled> <reference> <original> <output-prefix>" >&2
    exit 2
fi
target=$1
export FORGE_CFI_MODE=$2
reference=$(realpath "$3")
original=$(realpath "$4")
prefix=$(realpath -m "$5")
script_dir=$(realpath "$(dirname "$0")")
export FORGE_CFI_RESULT="$prefix.json"
export FORGE_CFI_REMOTE=
debugger_options=()
case "$target" in
    x86_64) debugger=gdb; export FORGE_CFI_REGISTER=r12 ;;
    aarch64)
        debugger=gdb-multiarch
        export FORGE_CFI_REGISTER=x19
        debugger_options=(-ex 'set sysroot /usr/aarch64-linux-gnu')
        ;;
    *) echo "unsupported reference target: $target" >&2; exit 2 ;;
esac
case "$FORGE_CFI_MODE" in
    compiler|disabled|probe) symbols=$reference ;;
    absent) symbols=$original ;;
    *) echo "unsupported reference mode: $FORGE_CFI_MODE" >&2; exit 2 ;;
esac
export FORGE_CFI_SYMBOLS="$symbols"
export FORGE_CFI_ORIGINAL="$original" FORGE_CFI_LOAD_HELPER="$script_dir/unwind-companion-gdb.py"
runtime=$original
load_symbols=$symbols
if [[ "${FORGE_CFI_COMPANION:-}" == 1 ]]; then load_symbols=$original; fi
inferior_args=()
if [[ "${FORGE_CFI_SHARED:-}" == 1 ]]; then
    runtime=$(realpath "${FORGE_CFI_DRIVER:?shared fixture needs a driver}")
    load_symbols=$runtime
    inferior_args=("$original")
    debugger_options+=(-ex "set solib-search-path $(dirname "$original")")
fi

source "$script_dir/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
if [[ "$target" == aarch64 ]]; then
    qemu_socket_start "$prefix.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$runtime" "${inferior_args[@]}"
    export FORGE_CFI_REMOTE="$qemu_socket_path"
fi
oracle="$script_dir/synthetic-cfi-reference-gdb.py"
if [[ "${FORGE_CFI_ALL_BOUNDARIES:-}" == 1 ]]; then
    oracle="$script_dir/compiler-cfi-boundaries-gdb.py"
fi
timeout --kill-after=5 90 "$debugger" -q -nx -batch \
    "${debugger_options[@]}" \
    -ex 'set pagination off' -ex 'set confirm off' \
    -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex 'set disable-randomization off' \
    -ex "directory \"$script_dir/../fixtures\"" \
    -ex "file \"$runtime\"" -ex "symbol-file \"$load_symbols\"" \
    -ex "set args ${inferior_args[*]}" \
    -x "$oracle" > "$prefix.log" 2>&1
if [[ "$target" == aarch64 ]]; then
    qemu_socket_wait
fi
