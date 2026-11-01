#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo 'usage: mips-wide-arguments-gdb.sh <case-directory> <compiler|forge> [instructions|source|calls]' >&2
    exit 64
fi
script_directory=$(cd "$(dirname "$0")" && pwd)
case_directory=$(realpath "$1")
mode=$2
[[ "$mode" == compiler || "$mode" == forge ]] || exit 64
phase=${3:-instructions}
[[ "$phase" == instructions || "$phase" == source || "$phase" == calls ]] || exit 64
result_prefix=$mode
if [[ "$phase" != instructions ]]; then result_prefix="$mode-$phase"; fi
source "$script_directory/qemu-socket.sh"
source "$script_directory/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
mapfile -t configuration < <(python3 - "$case_directory/metadata.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
for key in ('emulator', 'sysroot', 'runtime'):
    print(data[key])
PY
)
runtime="$case_directory/${configuration[2]}"
qemu_socket_start "$case_directory/$result_prefix.qemu" "${configuration[0]}" "${configuration[1]}" "$runtime"
FORGE_MIPS_WIDE_MODE="$mode" FORGE_MIPS_WIDE_CASE="$case_directory" \
    FORGE_MIPS_WIDE_REMOTE="$qemu_socket_path" FORGE_MIPS_WIDE_PHASE="$phase" \
    timeout 90s gdb-multiarch -q -nx -batch -ex 'set python print-stack full' \
        -x "$script_directory/mips-wide-arguments-gdb.py" 2>&1 | tee "$case_directory/$result_prefix-runtime-gdb.log"
qemu_socket_wait
layout_validate_gdb_diagnostics "$case_directory/$result_prefix-runtime-gdb.log" "$runtime" \
    "$mode" mips64 "$case_directory/compiler-runtime-gdb.log"
grep -q "MIPS_WIDE_ARGUMENTS_${mode^^}_PASS" "$case_directory/$result_prefix-runtime-gdb.log"
