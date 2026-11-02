#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
target=$3
source "$repository/src/test/integration/qemu-socket.sh"
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
case "$target" in
    mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
    mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
    *) echo 'MIPS target required' >&2; exit 64 ;;
esac
mapfile -t wide_configuration < <(python3 - "$case_dir/metadata.json" <<'PYTHON'
import json, sys
data = json.load(open(sys.argv[1]))
if data['profile'] in ('n32', 'n64'):
    print(data['emulator'])
    print(data['sysroot'])
PYTHON
)
if [[ ${#wide_configuration[@]} -gt 0 ]]; then
    emulator=${wide_configuration[0]}
    sysroot=${wide_configuration[1]}
fi
for variant in compiler fixed ${MIPS_CALL_PREVIOUS:-}; do
    input="$case_dir/call.input"
    symbols="$case_dir/$variant.dbg"
    if [[ "$variant" == compiler ]]; then symbols="$case_dir/call.reference"; fi
    symbol_arguments=(-ex "symbol-file $symbols")
    if [[ ${#wide_configuration[@]} -gt 0 ]]; then symbol_arguments=(); fi
    qemu_socket_start "$case_dir/$variant-qemu" "$emulator" "$sysroot" "$input"
    MIPS_CALL_CASE="$case_dir" MIPS_CALL_VARIANT="$variant" timeout 60s gdb-multiarch -q -nx -batch \
        -ex 'set debuginfod enabled off' -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set auto-solib-add off' -ex 'set python print-stack full' \
        -ex "file $input" "${symbol_arguments[@]}" -ex "set sysroot $sysroot" \
        -ex "target remote $qemu_socket_path" -x "$repository/src/test/integration/mips-floating-call-gdb.py" \
        > "$case_dir/$variant-gdb.log" 2>&1
    qemu_socket_wait
    layout_validate_gdb_diagnostics "$case_dir/$variant-gdb.log" "$input" "$variant" "$target" "$case_dir/compiler-gdb.log"
    grep -Fxq "mips-floating-call-gdb=$variant PASS" "$case_dir/$variant-gdb.log"
done
