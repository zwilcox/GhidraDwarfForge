#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
target=$3
source "$repository/src/test/integration/qemu-socket.sh"
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
for variant in ${LOCAL_VARIANTS:?}; do
    if [[ "$variant" == compiler ]]; then input="$case_dir/local.reference"; else input="$case_dir/local.input"; fi
    remote=
    if [[ "$target" == aarch64 ]]; then
        qemu_socket_start "$case_dir/$variant.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$input"
        remote=$qemu_socket_path
    fi
    LOCAL_CASE="$case_dir" LOCAL_VARIANT="$variant" LOCAL_TARGET="$target" LOCAL_REMOTE="$remote" \
        gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' -ex 'set python print-stack full' \
        -x "$repository/src/test/integration/stack-local-effects-gdb.py" \
        > "$case_dir/$variant-gdb.log" 2>&1
    if [[ "$target" == aarch64 ]]; then qemu_socket_wait; fi
    python3 - "$case_dir" "$variant" <<'PYCODE'
from pathlib import Path
import re
import sys

case, variant = Path(sys.argv[1]), sys.argv[2]
raw = case / (variant + '-gdb.log')
lines = raw.read_text().splitlines(keepends=True)
source = None if variant == 'compiler' else (case / ('local.dbg.c' if variant == 'forge' else 'previous.dbg.c')).read_text().splitlines()
clean = []
for line in lines:
    match = re.fullmatch(r'(\d+)\t(.*WARNING:.*)\n?', line)
    if match and source is not None:
        assert source[int(match[1]) - 1] == match[2], line
    else:
        clean.append(line)
(case / (variant + '-diagnostics.log')).write_text(''.join(clean))
PYCODE
    layout_validate_gdb_diagnostics "$case_dir/$variant-diagnostics.log" "$input" "$variant" "$target" "$case_dir/compiler-gdb.log"
    grep -Fxq "stack-local-effects-gdb=$variant PASS" "$case_dir/$variant-gdb.log"
done
