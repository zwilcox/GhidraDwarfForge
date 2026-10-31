#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
for variant in compiler fixed; do
    TYPE_FLAGS_CASE="$case_dir" TYPE_FLAGS_VARIANT="$variant" timeout 60s gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
        -ex 'set auto-solib-add off' -ex 'set disable-randomization off' -ex 'set python print-stack full' \
        -x "$repository/src/test/integration/function-type-flags-gdb.py" > "$case_dir/$variant-gdb.log" 2>&1
    layout_validate_gdb_diagnostics "$case_dir/$variant-gdb.log" "$case_dir/flags.input" "$variant" x86_64 "$case_dir/compiler-gdb.log"
    grep -Fxq "function-type-flags-gdb=$variant PASS" "$case_dir/$variant-gdb.log"
done
