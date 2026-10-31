#!/usr/bin/env bash
set -euo pipefail
repository=$1
case_dir=$2
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
for variant in compiler fixed ${CUSTOM_CALL_PREVIOUS:-}; do
    if [[ "$variant" == compiler ]]; then input="$case_dir/control.reference"; else input="$case_dir/control.input"; fi
    CUSTOM_CALL_VARIANT="$variant" gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' -ex 'set python print-stack full' \
        -x "$repository/src/test/integration/custom-call-storage-gdb.py" \
        > "$case_dir/$variant-gdb.log" 2>&1
    # DW_CC_nocall also honestly prevents GDB's unclassified return-value display.
    # Retain the original log and permit exactly this one observed warning.
    python3 - "$case_dir" "$variant" <<'PYTHON'
from pathlib import Path
import sys
case, variant = Path(sys.argv[1]), sys.argv[2]
text = (case / (variant + '-gdb.log')).read_text()
for name in ('microsoft_function', 'custom_return'):
    warning = "warning: Function '" + name + "' does not follow the target calling convention, cannot determine its returned value.\n"
    assert text.count(warning) == (1 if variant == 'fixed' else 0)
    text = text.replace(warning, '')
(case / (variant + '-gdb-diagnostics.log')).write_text(text)
PYTHON
    layout_validate_gdb_diagnostics "$case_dir/$variant-gdb-diagnostics.log" "$input" "$variant" x86_64 "$case_dir/compiler-gdb.log"
    grep -Fxq "custom-call-storage-gdb=$variant PASS" "$case_dir/$variant-gdb.log"
done
