#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp>" >&2
    exit 2
fi

repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture="$repository_dir/build/fixtures/x86_64/semantic.exec.stripped"
sidecar="$repository_dir/build/fixtures/x86_64/semantic.exec.ghidra-forge.dbg"
source="$sidecar.c"
result_dir="$repository_dir/build/test-results/rebased-program-export"
mkdir -p "$result_dir"

before_input=$(sha256sum "$fixture" | cut -d' ' -f1)
FIXTURE_ROLE=exec "$repository_dir/src/test/integration/headless-symbol-export.sh" \
    "$1" "$2" "$3" x86_64
baseline_sidecar=$(sha256sum "$sidecar" | cut -d' ' -f1)
baseline_source=$(sha256sum "$source" | cut -d' ' -f1)
headless_log="$repository_dir/build/test-results/headless-symbol-export/x86_64.exec.log"
headless_info="$repository_dir/build/test-results/headless-symbol-export/x86_64.exec.readelf-info.txt"
baseline_globals=$(sed -n 's/.*global variables: \([0-9][0-9]*\).*/\1/p' \
    "$headless_log" | tail -1)
cp "$headless_log" "$result_dir/baseline-headless.log"
cp "$headless_info" "$result_dir/baseline-readelf-info.txt"
if grep -q 'ElfComment' "$result_dir/baseline-readelf-info.txt"; then
    echo "non-loaded ELF metadata leaked into baseline globals" >&2
    exit 1
fi

GHIDRA_REBASE_DELTA=0x2000000 FIXTURE_ROLE=exec \
    "$repository_dir/src/test/integration/headless-symbol-export.sh" \
    "$1" "$2" "$3" x86_64
rebased_sidecar=$(sha256sum "$sidecar" | cut -d' ' -f1)
rebased_source=$(sha256sum "$source" | cut -d' ' -f1)
after_input=$(sha256sum "$fixture" | cut -d' ' -f1)
rebased_globals=$(sed -n 's/.*global variables: \([0-9][0-9]*\).*/\1/p' \
    "$headless_log" | tail -1)
cp "$headless_log" "$result_dir/rebased-headless.log"
cp "$headless_info" "$result_dir/rebased-readelf-info.txt"

test "$before_input" = "$after_input"
test -n "$baseline_globals"
test "$baseline_globals" = "$rebased_globals"
if grep -q 'ElfComment' "$result_dir/rebased-readelf-info.txt"; then
    echo "non-loaded ELF metadata leaked into rebased globals" >&2
    exit 1
fi
if grep -Eq 'DW_AT_(low_pc|location).*(0x)?0?24[0-9a-f]{5}' \
        "$result_dir/rebased-readelf-info.txt"; then
    echo "rebased Ghidra address leaked into link-time DWARF" >&2
    exit 1
fi
GHIDRA_NAME_REBASE_DELTA=0x2000000 FIXTURE_ROLE=exec \
    "$repository_dir/src/test/integration/qemu-gdb-symbols.sh" x86_64

# Leave the standard artifact in its ordinary (non-rebased) deterministic state
# for subsequent CI consumers such as the Windows cross-host comparison.
FIXTURE_ROLE=exec "$repository_dir/src/test/integration/headless-symbol-export.sh" \
    "$1" "$2" "$3" x86_64 >/dev/null
test "$baseline_sidecar" = "$(sha256sum "$sidecar" | cut -d' ' -f1)"
test "$baseline_source" = "$(sha256sum "$source" | cut -d' ' -f1)"

{
    echo "input_sha256=$after_input"
    echo "baseline_sidecar_sha256=$baseline_sidecar"
    echo "rebased_sidecar_sha256=$rebased_sidecar"
    echo "baseline_source_sha256=$baseline_source"
    echo "rebased_source_sha256=$rebased_source"
    echo "global_variables=$rebased_globals"
    echo "ghidra_rebase_delta=0x2000000"
    echo "rebased_program_export=PASS"
} | tee "$result_dir/result.txt"
