#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp>" >&2
    exit 2
fi

repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture_dir="$repository_dir/build/fixtures/x86_64"
reference="$fixture_dir/semantic.exec.reference"
runtime="$fixture_dir/semantic.partial.stripped"
output="$fixture_dir/semantic.partial.ghidra-forge.dbg"
source="$output.c"
result_root="$repository_dir/build/test-results/existing-debug-export"
headless_results="$repository_dir/build/test-results/headless-symbol-export"
gdb_results="$repository_dir/build/test-results/qemu-gdb-symbols"
active_case=""
stage=preparation

for tool in objcopy gdb-add-index readelf llvm-dwarfdump dwarfdump gdb-multiarch; do
    command -v "$tool" >/dev/null
done
test -f "$reference"
test -f "$runtime"
# The partial role retains ELF symbol names and omits exec-only checks for
# automatically named FUN_* functions. Its reference has identical code/data.
cmp "$reference" "$fixture_dir/semantic.partial.reference"
reference_hash=$(sha256sum "$reference" | cut -d' ' -f1)
runtime_hash=$(sha256sum "$runtime" | cut -d' ' -f1)
mkdir -p "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
echo "existing-debug-results=$result_dir"

section_rows() {
    readelf --wide --sections "$1" | awk '
        /^[[:space:]]*\[[[:space:]]*[0-9]+\]/ {
            sub(/^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]*/, "")
            print
        }'
}

section_names() {
    section_rows "$1" | awk '{ print $1 }'
}

archive_case() {
    if [[ -z "$active_case" ]]; then
        return
    fi
    local file
    echo "stage=$stage" >"$active_case/archive-stage.txt"
    for file in "$headless_results"/x86_64.partial.*; do
        if [[ -f "$file" && -f "$active_case/export-started" &&
                "$file" -nt "$active_case/export-started" ]]; then
            cp -- "$file" "$active_case/"
        fi
    done
    if [[ -f "$active_case/gdb-started" &&
            "$gdb_results/x86_64.partial.txt" -nt "$active_case/gdb-started" ]]; then
        cp -- "$gdb_results/x86_64.partial.txt" "$active_case/gdb.txt"
    fi
    if [[ -f "$active_case/export-started" &&
            "$output" -nt "$active_case/export-started" ]]; then
        cp -- "$output" "$active_case/semantic.partial.ghidra-forge.dbg"
    fi
    if [[ -f "$active_case/export-started" &&
            "$source" -nt "$active_case/export-started" ]]; then
        cp -- "$source" "$active_case/semantic.partial.ghidra-forge.dbg.c"
    fi
}
trap archive_case EXIT

section_names "$runtime" >"$result_dir/runtime-sections.txt"
if grep -Eq '^[.](debug_|zdebug_|gdb_index$|gnu_debug)' \
        "$result_dir/runtime-sections.txt"; then
    echo "runtime fixture contains debug data that could mask exporter failures" >&2
    exit 1
fi

for variant in plain zlib zlib-gnu indexed; do
    active_case="$result_dir/$variant"
    stage=preparation
    mkdir -p "$active_case"
    suffix="existing-$variant"
    input="$fixture_dir/semantic.partial.$suffix"
    cp -- "$reference" "$input"
    case "$variant" in
        zlib|zlib-gnu)
            objcopy --compress-debug-sections="$variant" "$input"
            ;;
        indexed)
            gdb-add-index "$input" >"$active_case/index-build.txt" 2>&1
            ;;
    esac
    before=$(sha256sum "$input" | cut -d' ' -f1)
    cp -- "$input" "$active_case/input.elf"
    section_rows "$input" >"$active_case/input-sections.txt"
    section_names "$input" >"$active_case/input-section-names.txt"
    case "$variant" in
        plain)
            grep -Fxq '.debug_info' "$active_case/input-section-names.txt"
            ;;
        zlib)
            awk '$1 == ".debug_info" && $7 ~ /C/ { found = 1 }
                END { exit !found }' "$active_case/input-sections.txt"
            ;;
        zlib-gnu)
            grep -Fxq '.zdebug_info' "$active_case/input-section-names.txt"
            ;;
        indexed)
            grep -Fxq '.gdb_index' "$active_case/input-section-names.txt"
            ;;
    esac

    stage=headless-export
    touch "$active_case/export-started"
    FIXTURE_ROLE=partial FIXTURE_INPUT_SUFFIX="$suffix" \
        "$repository_dir/src/test/integration/headless-symbol-export.sh" \
        "$1" "$2" "$3" x86_64 >"$active_case/headless-console.txt" 2>&1
    stage=section-policy
    test "$before" = "$(sha256sum "$input" | cut -d' ' -f1)"
    section_names "$output" >"$active_case/output-section-names.txt"
    if grep -Eq '^[.](zdebug_|gdb_index$|gnu_debug)' \
            "$active_case/output-section-names.txt"; then
        echo "inherited debug metadata is still active for $variant" >&2
        exit 1
    fi
    while IFS= read -r section; do
        case "$section" in
            .debug_info|.debug_abbrev|.debug_str|.debug_line|.debug_rnglists|.debug_loclists|.debug_aranges)
                ;;
            .debug_*)
                echo "unexpected active debug section for $variant: $section" >&2
                exit 1
                ;;
        esac
    done <"$active_case/output-section-names.txt"
    test "$(grep -Fxc '.debug_info' "$active_case/output-section-names.txt")" = 1
    test "$(grep -Fxc '.debug_line' "$active_case/output-section-names.txt")" = 1
    test "$(grep -Fxc '.debug_aranges' "$active_case/output-section-names.txt")" = 1
    # The headless harness independently checks this new table against Forge's
    # actual DIE coverage, including for compressed and indexed compiler inputs.
    info="$headless_results/x86_64.partial.readelf-info.txt"
    test "$(grep -c 'DW_TAG_compile_unit' "$info")" = 1
    grep -q 'DW_AT_producer.*GhidraDwarfForge' "$info"
    grep -q 'DW_AT_name.*semantic.partial.ghidra-forge.dbg.c' "$info"
    case "$variant" in
        zlib-gnu)
            grep -Fxq '.forge.stale.zdebug_info' "$active_case/output-section-names.txt"
            ;;
        indexed)
            grep -Fxq '.forge.stale.gdb_index' "$active_case/output-section-names.txt"
            ;;
    esac

    stage=gdb
    touch "$active_case/gdb-started"
    FIXTURE_ROLE=partial "$repository_dir/src/test/integration/qemu-gdb-symbols.sh" \
        x86_64 >"$active_case/gdb-console.txt" 2>&1
    if grep -Eiq 'warning:|error:|malformed|corrupt|could not find' \
            "$gdb_results/x86_64.partial.txt"; then
        echo "unexpected GDB diagnostic for $variant" >&2
        exit 1
    fi
    test "$reference_hash" = "$(sha256sum "$reference" | cut -d' ' -f1)"
    test "$runtime_hash" = "$(sha256sum "$runtime" | cut -d' ' -f1)"
    {
        echo "variant=$variant"
        echo "input_sha256=$before"
        echo "reference_sha256=$reference_hash"
        echo "runtime_sha256=$runtime_hash"
        echo "sidecar_sha256=$(sha256sum "$output" | cut -d' ' -f1)"
        echo "source_sha256=$(sha256sum "$source" | cut -d' ' -f1)"
        echo "existing_debug_export=PASS"
    } | tee "$active_case/result.txt"
    stage=complete
    archive_case
    active_case=""
done

echo "existing-debug-export=PASS"
