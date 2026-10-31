#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp>" >&2
    exit 2
fi
ghidra_dir=$(realpath "$1")
consumer=$(realpath "$2")
producer=$(realpath "$3")
repository_dir=$(realpath "$(dirname "$0")/../../..")
sources="$repository_dir/src/test/fixtures"
result_kind=function-entry-export
alias_args=()
if [[ "${FORGE_ENTRY_ALIASES:-0}" == 1 ]]; then
    result_kind=function-entry-alias-export
    alias_args=(--aliases)
fi
result_root="$repository_dir/build/test-results/$result_kind"
mkdir -p "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
projects=$(mktemp -d /tmp/forge-function-entry.XXXXXXXX)
trap 'rm -rf -- "$projects"' EXIT
echo "function-entry-results=$result_dir"
module_jar="$ghidra_dir/Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar"
sha256sum "$module_jar" "$sources/function_entry_ranges.c" "$sources/function_entry_ranges.S" \
    "$repository_dir/src/test/integration/function-entry-export.sh" \
    "$repository_dir/src/test/integration/function-entry-gdb.py" \
    "$repository_dir/src/test/integration/ghidra_scripts/PrepareFunctionEntryRanges.java" \
    "$repository_dir/src/test/integration/function-entry-alias-check.py" > "$result_dir/protected.sha256"

run_case() {
    local role=$1 name=$2 delta=$3
    local input="$result_dir/$role/entry.stripped"
    local labels="$result_dir/$role/labels.txt"
    local case_dir="$result_dir/$role/$name"
    local output="$result_dir/$role/artifacts/entry.dbg"
    mkdir -p "$case_dir" "$(dirname "$output")"
    local rebase=()
    if ((delta != 0)); then
        rebase=(-postScript RebaseFixtureProgram.java "$delta")
    fi
    local addresses=()
    mapfile -t addresses < <(awk '{ print $2 }' "$labels")
    local before
    before=$(sha256sum "$input" | cut -d' ' -f1)
    "$ghidra_dir/support/analyzeHeadless" "$projects" "Entry_${role}_${name}" \
        -deleteProject -import "$input" -analysisTimeoutPerFile 120 \
        -scriptPath "$repository_dir/src/test/integration/ghidra_scripts" \
        "${rebase[@]}" -postScript PrepareFunctionEntryRanges.java "${addresses[@]}" "${alias_args[@]}" \
        -postScript GhidraDwarfForge.java "--libdwarf=$consumer" \
        "--libdwarfp=$producer" "--output=$output" >"$case_dir/headless.txt" 2>&1
    grep -Fq 'function-entry-preparation=PASS' "$case_dir/headless.txt"
    python3 - "$case_dir/headless.txt" "$module_jar" <<'PYORIGIN'
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit
log, jar = map(Path, sys.argv[1:])
origin, = [line.split('function-entry-exporter-origin=', 1)[1].split()[0]
    for line in log.read_text().splitlines() if 'function-entry-exporter-origin=' in line]
assert Path(unquote(urlsplit(origin).path)).resolve() == jar.resolve()
PYORIGIN
    grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/headless.txt"
    if ((delta != 0)); then
        grep -E "Rebased fixture image from .* by $delta " "$case_dir/headless.txt"
    fi
    test "$before" = "$(sha256sum "$input" | cut -d' ' -f1)"
    test -s "$output.c"
    local warnings="$case_dir/readelf.stderr"
    : >"$warnings"
    readelf -hW "$output" >"$case_dir/header.txt" 2>>"$warnings"
    readelf -SW "$output" >"$case_dir/sections.txt" 2>>"$warnings"
    readelf -n "$output" >"$case_dir/notes.txt" 2>>"$warnings"
    for section in info abbrev aranges decodedline Ranges loc; do
        readelf --debug-dump="$section" "$output" \
            >"$case_dir/$section.txt" 2>>"$warnings"
    done
    test ! -s "$warnings"
    python3 "$repository_dir/src/test/integration/check-code-address-index.py" \
        "$output" --negative-controls > "$case_dir/address-index.json"
    llvm-dwarfdump --verify "$output" >"$case_dir/llvm.txt" 2>&1
    python3 "$repository_dir/src/test/integration/check-dwarfdump.py" \
        "$output" "$case_dir/dwarfdump.txt" --original "$input"
    local symbol address
    for symbol in below_entry middle_entry; do
        address=$(awk -v name="$symbol" '$1 == name { print $2 }' "$labels")
        grep -Eq "DW_AT_entry_pc[[:space:]]*:[[:space:]]*$address$" "$case_dir/info.txt"
    done
    diff <(readelf -n "$input" | awk '/Build ID:/ {print $3}') \
        <(awk '/Build ID:/ {print $3}' "$case_dir/notes.txt")
    if [[ "${FORGE_ENTRY_ALIASES:-0}" == 1 ]]; then
        grep -Fq 'function-entry-alias-preparation=PASS' "$case_dir/headless.txt"
        python3 "$repository_dir/src/test/integration/function-entry-alias-check.py" \
            "$input" "$output" "$labels" > "$case_dir/alias-symbols.json"
    fi
    FORGE_ENTRY_LABELS="$labels" FORGE_ENTRY_ALIASES="${FORGE_ENTRY_ALIASES:-0}" timeout 30s gdb-multiarch -q -nx -batch \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex "file \"$input\"" -ex "symbol-file \"$output\"" \
        -x "$repository_dir/src/test/integration/function-entry-gdb.py" \
        >"$case_dir/gdb.txt" 2>&1
    grep -Fxq 'static-entry-ranges-and-gap=PASS' "$case_dir/gdb.txt"
    grep -Fxq 'true-entry-breakpoints-backward-bodies-values-stepping=PASS' "$case_dir/gdb.txt"
    if grep -Eiq 'warning:|error:|cannot access|no line number|malformed|corrupt' \
            "$case_dir/gdb.txt"; then
        cat "$case_dir/gdb.txt" >&2
        return 1
    fi
    cp -- "$output" "$case_dir/entry.dbg"
    cp -- "$output.c" "$case_dir/entry.dbg.c"
    printf 'input_sha256=%s\nrebase_delta=%s\nfunction_entry_case=%s/%s PASS\n' \
        "$before" "$delta" "$role" "$name" | tee "$case_dir/result.txt"
}

for role in exec pie; do
    mkdir -p "$result_dir/$role"
    reference="$result_dir/$role/entry.reference"
    input="$result_dir/$role/entry.stripped"
    flags=(-fno-pie -no-pie)
    if [[ "$role" == pie ]]; then
        flags=(-fPIE -pie)
    fi
    SOURCE_DATE_EPOCH=1750550400 gcc -O0 -g -gdwarf-5 "${flags[@]}" \
        "-ffile-prefix-map=$repository_dir=/ghidra-dwarf-forge" -Wl,--build-id=sha1 \
        "$sources/function_entry_ranges.c" "$sources/function_entry_ranges.S" \
        -o "$reference"
    objcopy --strip-all "$reference" "$input"
    "$input"
    readelf -hW "$input" >"$result_dir/$role/input-header.txt"
    readelf -SW "$input" >"$result_dir/$role/input-sections.txt"
    readelf -Ws "$reference" >"$result_dir/$role/reference-symbols.txt"
    if grep -Eq '[[:space:]][.](debug_|symtab)' "$result_dir/$role/input-sections.txt"; then
        echo 'runtime input retains compiler debug information or static symbols' >&2
        exit 1
    fi
    : >"$result_dir/$role/labels.txt"
    for label in below_start below_end below_entry below_entry_end \
            middle_start middle_entry middle_end below_sink middle_sink; do
        address=$(awk -v name="$label" '$8 == name {print "0x" $2}' \
            "$result_dir/$role/reference-symbols.txt")
        test -n "$address"
        printf '%s 0x%x\n' "$label" "$((address))" >>"$result_dir/$role/labels.txt"
    done
    run_case "$role" baseline 0
    run_case "$role" rebased "$((0x2000000))"
    run_case "$role" repeat 0
    cmp "$result_dir/$role/baseline/entry.dbg" "$result_dir/$role/repeat/entry.dbg"
    cmp "$result_dir/$role/baseline/entry.dbg.c" "$result_dir/$role/repeat/entry.dbg.c"
done
sha256sum --check "$result_dir/protected.sha256" > "$result_dir/protected-check.log"
echo "$result_kind=PASS"
