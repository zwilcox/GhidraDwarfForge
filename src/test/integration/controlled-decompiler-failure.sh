#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp>" >&2
    exit 2
fi

ghidra_dir=$(realpath "$1")
consumer=$(realpath "$2")
producer=$(realpath "$3")
repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture_dir="$repository_dir/build/fixtures/x86_64"
input="$fixture_dir/semantic.exec.stripped"
reference="$fixture_dir/semantic.exec.reference"
output="$fixture_dir/semantic.exec.controlled-failure.dbg"
source="$output.c"
result_dir="$repository_dir/build/test-results/controlled-decompiler-failure"
temporary_projects=$(mktemp -d -t ghidra-dwarf-forge-failure.XXXXXXXX)

cleanup() {
    case "$temporary_projects" in
        /tmp/ghidra-dwarf-forge-failure.*) rm -rf -- "$temporary_projects" ;;
        *) echo "refusing to remove unexpected path: $temporary_projects" >&2 ;;
    esac
}
trap cleanup EXIT

symbol_address() {
    local symbol=$1
    local value
    value=$(readelf -Ws "$reference" |
        awk -v name="$symbol" '$4 == "FUNC" && $8 == name { print $2; exit }')
    if [[ -z "$value" ]]; then
        echo "missing fixture symbol $symbol" >&2
        return 1
    fi
    printf '0x%x\n' "$((16#$value))"
}

mkdir -p "$result_dir"
before=$(sha256sum "$input" | cut -d' ' -f1)
add_address=$(symbol_address recovered_add)
variadic_address=$(symbol_address recovered_variadic)
noreturn_address=$(symbol_address recovered_spin)
composite_address=$(symbol_address recovered_composite)
global_address=$(readelf -Ws "$reference" |
    awk '$8 == "fixture_sink" { print "0x" $2; exit }')
scoped_global_address=$(readelf -Ws "$reference" |
    awk '$8 == "scoped_counter" { print "0x" $2; exit }')

"$ghidra_dir/support/analyzeHeadless" \
    "$temporary_projects" ControlledDecompilerFailure -deleteProject \
    -import "$input" -analysisTimeoutPerFile 120 \
    -scriptPath "$repository_dir/src/test/integration/ghidra_scripts" \
    -postScript RenameFixtureFunction.java "$add_address" "$variadic_address" \
        "$noreturn_address" recovered_add "$global_address" "$composite_address" \
        "$scoped_global_address" \
    -postScript ControlledDecompilerFailureExport.java "$consumer" "$producer" \
        "$output" recovered_add 2>&1 | tee "$result_dir/headless.log"

test "$before" = "$(sha256sum "$input" | cut -d' ' -f1)"
grep -q 'controlled-decompiler-failure-export=PASS' "$result_dir/headless.log"
grep -Fq 'GhidraDwarfForge report: {"schemaVersion":1,"status":"PARTIAL"' \
    "$result_dir/headless.log"
grep -Fq '"functionsFailed":1' "$result_dir/headless.log"
grep -Fq '"failedFunctions":[{"name":"recovered_add"' "$result_dir/headless.log"
grep -Fq '"diagnostic":"IllegalStateException: controlled integration failure"' \
    "$result_dir/headless.log"
grep -Fq 'Decompilation unavailable for recovered_add' "$source"
grep -Fq 'IllegalStateException: controlled integration failure' "$source"
grep -Fq 'recovered_composite' "$source"

readelf --debug-dump=info --wide "$output" >"$result_dir/readelf-info.txt"
readelf --debug-dump=decodedline "$output" >"$result_dir/readelf-lines.txt"
grep -q 'DW_AT_name.*recovered_add' "$result_dir/readelf-info.txt"
if perl -0777 -ne '
    while (/(<1><[0-9a-f]+>: Abbrev Number: .*?\(DW_TAG_subprogram\).*?)(?=<1><|$)/sg) {
        my $die = $1;
        if ($die =~ /DW_AT_name[^\n]*recovered_add/) {
            exit($die =~ /DW_AT_decl_(?:file|line)|DW_AT_type|DW_AT_prototyped|DW_AT_noreturn|DW_TAG_formal_parameter|DW_TAG_variable/ ? 1 : 0);
        }
    }
    exit 2;
' "$result_dir/readelf-info.txt"; then
    :
else
    echo "failed function is missing or is not a symbol-only DIE" >&2
    exit 1
fi

llvm-dwarfdump --verify "$output" >"$result_dir/llvm.txt"
dwarfdump -ka -ks "$output" >"$result_dir/dwarfdump.txt" 2>&1
gdb -q -nx -batch \
    -ex "file $input" \
    -ex 'set auto-solib-add off' \
    -ex "symbol-file $output" \
    -ex 'info address recovered_add' \
    -ex 'info line recovered_add' \
    -ex 'info line recovered_composite' >"$result_dir/gdb.txt" 2>&1
grep -q 'Symbol "recovered_add" is a function at address' "$result_dir/gdb.txt"
grep -q 'No line number information available for address.*recovered_add' \
    "$result_dir/gdb.txt"
grep -q 'Line .*recovered_composite' "$result_dir/gdb.txt"

echo controlled-decompiler-failure=PASS
