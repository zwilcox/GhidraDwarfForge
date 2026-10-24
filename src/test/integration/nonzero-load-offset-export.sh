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
fixture_sources="$repository_dir/src/test/fixtures"
fixture_dir="$repository_dir/build/fixtures/nonzero-load-offset"
result_root="$repository_dir/build/test-results/nonzero-load-offset-export"
mkdir -p "$fixture_dir" "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
artifact_dir="$result_dir/artifacts"
mkdir -p "$artifact_dir"
projects=$(mktemp -d /tmp/forge-load-offset-projects.XXXXXXXX)
reference="$fixture_dir/nonzero.reference"
input="$fixture_dir/nonzero.stripped"

cleanup() {
    case "$projects" in
        /tmp/forge-load-offset-projects.*) rm -rf -- "$projects" ;;
        *) echo "unexpected temporary project path: $projects" >&2 ;;
    esac
}
trap cleanup EXIT

echo "nonzero-load-offset-results=$result_dir"
SOURCE_DATE_EPOCH=1750550400 gcc -O0 -g -gdwarf-5 -fno-pie \
    -fno-stack-protector -fno-omit-frame-pointer -nostdlib -no-pie \
    "-ffile-prefix-map=$repository_dir=/ghidra-dwarf-forge" \
    -Wl,--build-id=sha1,-z,max-page-size=0x1000 \
    "-Wl,-T,$fixture_sources/nonzero_load_offset.ld" \
    "$fixture_sources/nonzero_load_offset_start.S" \
    "$fixture_sources/nonzero_load_offset.c" -o "$reference"
objcopy --strip-debug "$reference" "$input"
readelf -hW "$input" >"$result_dir/input-header.txt"
readelf -lW "$input" >"$result_dir/input-programs.txt"
readelf -SW "$input" >"$result_dir/input-sections.txt"
readelf -n "$input" >"$result_dir/input-notes.txt"
if grep -Eq '[[:space:]][.]debug_' "$result_dir/input-sections.txt"; then
    echo "runtime fixture unexpectedly contains compiler DWARF" >&2
    exit 1
fi
read -r file_offset link_base < <(awk '$1 == "LOAD" { print $2, $3; exit }' \
    "$result_dir/input-programs.txt")
test "$((file_offset))" = "$((0x1000))"
test "$((link_base))" = "$((0x401000))"
"$input"
input_hash=$(sha256sum "$input" | cut -d' ' -f1)
function_address=$(readelf -Ws "$reference" |
    awk '$8 == "nonzero_add" { print "0x" $2; exit }')
global_address=$(readelf -Ws "$reference" |
    awk '$8 == "nonzero_sink" { print "0x" $2; exit }')
test -n "$function_address"
test -n "$global_address"
function_address=$(printf '0x%x' "$((function_address))")
global_address=$(printf '0x%x' "$((global_address))")

run_case() {
    local name=$1 delta=$2
    local case_dir="$result_dir/$name"
    mkdir -p "$case_dir"
    local output="$artifact_dir/nonzero.dbg"
    local log="$case_dir/headless.txt"
    local prepare=()
    if ((delta != 0)); then
        prepare=(-postScript RebaseFixtureProgram.java "$(printf '0x%x' "$delta")")
    fi
    "$ghidra_dir/support/analyzeHeadless" "$projects" "NonzeroLoadOffset_$name" \
        -deleteProject -import "$input" -analysisTimeoutPerFile 120 \
        -scriptPath "$repository_dir/src/test/integration/ghidra_scripts" \
        "${prepare[@]}" -postScript PrepareNonzeroLoadOffset.java \
        "$(printf '0x%x' "$((function_address + delta))")" \
        "$(printf '0x%x' "$((global_address + delta))")" \
        -postScript GhidraDwarfForge.java "--libdwarf=$consumer" \
        "--libdwarfp=$producer" "--output=$output" >"$log" 2>&1
    grep -Fq 'GhidraDwarfForge symbol export PASS' "$log"
    grep -Fq "Ghidra-to-ELF address delta: $(printf '0x%x' "$delta")" "$log"
    test "$input_hash" = "$(sha256sum "$input" | cut -d' ' -f1)"
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
    if [[ -s "$warnings" ]]; then
        cat "$warnings" >&2
        exit 1
    fi
    llvm-dwarfdump --verify "$output" >"$case_dir/llvm.txt" 2>&1
    python3 "$repository_dir/src/test/integration/check-dwarfdump.py" \
        "$output" "$case_dir/dwarfdump.txt" --original "$input"
    grep -Eq "DW_AT_low_pc[[:space:]]*:[[:space:]]*$function_address$" \
        "$case_dir/info.txt"
    grep -Fq 'GhidraDwarfForge' "$case_dir/info.txt"
    grep -Fq 'nonzero.dbg.c' "$case_dir/decodedline.txt"
    local original_id output_id
    original_id=$(awk '/Build ID:/ { print $3 }' "$result_dir/input-notes.txt")
    output_id=$(awk '/Build ID:/ { print $3 }' "$case_dir/notes.txt")
    test -n "$original_id"
    test "$original_id" = "$output_id"

    timeout 30s gdb-multiarch -q -nx -batch \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex "directory $artifact_dir" -ex "file $input" -ex "symbol-file \"$output\"" \
        -ex 'info functions nonzero_add' -ex 'list nonzero_add' \
        -ex 'ptype nonzero_add' -ex 'ptype nonzero_sink' \
        -ex 'printf "function_address=%#lx\n", (unsigned long)&nonzero_add' \
        -ex 'printf "global_address=%#lx\n", (unsigned long)&nonzero_sink' \
        -ex 'break nonzero_add' -ex run -ex 'info args' \
        -ex 'printf "sink_before=%d\n", nonzero_sink' \
        -ex next -ex step -ex 'printf "sink_after=%d\n", nonzero_sink' \
        -ex continue >"$case_dir/gdb.txt" 2>&1
    grep -Fxq "function_address=$function_address" "$case_dir/gdb.txt"
    grep -Fxq "global_address=$global_address" "$case_dir/gdb.txt"
    grep -Fq 'type = int (int, int)' "$case_dir/gdb.txt"
    grep -Fq 'Breakpoint 1,' "$case_dir/gdb.txt"
    grep -Eq 'nonzero[.]dbg[.]c:[0-9]+' "$case_dir/gdb.txt"
    grep -Fxq 'left = 19' "$case_dir/gdb.txt"
    grep -Fxq 'right = 23' "$case_dir/gdb.txt"
    grep -Fxq 'sink_before=-1' "$case_dir/gdb.txt"
    grep -Fxq 'sink_after=42' "$case_dir/gdb.txt"
    grep -Fq 'exited normally' "$case_dir/gdb.txt"
    if grep -Eiq 'warning:|error:|cannot insert|cannot access|no line number|malformed|corrupt' \
            "$case_dir/gdb.txt"; then
        cat "$case_dir/gdb.txt" >&2
        exit 1
    fi
    cp -- "$output" "$case_dir/nonzero.dbg"
    cp -- "$output.c" "$case_dir/nonzero.dbg.c"
    {
        echo "input_sha256=$input_hash"
        echo "load_offset=$file_offset"
        echo "link_base=$link_base"
        echo "rebase_delta=$delta"
        echo "function_address=$function_address"
        echo "global_address=$global_address"
        echo "nonzero_load_offset_case=$name PASS"
    } | tee "$case_dir/result.txt"
}

run_case baseline 0
run_case rebased "$((0x2000000))"
run_case repeat 0
cmp "$result_dir/baseline/nonzero.dbg" "$result_dir/repeat/nonzero.dbg"
cmp "$result_dir/baseline/nonzero.dbg.c" "$result_dir/repeat/nonzero.dbg.c"
test "$input_hash" = "$(sha256sum "$input" | cut -d' ' -f1)"
echo "nonzero-load-offset-export=PASS"
