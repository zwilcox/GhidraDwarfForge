#!/usr/bin/env bash
# Natural x86-64 SysV aggregate return, curated signature, saved program and GDB.
set -euo pipefail
if [[ $# -ne 1 ]]; then
    echo "usage: $0 <ghidra-dir>" >&2
    exit 2
fi
export LC_ALL=C
repository=$(realpath "$(dirname "$0")/../../..")
source_dir="$repository/src/test/integration"
ghidra=$(realpath "$1")
module="$ghidra/Ghidra/Extensions/GhidraDwarfForge"
results="$repository/build/test-results/formal-function-return"
mkdir -p "$results"
case_dir=$(mktemp -d "$results/x86_64.XXXXXXXX")
mkdir "$case_dir/project" "$case_dir/empty-debug"
exec 9>"$case_dir/commands.log"
BASH_XTRACEFD=9
set -x
for tool in gcc objcopy objdump readelf llvm-dwarfdump gdb-multiarch; do
    "$tool" --version >"$case_dir/$tool.version" 2>&1
done
# Same ordinary C and compiler flags as the retained failing probe; no injected call.
gcc -O1 -g3 -gdwarf-5 -fno-inline -fno-ipa-sra -fno-omit-frame-pointer -fno-pie -no-pie \
    -Wl,--build-id=none "$repository/src/test/fixtures/formal-function-return.c" -o "$case_dir/return.reference" \
    >"$case_dir/compile.stdout" 2>"$case_dir/compile.stderr"
test ! -s "$case_dir/compile.stderr"
objcopy --strip-all "$case_dir/return.reference" "$case_dir/return.stripped"
for view in header sections notes symbols info; do
    case "$view" in header) option=-h ;; sections) option=-SW ;; notes) option=-n ;; symbols) option=-sW ;; *) option=--debug-dump=info ;; esac
    readelf "$option" "$case_dir/return.reference" >"$case_dir/compiler-$view.stdout" 2>"$case_dir/compiler-$view.stderr"
    test ! -s "$case_dir/compiler-$view.stderr"
done
objdump -drwC "$case_dir/return.reference" >"$case_dir/compiler-disassembly.stdout" 2>"$case_dir/compiler-disassembly.stderr"
test ! -s "$case_dir/compiler-disassembly.stderr"
python3 "$source_dir/formal-function-return-check.py" labels "$case_dir" "$repository" "$module"
timeout 30s "$case_dir/return.reference" >"$case_dir/plain.stdout" 2>"$case_dir/plain.stderr"
test ! -s "$case_dir/plain.stdout"
test ! -s "$case_dir/plain.stderr"
for phase in natural curate reopen; do
    mode=(-process return.stripped -noanalysis)
    if [[ "$phase" == natural ]]; then mode=(-import "$case_dir/return.stripped" -analysisTimeoutPerFile 120); fi
    if [[ "$phase" == reopen ]]; then mode+=(-readOnly); fi
    export_script=()
    if [[ "$phase" != natural ]]; then export_script=(-postScript GhidraDwarfForge.java --packaged-natives "--output=$case_dir/return.dbg"); fi
    timeout 240s "$ghidra/support/analyzeHeadless" "$case_dir/project" FormalReturn "${mode[@]}" \
        -scriptPath "$source_dir/ghidra_scripts" \
        -postScript PrepareReturnTriple.java "$phase" "$case_dir/labels.txt" "$case_dir/$phase.json" \
        "${export_script[@]}" >"$case_dir/export-$phase.log" 2>&1
    test -f "$case_dir/$phase.json"
    if [[ "$phase" != natural ]]; then grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$phase.log"; fi
    if [[ "$phase" == curate ]]; then
        cp "$case_dir/return.dbg" "$case_dir/first.return.dbg"
        cp "$case_dir/return.dbg.c" "$case_dir/first.return.dbg.c"
    fi
done
cmp "$case_dir/return.dbg" "$case_dir/first.return.dbg"
cmp "$case_dir/return.dbg.c" "$case_dir/first.return.dbg.c"
for view in header sections notes info abbrev aranges decodedline loc Ranges; do
    case "$view" in header) option=-h ;; sections) option=-SW ;; notes) option=-n ;; *) option="--debug-dump=$view" ;; esac
    readelf "$option" "$case_dir/return.dbg" >"$case_dir/forge-$view.stdout" 2>"$case_dir/forge-$view.stderr"
    test ! -s "$case_dir/forge-$view.stderr"
done
llvm-dwarfdump --verify "$case_dir/return.dbg" >"$case_dir/llvm.stdout" 2>"$case_dir/llvm.stderr"
test ! -s "$case_dir/llvm.stderr"
grep -Fq 'No errors.' "$case_dir/llvm.stdout"
python3 "$source_dir/check-dwarfdump.py" "$case_dir/return.dbg" "$case_dir/strict.log" --original "$case_dir/return.stripped"
python3 "$source_dir/formal-function-return-check.py" observations "$case_dir" "$repository" "$module"
for variant in compiler forge; do
    input="$case_dir/return.reference"; symbols="$input"
    if [[ "$variant" == forge ]]; then input="$case_dir/return.stripped"; symbols="$case_dir/return.dbg"; fi
    RETURN_CASE="$case_dir" RETURN_VARIANT="$variant" RETURN_SOURCE="$repository/src/test/fixtures/formal-function-return.c" \
        timeout 90s gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' -ex 'set disable-randomization off' \
        -ex "set debug-file-directory $case_dir/empty-debug" -ex "file $input" -ex "symbol-file $symbols" \
        -x "$source_dir/formal-function-return-gdb.py" >"$case_dir/$variant-gdb.stdout" 2>"$case_dir/$variant-gdb.stderr"
    grep -Fq "return-triple-gdb=$variant PASS" "$case_dir/$variant-gdb.stdout"
    test ! -s "$case_dir/$variant-gdb.stderr"
done
python3 "$source_dir/formal-function-return-check.py" finish "$case_dir" "$repository" "$module"
set +x
unset BASH_XTRACEFD
exec 9>&-
