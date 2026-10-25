#!/usr/bin/env bash
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
results="$repository/build/test-results/external-function-declarations"
mkdir -p "$results"
case_dir=$(mktemp -d "$results/x86_64.XXXXXXXX")
mkdir "$case_dir/project" "$case_dir/empty-debug"
exec 9>"$case_dir/commands.log"
BASH_XTRACEFD=9
set -x
for tool in gcc objcopy objdump readelf llvm-dwarfdump gdb-multiarch; do
    "$tool" --version >"$case_dir/$tool.version" 2>&1
done
gcc -O0 -fPIC -shared -DFORGE_DECL_LIBRARY "$repository/src/test/fixtures/external-function-declarations.c" \
    -o "$case_dir/libexternal.so" >"$case_dir/library.stdout" 2>"$case_dir/library.stderr"
gcc -O0 -g3 -gdwarf-5 -fno-pie -no-pie "$repository/src/test/fixtures/external-function-declarations.c" \
    -L"$case_dir" -lexternal -Wl,-rpath,"$case_dir" -Wl,--build-id=none -o "$case_dir/decl.reference" \
    >"$case_dir/compile.stdout" 2>"$case_dir/compile.stderr"
test ! -s "$case_dir/library.stderr"
test ! -s "$case_dir/compile.stderr"
objcopy --strip-all "$case_dir/decl.reference" "$case_dir/decl.stripped"
readelf --debug-dump=info "$case_dir/decl.reference" >"$case_dir/compiler-info.stdout" 2>"$case_dir/compiler-info.stderr"
objdump -drwC "$case_dir/decl.reference" >"$case_dir/compiler-disassembly.stdout" 2>"$case_dir/compiler-disassembly.stderr"
test ! -s "$case_dir/compiler-info.stderr"
test ! -s "$case_dir/compiler-disassembly.stderr"
python3 "$source_dir/external-function-declarations-check.py" labels "$case_dir" "$repository" "$module"
read -r main_address global_address < "$case_dir/labels.txt"
timeout 30s "$case_dir/decl.reference" >"$case_dir/plain.stdout" 2>"$case_dir/plain.stderr"
test ! -s "$case_dir/plain.stdout"
test ! -s "$case_dir/plain.stderr"
for phase in curate reopen; do
    mode=(-import "$case_dir/decl.stripped" -analysisTimeoutPerFile 120)
    if [[ "$phase" == reopen ]]; then mode=(-process decl.stripped -noanalysis -readOnly); fi
    timeout 240s "$ghidra/support/analyzeHeadless" "$case_dir/project" ExternalDeclarations "${mode[@]}" \
        -scriptPath "$source_dir/ghidra_scripts" -postScript PrepareExternalDeclarations.java "$phase" \
        "$main_address" "$global_address" "$case_dir/$phase.json" \
        -postScript GhidraDwarfForge.java --packaged-natives "--output=$case_dir/decl.dbg" >"$case_dir/export-$phase.log" 2>&1
    test -f "$case_dir/$phase.json"
    grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$phase.log"
    if [[ "$phase" == curate ]]; then
        cp "$case_dir/decl.dbg" "$case_dir/first.decl.dbg"
        cp "$case_dir/decl.dbg.c" "$case_dir/first.decl.dbg.c"
    fi
done
cmp "$case_dir/decl.dbg" "$case_dir/first.decl.dbg"
cmp "$case_dir/decl.dbg.c" "$case_dir/first.decl.dbg.c"
for view in header sections notes info abbrev aranges decodedline loc Ranges; do
    case "$view" in header) option=-h ;; sections) option=-SW ;; notes) option=-n ;; *) option="--debug-dump=$view" ;; esac
    readelf "$option" "$case_dir/decl.dbg" >"$case_dir/forge-$view.stdout" 2>"$case_dir/forge-$view.stderr"
    test ! -s "$case_dir/forge-$view.stderr"
done
llvm-dwarfdump --verify "$case_dir/decl.dbg" >"$case_dir/llvm.stdout" 2>"$case_dir/llvm.stderr"
test ! -s "$case_dir/llvm.stderr"
grep -Fq 'No errors.' "$case_dir/llvm.stdout"
python3 "$source_dir/check-dwarfdump.py" "$case_dir/decl.dbg" "$case_dir/strict.log" --original "$case_dir/decl.stripped"
python3 "$source_dir/external-function-declarations-check.py" observations "$case_dir" "$repository" "$module"
for variant in compiler forge; do
    input="$case_dir/decl.reference"; symbols="$input"
    if [[ "$variant" == forge ]]; then input="$case_dir/decl.stripped"; symbols="$case_dir/decl.dbg"; fi
    DECL_CASE="$case_dir" DECL_VARIANT="$variant" DECL_SOURCE="$repository/src/test/fixtures/external-function-declarations.c" \
        timeout 90s gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' -ex 'set disable-randomization off' \
        -ex "set debug-file-directory $case_dir/empty-debug" -ex "file $input" -ex "symbol-file $symbols" \
        -x "$source_dir/external-function-declarations-gdb.py" >"$case_dir/$variant-gdb.stdout" 2>"$case_dir/$variant-gdb.stderr"
    test ! -s "$case_dir/$variant-gdb.stderr"
done
python3 "$source_dir/external-function-declarations-check.py" finish "$case_dir" "$repository" "$module"
set +x
unset BASH_XTRACEFD
exec 9>&-
