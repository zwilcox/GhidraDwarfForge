#!/usr/bin/env bash
# Same hard-float ELF, analyst dynamic base/VFP signatures, saved-program repeat.
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "usage: $0 <ghidra-dir>" >&2
    exit 2
fi
export LC_ALL=C
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
module="$ghidra/Ghidra/Extensions/GhidraDwarfForge"
results="$repository/build/test-results/arm-dynamic-pcs"
mkdir -p "$results"
case_dir=$(mktemp -d "$results/run.XXXXXXXX")
mkdir "$case_dir/project" "$case_dir/empty-debug"
exec 9>"$case_dir/commands.log"
BASH_XTRACEFD=9
set -x
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
compiler=${ARM32_CC:-arm-linux-gnueabihf-gcc}
objcopy=${ARM32_OBJCOPY:-arm-linux-gnueabihf-objcopy}
sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf}
"$compiler" -marm -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard -O0 -g3 -gdwarf-5 \
    -fno-omit-frame-pointer -funwind-tables -fno-pie -no-pie -Wl,--build-id=none \
    "$repository/src/test/fixtures/arm-dynamic-pcs.c" -o "$case_dir/pcs.reference" \
    >"$case_dir/compile.stdout" 2>"$case_dir/compile.stderr"
test ! -s "$case_dir/compile.stderr"
"$objcopy" --strip-all "$case_dir/pcs.reference" "$case_dir/pcs.stripped" \
    >"$case_dir/strip.stdout" 2>"$case_dir/strip.stderr"
test ! -s "$case_dir/strip.stderr"
for tool in "$compiler" "$objcopy" readelf llvm-dwarfdump gdb-multiarch qemu-arm-static; do
    "$tool" --version >"$case_dir/$(basename "$tool").version" 2>&1
done
for view in header sections attributes symbols info; do
    case "$view" in
        header) option=-h ;; sections) option=-SW ;; attributes) option=-A ;; symbols) option=-sW ;;
        *) option="--debug-dump=$view" ;;
    esac
    readelf "$option" "$case_dir/pcs.reference" >"$case_dir/compiler-$view.stdout" 2>"$case_dir/compiler-$view.stderr"
    test ! -s "$case_dir/compiler-$view.stderr"
done
python3 "$repository/src/test/integration/arm-dynamic-pcs-check.py" labels "$case_dir" "$repository" "$module"
run_gdb() {
    local variant=$1 input symbols
    if [[ "$variant" == compiler ]]; then
        input="$case_dir/pcs.reference"; symbols="$input"
    else
        input="$case_dir/pcs.stripped"; symbols="$case_dir/pcs.dbg"
    fi
    qemu_socket_start "$case_dir/$variant.qemu" qemu-arm-static "$sysroot" "$input"
    FORGE_PCS_CASE="$case_dir" FORGE_PCS_VARIANT="$variant" FORGE_PCS_REMOTE="$qemu_socket_path" \
        timeout 60s gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
        -ex 'set auto-solib-add off' -ex "set debug-file-directory $case_dir/empty-debug" \
        -ex "set sysroot $sysroot" -ex "file $input" -ex "symbol-file $symbols" \
        -x "$repository/src/test/integration/arm-dynamic-pcs-gdb.py" \
        >"$case_dir/$variant.stdout" 2>"$case_dir/$variant.stderr"
    grep -Fq "arm-dynamic-pcs-gdb=$variant PASS" "$case_dir/$variant.stdout"
    qemu_socket_wait
}
run_gdb compiler
"$ghidra/support/analyzeHeadless" "$case_dir/project" DynamicPcs \
    -import "$case_dir/pcs.stripped" -analysisTimeoutPerFile 120 >"$case_dir/import.log" 2>&1
grep -Fq 'REPORT: Import succeeded' "$case_dir/import.log"
for phase in curate inspect; do
    mode=()
    if [[ "$phase" == inspect ]]; then mode=(-readOnly); fi
    "$ghidra/support/analyzeHeadless" "$case_dir/project" DynamicPcs \
        -process pcs.stripped -noanalysis "${mode[@]}" \
        -scriptPath "$repository/src/test/integration/ghidra_scripts" \
        -postScript PrepareArmDynamicPcs.java "$phase" "$case_dir/labels.txt" \
        -postScript GhidraDwarfForge.java --packaged-natives "--output=$case_dir/pcs.dbg" \
        >"$case_dir/export-$phase.log" 2>&1
    grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$phase.log"
    if [[ "$phase" == curate ]]; then
        cp "$case_dir/pcs.dbg" "$case_dir/first.dbg"
        cp "$case_dir/pcs.dbg.c" "$case_dir/first.dbg.c"
    fi
done
cmp "$case_dir/pcs.dbg" "$case_dir/first.dbg"
cmp "$case_dir/pcs.dbg.c" "$case_dir/first.dbg.c"
for view in header sections notes info abbrev aranges decodedline loc Ranges; do
    case "$view" in
        header) option=-h ;; sections) option=-SW ;; notes) option=-n ;;
        *) option="--debug-dump=$view" ;;
    esac
    readelf "$option" "$case_dir/pcs.dbg" >"$case_dir/forge-$view.stdout" 2>"$case_dir/forge-$view.stderr"
    test ! -s "$case_dir/forge-$view.stderr"
done
llvm-dwarfdump --verify "$case_dir/pcs.dbg" >"$case_dir/llvm.stdout" 2>"$case_dir/llvm.stderr"
test ! -s "$case_dir/llvm.stderr"
grep -Fq 'No errors.' "$case_dir/llvm.stdout"
python3 "$repository/src/test/integration/check-dwarfdump.py" "$case_dir/pcs.dbg" \
    "$case_dir/strict.log" --original "$case_dir/pcs.stripped"
run_gdb forge
python3 "$repository/src/test/integration/arm-dynamic-pcs-check.py" finish "$case_dir" "$repository" "$module"
