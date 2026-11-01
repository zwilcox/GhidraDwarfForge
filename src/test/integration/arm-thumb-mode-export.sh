#!/usr/bin/env bash
# Real mixed-mode executable, same saved Program twice, default GDB ARM mode.
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "usage: $0 <ghidra-dir>" >&2
    exit 2
fi
export LC_ALL=C
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
module="$ghidra/Ghidra/Extensions/GhidraDwarfForge"
results="$repository/build/test-results/arm-thumb-mode"
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
role=${FORGE_THUMB_ROLE:-exec}
case "$role" in
    exec) code_model=-fno-pie; link_model=-no-pie ;;
    pie|pie-rebased|pie-dynamic) code_model=-fPIE; link_model=-pie ;;
    *) echo "unsupported Thumb role: $role" >&2; exit 2 ;;
esac
printf '%s\n' "$role" > "$case_dir/role.txt"
extra_link=()
if [[ "$role" == pie-dynamic ]]; then extra_link=(-Wl,--export-dynamic); fi
common=(-march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard -O0 -g3 -gdwarf-5
    -fno-omit-frame-pointer -funwind-tables "$code_model")
for unit in caller leaf after; do
    mode=-marm
    if [[ "$unit" == leaf ]]; then mode=-mthumb; fi
    "$compiler" "${common[@]}" "$mode" -c \
        "$repository/src/test/fixtures/arm-thumb-$unit.c" -o "$case_dir/$unit.o" \
        >"$case_dir/compile-$unit.stdout" 2>"$case_dir/compile-$unit.stderr"
    test ! -s "$case_dir/compile-$unit.stderr"
done
"$compiler" "${common[@]}" -marm "$link_model" "${extra_link[@]}" -Wl,--build-id=none \
    "$case_dir/caller.o" "$case_dir/leaf.o" "$case_dir/after.o" -o "$case_dir/thumb.reference" \
    >"$case_dir/link.stdout" 2>"$case_dir/link.stderr"
test ! -s "$case_dir/link.stderr"
"$objcopy" --strip-all "$case_dir/thumb.reference" "$case_dir/thumb.stripped" \
    >"$case_dir/strip.stdout" 2>"$case_dir/strip.stderr"
test ! -s "$case_dir/strip.stderr"
for tool in "$compiler" "$objcopy" readelf llvm-dwarfdump gdb-multiarch qemu-arm-static; do
    "$tool" --version > "$case_dir/$(basename "$tool").version" 2>&1
done
for view in header sections notes symbols info rawline; do
    case "$view" in
        header) option=-h ;; sections) option=-SW ;; notes) option=-n ;; symbols) option=-sW ;;
        *) option="--debug-dump=$view" ;;
    esac
    readelf "$option" "$case_dir/thumb.reference" >"$case_dir/compiler-$view.stdout" 2>"$case_dir/compiler-$view.stderr"
    test ! -s "$case_dir/compiler-$view.stderr"
done
python3 "$repository/src/test/integration/arm-thumb-mode-check.py" labels "$case_dir" "$repository" "$module"
mapfile -t preparation < "$case_dir/prepare.txt"
if [[ "$role" == pie-rebased ]]; then preparation+=(0x200000); fi
run_gdb() {
    local variant=$1 phase=$2 input symbols
    if [[ "$variant" == compiler ]]; then
        input="$case_dir/thumb.reference"; symbols="$input"
    else
        input="$case_dir/thumb.stripped"; symbols="$case_dir/thumb.dbg"
    fi
    qemu_socket_start "$case_dir/$variant-$phase.qemu" qemu-arm-static "$sysroot" "$input"
    FORGE_THUMB_CASE="$case_dir" FORGE_THUMB_VARIANT="$variant" FORGE_THUMB_PHASE="$phase" \
    FORGE_THUMB_REMOTE="$qemu_socket_path" timeout 60s gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
        -ex 'set auto-solib-add off' -ex "set debug-file-directory $case_dir/empty-debug" \
        -ex "set sysroot $sysroot" -ex "file $input" -ex "symbol-file $symbols" \
        -x "$repository/src/test/integration/arm-thumb-mode-gdb.py" \
        >"$case_dir/$variant-$phase.stdout" 2>"$case_dir/$variant-$phase.stderr"
    grep -Fq "arm-thumb-mode-gdb=$variant/$phase PASS" "$case_dir/$variant-$phase.stdout"
    qemu_socket_wait
}
run_gdb compiler calls
run_gdb compiler from-arm
"$ghidra/support/analyzeHeadless" "$case_dir/project" ThumbModes \
    -import "$case_dir/thumb.stripped" -analysisTimeoutPerFile 120 \
    >"$case_dir/import.log" 2>&1
grep -Fq 'REPORT: Import succeeded' "$case_dir/import.log"
"$ghidra/support/analyzeHeadless" "$case_dir/project" ThumbModes \
    -process thumb.stripped -noanalysis \
    -scriptPath "$repository/src/test/integration/ghidra_scripts" \
    -postScript PrepareArmThumbMode.java "${preparation[@]}" \
    -postScript GhidraDwarfForge.java --packaged-natives "--output=$case_dir/thumb.dbg" \
    >"$case_dir/export-first.log" 2>&1
grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-first.log"
cp "$case_dir/thumb.dbg" "$case_dir/first.thumb.dbg"
cp "$case_dir/thumb.dbg.c" "$case_dir/first.thumb.dbg.c"
"$ghidra/support/analyzeHeadless" "$case_dir/project" ThumbModes \
    -process thumb.stripped -noanalysis -readOnly \
    -postScript GhidraDwarfForge.java --packaged-natives "--output=$case_dir/thumb.dbg" \
    >"$case_dir/export-repeat.log" 2>&1
grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-repeat.log"
cmp "$case_dir/thumb.dbg" "$case_dir/first.thumb.dbg"
cmp "$case_dir/thumb.dbg.c" "$case_dir/first.thumb.dbg.c"
for view in header sections notes symbols info abbrev aranges decodedline rawline loc Ranges; do
    case "$view" in
        header) option=-h ;; sections) option=-SW ;; notes) option=-n ;; symbols) option=-sW ;;
        *) option="--debug-dump=$view" ;;
    esac
    readelf "$option" "$case_dir/thumb.dbg" >"$case_dir/forge-$view.stdout" 2>"$case_dir/forge-$view.stderr"
    test ! -s "$case_dir/forge-$view.stderr"
done
llvm-dwarfdump --verify "$case_dir/thumb.dbg" >"$case_dir/llvm.stdout" 2>"$case_dir/llvm.stderr"
test ! -s "$case_dir/llvm.stderr"
grep -Fq 'No errors.' "$case_dir/llvm.stdout"
python3 "$repository/src/test/integration/check-dwarfdump.py" "$case_dir/thumb.dbg" \
    "$case_dir/strict.log" --original "$case_dir/thumb.stripped"
run_gdb forge calls
run_gdb forge from-arm
python3 "$repository/src/test/integration/arm-thumb-mode-check.py" finish "$case_dir" "$repository" "$module"

if [[ "$role" != pie-dynamic ]]; then
    python3 "$repository/src/test/integration/arm-thumb-mode-negative.py" "$case_dir"
fi
