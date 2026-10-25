#!/usr/bin/env bash
# Ordinary O0 aggregate and separate O1 scalar, with computed and converted-custom storage.
set -euo pipefail
if [[ $# -ne 2 ]]; then
    echo "usage: $0 <ghidra-dir> <x86_64|aarch64|arm32|mips32be|mips32le>" >&2
    exit 2
fi
export LC_ALL=C
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
module="$ghidra/Ghidra/Extensions/GhidraDwarfForge"
target=$2
case "$target" in
    x86_64) compiler=gcc; objcopy=objcopy; objdump=objdump; emulator=; sysroot=; extra=(-fcf-protection=none) ;;
    aarch64) compiler=aarch64-linux-gnu-gcc; objcopy=aarch64-linux-gnu-objcopy; objdump=aarch64-linux-gnu-objdump
        emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu; extra=() ;;
    arm32) compiler=${ARM32_CC:-arm-linux-gnueabihf-gcc}; objcopy=${ARM32_OBJCOPY:-arm-linux-gnueabihf-objcopy}
        objdump=${ARM32_OBJDUMP:-arm-linux-gnueabihf-objdump}; emulator=qemu-arm-static
        sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf}; extra=(-marm -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard) ;;
    mips32be) compiler=mips-linux-gnu-gcc; objcopy=mips-linux-gnu-objcopy; objdump=mips-linux-gnu-objdump
        emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu; extra=() ;;
    mips32le) compiler=mipsel-linux-gnu-gcc; objcopy=mipsel-linux-gnu-objcopy; objdump=mipsel-linux-gnu-objdump
        emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu; extra=() ;;
    *) echo "unsupported fixture target: $target" >&2; exit 2 ;;
esac
results="$repository/build/test-results/dynamic-composite-storage"
mkdir -p "$results"
case_dir=$(mktemp -d "$results/$target.XXXXXXXX")
mkdir "$case_dir/project" "$case_dir/empty-debug"
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
exec 9>"$case_dir/commands.log"
BASH_XTRACEFD=9
set -x
for tool in "$compiler" "$objcopy" "$objdump" readelf llvm-dwarfdump gdb-multiarch; do
    "$tool" --version >"$case_dir/$(basename "$tool").version" 2>&1
done
if [[ -n "$emulator" ]]; then "$emulator" --version >"$case_dir/$emulator.version" 2>&1; fi
common=(-g3 -gdwarf-5 -fno-inline -fno-omit-frame-pointer -funwind-tables -fno-pie)
for unit in aggregate scalar caller; do
    optimization=(-O0)
    if [[ "$unit" == aggregate ]]; then optimization+=(-Dmain=aggregate_main); fi
    if [[ "$unit" == scalar ]]; then optimization=(-O1); fi
    "$compiler" "${common[@]}" "${extra[@]}" "${optimization[@]}" -c \
        "$repository/src/test/fixtures/dynamic-composite-$unit.c" -o "$case_dir/$unit.o" \
        >"$case_dir/compile-$unit.stdout" 2>"$case_dir/compile-$unit.stderr"
    test ! -s "$case_dir/compile-$unit.stderr"
done
"$compiler" "${extra[@]}" -fno-pie -no-pie -Wl,--build-id=none \
    "$case_dir/aggregate.o" "$case_dir/scalar.o" "$case_dir/caller.o" -o "$case_dir/composite.reference" \
    >"$case_dir/link.stdout" 2>"$case_dir/link.stderr"
test ! -s "$case_dir/link.stderr"
"$objcopy" --strip-all "$case_dir/composite.reference" "$case_dir/composite.stripped" >"$case_dir/strip.stdout" 2>"$case_dir/strip.stderr"
test ! -s "$case_dir/strip.stderr"
for view in header sections symbols info; do
    case "$view" in header) option=-h ;; sections) option=-SW ;; symbols) option=-sW ;; info) option=--debug-dump=info ;; esac
    readelf "$option" "$case_dir/composite.reference" >"$case_dir/compiler-$view.stdout" 2>"$case_dir/compiler-$view.stderr"
    test ! -s "$case_dir/compiler-$view.stderr"
done
"$objdump" -drwC "$case_dir/composite.reference" >"$case_dir/compiler-disassembly.stdout" 2>"$case_dir/compiler-disassembly.stderr"
test ! -s "$case_dir/compiler-disassembly.stderr"
python3 "$repository/src/test/integration/dynamic-composite-storage-check.py" labels "$case_dir" "$repository" "$module" "$target"
if [[ -n "$emulator" ]]; then
    timeout 30s "$emulator" -L "$sysroot" "$case_dir/composite.reference" >"$case_dir/plain.stdout" 2>"$case_dir/plain.stderr"
else
    timeout 30s "$case_dir/composite.reference" >"$case_dir/plain.stdout" 2>"$case_dir/plain.stderr"
fi
test ! -s "$case_dir/plain.stdout"
test ! -s "$case_dir/plain.stderr"
for phase in natural curate inspect custom reopen-custom; do
    mode=(-process composite.stripped -noanalysis)
    if [[ "$phase" == natural ]]; then mode=(-import "$case_dir/composite.stripped" -analysisTimeoutPerFile 120); fi
    if [[ "$phase" == inspect || "$phase" == reopen-custom ]]; then mode+=(-readOnly); fi
    output=composite.dbg
    if [[ "$phase" == custom || "$phase" == reopen-custom ]]; then output=custom.composite.dbg; fi
    export_script=()
    if [[ "$phase" != natural ]]; then export_script=(-postScript GhidraDwarfForge.java --packaged-natives "--output=$case_dir/$output"); fi
    "$ghidra/support/analyzeHeadless" "$case_dir/project" DynamicComposites "${mode[@]}" \
        -scriptPath "$repository/src/test/integration/ghidra_scripts" \
        -postScript PrepareDynamicCompositeStorage.java "$phase" "$case_dir/labels.txt" "$case_dir/$phase.json" \
        "${export_script[@]}" >"$case_dir/export-$phase.log" 2>&1
    test -f "$case_dir/$phase.json"
    if [[ "$phase" != natural ]]; then grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$phase.log"; fi
    if [[ "$phase" == curate || "$phase" == custom ]]; then
        cp "$case_dir/$output" "$case_dir/first.$output"
        cp "$case_dir/$output.c" "$case_dir/first.$output.c"
    fi
done
cmp "$case_dir/composite.dbg" "$case_dir/first.composite.dbg"
cmp "$case_dir/composite.dbg.c" "$case_dir/first.composite.dbg.c"
cmp "$case_dir/custom.composite.dbg" "$case_dir/first.custom.composite.dbg"
cmp "$case_dir/custom.composite.dbg.c" "$case_dir/first.custom.composite.dbg.c"
python3 "$repository/src/test/integration/dynamic-composite-storage-check.py" observations "$case_dir" "$repository" "$module" "$target"
for artifact in computed custom; do
    output=composite.dbg; prefix=
    if [[ "$artifact" == custom ]]; then output=custom.composite.dbg; prefix=custom-; fi
    for view in header sections notes info abbrev aranges decodedline loc Ranges; do
        case "$view" in header) option=-h ;; sections) option=-SW ;; notes) option=-n ;; *) option="--debug-dump=$view" ;; esac
        readelf "$option" "$case_dir/$output" >"$case_dir/${prefix}forge-$view.stdout" 2>"$case_dir/${prefix}forge-$view.stderr"
        test ! -s "$case_dir/${prefix}forge-$view.stderr"
    done
    llvm-dwarfdump --verify "$case_dir/$output" >"$case_dir/${prefix}llvm.stdout" 2>"$case_dir/${prefix}llvm.stderr"
    test ! -s "$case_dir/${prefix}llvm.stderr"
    grep -Fq 'No errors.' "$case_dir/${prefix}llvm.stdout"
    python3 "$repository/src/test/integration/check-dwarfdump.py" "$case_dir/$output" "$case_dir/${prefix}strict.log" --original "$case_dir/composite.stripped"
done
for variant in compiler forge custom; do
    input="$case_dir/composite.reference"; symbols="$input"; remote=; gdb_options=()
    if [[ "$variant" != compiler ]]; then input="$case_dir/composite.stripped"; symbols="$case_dir/composite.dbg"; fi
    if [[ "$variant" == custom ]]; then symbols="$case_dir/custom.composite.dbg"; fi
    if [[ -n "$emulator" ]]; then
        qemu_socket_start "$case_dir/$variant.qemu" "$emulator" "$sysroot" "$input"
        remote="$qemu_socket_path"; gdb_options=(-ex "set sysroot $sysroot")
    fi
    FORGE_COMPOSITE_CASE="$case_dir" FORGE_COMPOSITE_TARGET="$target" FORGE_COMPOSITE_VARIANT="$variant" FORGE_COMPOSITE_REMOTE="$remote" \
        timeout 90s gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' -ex 'set disable-randomization off' \
        -ex "set debug-file-directory $case_dir/empty-debug" "${gdb_options[@]}" \
        -ex "file $input" -ex "symbol-file $symbols" -x "$repository/src/test/integration/dynamic-composite-storage-gdb.py" \
        >"$case_dir/$variant-gdb.stdout" 2>"$case_dir/$variant-gdb.stderr"
    grep -Fq "dynamic-composite-storage-gdb=$variant PASS" "$case_dir/$variant-gdb.stdout"
    if [[ -n "$emulator" ]]; then qemu_socket_wait; fi
done
python3 "$repository/src/test/integration/dynamic-composite-storage-check.py" finish "$case_dir" "$repository" "$module" "$target"
set +x
unset BASH_XTRACEFD
exec 9>&-
