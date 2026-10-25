#!/usr/bin/env bash
# ET_EXEC computed/custom incoming composite prefixes; unchanged research C and flags.
set -euo pipefail
if [[ $# -ne 2 ]]; then
    echo "usage: $0 <ghidra-dir> <x86_64|aarch64>" >&2
    exit 2
fi
export LC_ALL=C
repository=$(realpath "$(dirname "$0")/../../..")
source_dir="$repository/src/test/integration"
ghidra=$(realpath "$1")
module="$ghidra/Ghidra/Extensions/GhidraDwarfForge"
target=$2
case "$target" in
    x86_64) compiler=gcc; objcopy=objcopy; objdump=objdump; emulator=; sysroot=; extra=(-fcf-protection=none) ;;
    aarch64) compiler=aarch64-linux-gnu-gcc; objcopy=aarch64-linux-gnu-objcopy; objdump=aarch64-linux-gnu-objdump
        emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu; extra=() ;;
    *) echo "unsupported fixture target: $target" >&2; exit 2 ;;
esac
results="$repository/build/test-results/composite-register-prefix"
mkdir -p "$results"
case_dir=$(mktemp -d "$results/$target.XXXXXXXX")
mkdir "$case_dir/project" "$case_dir/empty-debug"
source "$source_dir/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
exec 9>"$case_dir/commands.log"
BASH_XTRACEFD=9
set -x
for tool in "$compiler" "$objcopy" "$objdump" readelf llvm-dwarfdump gdb-multiarch; do
    "$tool" --version >"$case_dir/$(basename "$tool").version" 2>&1
done
if [[ -n "$emulator" ]]; then "$emulator" --version >"$case_dir/$emulator.version" 2>&1; fi
# Preselected before execution: ordinary16-byte C aggregate; exact clobber declared to compiler.
"$compiler" -O1 -g3 -gdwarf-5 -fno-inline -fno-omit-frame-pointer -fno-ipa-sra \
    -fno-stack-protector -funwind-tables -fno-pie -no-pie "${extra[@]}" \
    -Wl,--build-id=none "$repository/src/test/fixtures/composite-register-prefix.c" -o "$case_dir/prefix.reference" \
    >"$case_dir/compile.stdout" 2>"$case_dir/compile.stderr"
test ! -s "$case_dir/compile.stderr"
"$objcopy" --strip-all "$case_dir/prefix.reference" "$case_dir/prefix.stripped" >"$case_dir/strip.stdout" 2>"$case_dir/strip.stderr"
test ! -s "$case_dir/strip.stderr"
for view in header sections symbols info; do
    case "$view" in header) option=-h ;; sections) option=-SW ;; symbols) option=-sW ;; info) option=--debug-dump=info ;; esac
    readelf "$option" "$case_dir/prefix.reference" >"$case_dir/compiler-$view.stdout" 2>"$case_dir/compiler-$view.stderr"
    test ! -s "$case_dir/compiler-$view.stderr"
done
"$objdump" -drwC "$case_dir/prefix.reference" >"$case_dir/compiler-disassembly.stdout" 2>"$case_dir/compiler-disassembly.stderr"
test ! -s "$case_dir/compiler-disassembly.stderr"
python3 "$source_dir/composite-register-prefix-check.py" labels "$case_dir" "$repository" "$module" "$target"
if [[ -n "$emulator" ]]; then
    timeout 30s "$emulator" -L "$sysroot" "$case_dir/prefix.reference" >"$case_dir/plain.stdout" 2>"$case_dir/plain.stderr"
else
    timeout 30s "$case_dir/prefix.reference" >"$case_dir/plain.stdout" 2>"$case_dir/plain.stderr"
fi
test ! -s "$case_dir/plain.stdout"
test ! -s "$case_dir/plain.stderr"
for phase in natural curate inspect custom reopen-custom; do
    mode=(-process prefix.stripped -noanalysis)
    if [[ "$phase" == natural ]]; then mode=(-import "$case_dir/prefix.stripped" -analysisTimeoutPerFile 120); fi
    if [[ "$phase" == inspect || "$phase" == reopen-custom ]]; then mode+=(-readOnly); fi
    output=prefix.dbg
    if [[ "$phase" == custom || "$phase" == reopen-custom ]]; then output=custom.prefix.dbg; fi
    export_script=()
    if [[ "$phase" != natural ]]; then export_script=(-postScript GhidraDwarfForge.java --packaged-natives "--output=$case_dir/$output"); fi
    "$ghidra/support/analyzeHeadless" "$case_dir/project" CompositePrefix "${mode[@]}" \
        -scriptPath "$source_dir/ghidra_scripts" \
        -postScript PrepareCompositeRegisterPrefix.java "$phase" "$case_dir/labels.txt" "$case_dir/$phase.json" \
        "${export_script[@]}" >"$case_dir/export-$phase.log" 2>&1
    test -f "$case_dir/$phase.json"
    if [[ "$phase" != natural ]]; then grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$phase.log"; fi
    if [[ "$phase" == curate || "$phase" == custom ]]; then
        cp "$case_dir/$output" "$case_dir/first.$output"
        cp "$case_dir/$output.c" "$case_dir/first.$output.c"
    fi
done
cmp "$case_dir/prefix.dbg" "$case_dir/first.prefix.dbg"
cmp "$case_dir/prefix.dbg.c" "$case_dir/first.prefix.dbg.c"
cmp "$case_dir/custom.prefix.dbg" "$case_dir/first.custom.prefix.dbg"
cmp "$case_dir/custom.prefix.dbg.c" "$case_dir/first.custom.prefix.dbg.c"
python3 "$source_dir/composite-register-prefix-check.py" observations "$case_dir" "$repository" "$module" "$target"
for artifact in computed custom; do
    output=prefix.dbg; prefix=
    if [[ "$artifact" == custom ]]; then output=custom.prefix.dbg; prefix=custom-; fi
    for view in header sections notes info abbrev aranges decodedline loc Ranges; do
        case "$view" in header) option=-h ;; sections) option=-SW ;; notes) option=-n ;; *) option="--debug-dump=$view" ;; esac
        readelf "$option" "$case_dir/$output" >"$case_dir/${prefix}forge-$view.stdout" 2>"$case_dir/${prefix}forge-$view.stderr"
        test ! -s "$case_dir/${prefix}forge-$view.stderr"
    done
    llvm-dwarfdump --verify "$case_dir/$output" >"$case_dir/${prefix}llvm.stdout" 2>"$case_dir/${prefix}llvm.stderr"
    test ! -s "$case_dir/${prefix}llvm.stderr"
    grep -Fq 'No errors.' "$case_dir/${prefix}llvm.stdout"
    python3 "$source_dir/check-dwarfdump.py" "$case_dir/$output" "$case_dir/${prefix}strict.log" --original "$case_dir/prefix.stripped"
done
for variant in compiler forge custom; do
    input="$case_dir/prefix.reference"; symbols="$input"; remote=; gdb_options=()
    if [[ "$variant" != compiler ]]; then input="$case_dir/prefix.stripped"; symbols="$case_dir/prefix.dbg"; fi
    if [[ "$variant" == custom ]]; then symbols="$case_dir/custom.prefix.dbg"; fi
    if [[ -n "$emulator" ]]; then
        qemu_socket_start "$case_dir/$variant.qemu" "$emulator" "$sysroot" "$input"
        remote="$qemu_socket_path"; gdb_options=(-ex "set sysroot $sysroot")
    fi
    PREFIX_CASE="$case_dir" PREFIX_TARGET="$target" PREFIX_VARIANT="$variant" PREFIX_REMOTE="$remote" PREFIX_SOURCE="$repository/src/test/fixtures/composite-register-prefix.c" \
        timeout 90s gdb-multiarch -q -nx -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' -ex 'set disable-randomization off' \
        -ex "set debug-file-directory $case_dir/empty-debug" "${gdb_options[@]}" \
        -ex "file $input" -ex "symbol-file $symbols" -x "$source_dir/composite-register-prefix-gdb.py" \
        >"$case_dir/$variant-gdb.stdout" 2>"$case_dir/$variant-gdb.stderr"
    grep -Fq "composite-register-prefix-gdb=$variant PASS" "$case_dir/$variant-gdb.stdout"
    if [[ -n "$emulator" ]]; then qemu_socket_wait; fi
done
python3 "$source_dir/composite-register-prefix-check.py" finish "$case_dir" "$repository" "$module" "$target"
set +x
unset BASH_XTRACEFD
exec 9>&-
