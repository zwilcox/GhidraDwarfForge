#!/usr/bin/env bash
# Freestanding O32/N32 STORE proof, both byte orders; no libc/profile expansion.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "usage: $0 <ghidra-dir> <mips32be|mips32le>" >&2
    exit 2
fi
export LC_ALL=C
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
target=$2
case "$target" in
    mips32be) prefix=mips-linux-gnu; suffix= ;;
    mips32le) prefix=mipsel-linux-gnu; suffix=el ;;
    *) echo "unsupported fixture target: $target" >&2; exit 2 ;;
esac
module="$ghidra/Ghidra/Extensions/GhidraDwarfForge"
results="$repository/build/test-results/mips-truncated-space"
mkdir -p "$results"
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
for abi in o32 n32; do
    case_dir=$(mktemp -d "$results/$target.$abi.XXXXXXXX")
    mkdir "$case_dir/project" "$case_dir/empty-debug"
    exec 9>"$case_dir/commands.log"
    BASH_XTRACEFD=9
    set -x
    if [[ "$abi" == o32 ]]; then
        flags=(-mabi=32 -march=mips32r2)
        emulator="qemu-mips${suffix}-static"
        export QEMU_CPU=24Kf
    else
        flags=(-mabi=n32 -march=mips64r2)
        emulator="qemu-mipsn32${suffix}-static"
        export QEMU_CPU=MIPS64R2-generic
    fi
    for tool in "$prefix-gcc" "$prefix-objcopy" "$prefix-objdump" readelf llvm-dwarfdump gdb-multiarch "$emulator"; do
        "$tool" --version >"$case_dir/$(basename "$tool").version" 2>&1
    done
    printf '#include <asm/unistd.h>\n' | "$prefix-gcc" "${flags[@]}" -dM -E -x c - \
        >"$case_dir/macros.stdout" 2>"$case_dir/macros.stderr"
    test ! -s "$case_dir/macros.stderr"
    "$prefix-gcc" "${flags[@]}" -E -P "$repository/src/test/fixtures/mips-truncated-space-start.S" \
        >"$case_dir/start.stdout" 2>"$case_dir/start.stderr"
    test ! -s "$case_dir/start.stderr"
    "$prefix-gcc" "${flags[@]}" -O0 -g3 -gdwarf-5 -fno-inline -fno-omit-frame-pointer \
        -fno-stack-protector -fno-pic -fno-pie -mno-abicalls -G0 -nostdlib -nostartfiles \
        -static -no-pie -Wl,-e,_start -Wl,--build-id=none \
        "$repository/src/test/fixtures/mips-truncated-space-start.S" \
        "$repository/src/test/fixtures/mips-truncated-space.c" -o "$case_dir/abi.reference" \
        >"$case_dir/compile.stdout" 2>"$case_dir/compile.stderr"
    test ! -s "$case_dir/compile.stderr"
    "$prefix-objcopy" --strip-all "$case_dir/abi.reference" "$case_dir/abi.stripped" \
        >"$case_dir/strip.stdout" 2>"$case_dir/strip.stderr"
    test ! -s "$case_dir/strip.stderr"
    readelf -h -A "$case_dir/abi.reference" >"$case_dir/compiler-header.stdout" 2>"$case_dir/compiler-header.stderr"
    readelf -sW "$case_dir/abi.reference" >"$case_dir/compiler-symbols.stdout" 2>"$case_dir/compiler-symbols.stderr"
    readelf --debug-dump=info "$case_dir/abi.reference" >"$case_dir/compiler-info.stdout" 2>"$case_dir/compiler-info.stderr"
    "$prefix-objdump" -drwC "$case_dir/abi.reference" >"$case_dir/compiler-disassembly.stdout" 2>"$case_dir/compiler-disassembly.stderr"
    for view in header symbols info disassembly; do test ! -s "$case_dir/compiler-$view.stderr"; done
    python3 "$repository/src/test/integration/mips-truncated-space-check.py" labels \
        "$case_dir" "$repository" "$module" "$target" "$abi"
    timeout 15s "$emulator" "$case_dir/abi.reference" >"$case_dir/plain.stdout" 2>"$case_dir/plain.stderr"
    test ! -s "$case_dir/plain.stdout"
    test ! -s "$case_dir/plain.stderr"
    "$ghidra/support/analyzeHeadless" "$case_dir/project" TruncatedSpace \
        -import "$case_dir/abi.stripped" -analysisTimeoutPerFile 120 \
        -scriptPath "$repository/src/test/integration/ghidra_scripts" \
        -postScript PrepareMipsTruncatedSpace.java natural "$case_dir/labels.txt" "$case_dir/natural.json" \
        >"$case_dir/import.log" 2>&1
    grep -Fq 'REPORT: Import succeeded' "$case_dir/import.log"
    grep -Fq 'MIPS_TRUNCATED_SPACE_PASS natural' "$case_dir/import.log"
    for phase in curate inspect; do
        mode=()
        if [[ "$phase" == inspect ]]; then mode=(-readOnly); fi
        "$ghidra/support/analyzeHeadless" "$case_dir/project" TruncatedSpace \
            -process abi.stripped -noanalysis "${mode[@]}" \
            -scriptPath "$repository/src/test/integration/ghidra_scripts" \
            -postScript PrepareMipsTruncatedSpace.java "$phase" "$case_dir/labels.txt" "$case_dir/$phase.json" \
            -postScript GhidraDwarfForge.java --packaged-natives "--output=$case_dir/abi.dbg" \
            >"$case_dir/export-$phase.log" 2>&1
        grep -Fq "MIPS_TRUNCATED_SPACE_PASS $phase" "$case_dir/export-$phase.log"
        grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$phase.log"
        if [[ "$phase" == curate ]]; then
            cp "$case_dir/abi.dbg" "$case_dir/first.abi.dbg"
            cp "$case_dir/abi.dbg.c" "$case_dir/first.abi.dbg.c"
        fi
    done
    cmp "$case_dir/abi.dbg" "$case_dir/first.abi.dbg"
    cmp "$case_dir/abi.dbg.c" "$case_dir/first.abi.dbg.c"
    python3 "$repository/src/test/integration/mips-truncated-space-check.py" observations \
        "$case_dir" "$repository" "$module" "$target" "$abi"
    for view in header sections notes info abbrev aranges decodedline loc Ranges; do
        case "$view" in
            header) option=-h ;; sections) option=-SW ;; notes) option=-n ;;
            *) option="--debug-dump=$view" ;;
        esac
        readelf "$option" "$case_dir/abi.dbg" >"$case_dir/forge-$view.stdout" 2>"$case_dir/forge-$view.stderr"
        test ! -s "$case_dir/forge-$view.stderr"
    done
    llvm-dwarfdump --verify "$case_dir/abi.dbg" >"$case_dir/llvm.stdout" 2>"$case_dir/llvm.stderr"
    test ! -s "$case_dir/llvm.stderr"
    grep -Fq 'No errors.' "$case_dir/llvm.stdout"
    python3 "$repository/src/test/integration/check-dwarfdump.py" "$case_dir/abi.dbg" \
        "$case_dir/strict.log" --original "$case_dir/abi.stripped"
    for variant in compiler forge; do
        input="$case_dir/abi.reference"; symbols="$input"
        if [[ "$variant" == forge ]]; then input="$case_dir/abi.stripped"; symbols="$case_dir/abi.dbg"; fi
        qemu_socket_start "$case_dir/$variant.qemu" "$emulator" '' "$input"
        FORGE_MIPS_CASE="$case_dir" FORGE_MIPS_VARIANT="$variant" FORGE_MIPS_REMOTE="$qemu_socket_path" \
            timeout 90s gdb-multiarch -q -nx -batch \
            -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
            -ex 'set auto-solib-add off' -ex "set debug-file-directory $case_dir/empty-debug" \
            -ex "file $input" -ex "symbol-file $symbols" \
            -x "$repository/src/test/integration/mips-truncated-space-gdb.py" \
            >"$case_dir/$variant-gdb.stdout" 2>"$case_dir/$variant-gdb.stderr"
        grep -Fq "mips-truncated-space-gdb=$variant PASS" "$case_dir/$variant-gdb.stdout"
        test ! -s "$case_dir/$variant-gdb.stderr"
        qemu_socket_wait
    done
    python3 "$repository/src/test/integration/mips-truncated-space-check.py" finish \
        "$case_dir" "$repository" "$module" "$target" "$abi"
    set +x
    unset BASH_XTRACEFD
    exec 9>&-
done
