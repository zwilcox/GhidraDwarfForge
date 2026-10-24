#!/usr/bin/env bash
# Real ordinary dynamic parameters across the existing five ELF profiles.
set -euo pipefail
if [[ $# -lt 1 ]]; then
    echo "usage: $0 <ghidra-dir> [x86_64 aarch64 arm32 mips32be mips32le ...]" >&2
    exit 2
fi
export LC_ALL=C
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
module="$ghidra/Ghidra/Extensions/GhidraDwarfForge"
shift
targets=("$@")
if [[ ${#targets[@]} == 0 ]]; then targets=(x86_64 aarch64 arm32 mips32be mips32le); fi
results="$repository/build/test-results/dynamic-parameter-storage"
mkdir -p "$results"
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
for target in "${targets[@]}"; do
    case "$target" in
        x86_64) compiler=gcc; objcopy=objcopy; emulator=; sysroot=; extra=(-fcf-protection=none) ;;
        aarch64) compiler=aarch64-linux-gnu-gcc; objcopy=aarch64-linux-gnu-objcopy
            emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu; extra=() ;;
        arm32) compiler=${ARM32_CC:-arm-linux-gnueabihf-gcc}; objcopy=${ARM32_OBJCOPY:-arm-linux-gnueabihf-objcopy}
            emulator=qemu-arm-static; sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf}
            extra=(-marm -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard) ;;
        mips32be) compiler=mips-linux-gnu-gcc; objcopy=mips-linux-gnu-objcopy
            emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu; extra=() ;;
        mips32le) compiler=mipsel-linux-gnu-gcc; objcopy=mipsel-linux-gnu-objcopy
            emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu; extra=() ;;
        *) echo "unsupported target: $target" >&2; exit 2 ;;
    esac
    case_dir=$(mktemp -d "$results/$target.XXXXXXXX")
    mkdir "$case_dir/project" "$case_dir/empty-debug"
    exec 9>"$case_dir/commands.log"
    BASH_XTRACEFD=9
    set -x
    "$compiler" -O0 -g3 -gdwarf-5 -fno-omit-frame-pointer -funwind-tables \
        -fno-pie -no-pie -Wl,--build-id=none "${extra[@]}" \
        "$repository/src/test/fixtures/dynamic-parameter-storage.c" -o "$case_dir/dynamic.reference" \
        >"$case_dir/compile.stdout" 2>"$case_dir/compile.stderr"
    test ! -s "$case_dir/compile.stderr"
    "$objcopy" --strip-all "$case_dir/dynamic.reference" "$case_dir/dynamic.stripped" \
        >"$case_dir/strip.stdout" 2>"$case_dir/strip.stderr"
    test ! -s "$case_dir/strip.stderr"
    tools=("$compiler" "$objcopy" readelf llvm-dwarfdump gdb-multiarch)
    if [[ -n "$emulator" ]]; then tools+=("$emulator"); fi
    for tool in "${tools[@]}"; do
        "$tool" --version >"$case_dir/$(basename "$tool").version" 2>&1
    done
    for view in header sections symbols; do
        case "$view" in header) option=-h ;; sections) option=-SW ;; symbols) option=-sW ;; esac
        readelf "$option" "$case_dir/dynamic.reference" >"$case_dir/compiler-$view.stdout" 2>"$case_dir/compiler-$view.stderr"
        test ! -s "$case_dir/compiler-$view.stderr"
    done
    python3 "$repository/src/test/integration/dynamic-parameter-storage-check.py" \
        labels "$case_dir" "$repository" "$module" "$target"
    "$ghidra/support/analyzeHeadless" "$case_dir/project" DynamicParameters \
        -import "$case_dir/dynamic.stripped" -analysisTimeoutPerFile 120 >"$case_dir/import.log" 2>&1
    grep -Fq 'REPORT: Import succeeded' "$case_dir/import.log"
    for phase in curate inspect; do
        mode=()
        if [[ "$phase" == inspect ]]; then mode=(-readOnly); fi
        "$ghidra/support/analyzeHeadless" "$case_dir/project" DynamicParameters \
            -process dynamic.stripped -noanalysis "${mode[@]}" \
            -scriptPath "$repository/src/test/integration/ghidra_scripts" \
            -postScript PrepareDynamicParameterStorage.java "$phase" "$case_dir/labels.txt" \
            -postScript GhidraDwarfForge.java --packaged-natives "--output=$case_dir/dynamic.dbg" \
            >"$case_dir/export-$phase.log" 2>&1
        grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$phase.log"
        if [[ "$phase" == curate ]]; then
            cp "$case_dir/dynamic.dbg" "$case_dir/first.dynamic.dbg"
            cp "$case_dir/dynamic.dbg.c" "$case_dir/first.dynamic.dbg.c"
        fi
    done
    cmp "$case_dir/dynamic.dbg" "$case_dir/first.dynamic.dbg"
    cmp "$case_dir/dynamic.dbg.c" "$case_dir/first.dynamic.dbg.c"
    python3 "$repository/src/test/integration/dynamic-parameter-storage-check.py" \
        observations "$case_dir" "$repository" "$module" "$target"
    for view in header sections notes info abbrev aranges decodedline loc Ranges; do
        case "$view" in
            header) option=-h ;; sections) option=-SW ;; notes) option=-n ;;
            *) option="--debug-dump=$view" ;;
        esac
        readelf "$option" "$case_dir/dynamic.dbg" >"$case_dir/forge-$view.stdout" 2>"$case_dir/forge-$view.stderr"
        test ! -s "$case_dir/forge-$view.stderr"
    done
    llvm-dwarfdump --verify "$case_dir/dynamic.dbg" >"$case_dir/llvm.stdout" 2>"$case_dir/llvm.stderr"
    test ! -s "$case_dir/llvm.stderr"
    grep -Fq 'No errors.' "$case_dir/llvm.stdout"
    python3 "$repository/src/test/integration/check-dwarfdump.py" "$case_dir/dynamic.dbg" \
        "$case_dir/strict.log" --original "$case_dir/dynamic.stripped"
    for variant in compiler forge; do
        input="$case_dir/dynamic.reference"; symbols="$input"; remote=; gdb_options=()
        if [[ "$variant" == forge ]]; then input="$case_dir/dynamic.stripped"; symbols="$case_dir/dynamic.dbg"; fi
        if [[ -n "$emulator" ]]; then
            qemu_socket_start "$case_dir/$variant.qemu" "$emulator" "$sysroot" "$input"
            remote="$qemu_socket_path"; gdb_options=(-ex "set sysroot $sysroot")
        fi
        FORGE_DYNAMIC_CASE="$case_dir" FORGE_DYNAMIC_VARIANT="$variant" FORGE_DYNAMIC_REMOTE="$remote" \
            timeout 90s gdb-multiarch -q -nx -batch \
            -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
            -ex 'set auto-solib-add off' -ex 'set disable-randomization off' \
            -ex "set debug-file-directory $case_dir/empty-debug" "${gdb_options[@]}" \
            -ex "file $input" -ex "symbol-file $symbols" \
            -x "$repository/src/test/integration/dynamic-parameter-storage-gdb.py" \
            >"$case_dir/$variant-gdb.stdout" 2>"$case_dir/$variant-gdb.stderr"
        grep -Fq "dynamic-parameter-storage-gdb=$variant PASS" "$case_dir/$variant-gdb.stdout"
        if [[ -n "$emulator" ]]; then qemu_socket_wait; fi
    done
    python3 "$repository/src/test/integration/dynamic-parameter-storage-check.py" \
        finish "$case_dir" "$repository" "$module" "$target"
    set +x
    unset BASH_XTRACEFD
    exec 9>&-
done
