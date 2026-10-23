#!/usr/bin/env bash
set -euo pipefail

# Real Ghidra extraction + value-based GDB checks for four-byte integer bit
# fields with one-byte component storage. Linux cross-toolchains/QEMU are used
# for non-native targets. No compiler debug information is imported into Ghidra.
if [[ $# -lt 1 ]]; then
    echo "usage: $0 <ghidra-dir-with-packaged-natives> [x86_64 aarch64 arm32 mips32be mips32le ...]" >&2
    exit 64
fi
export LC_ALL=C
repository_dir=$(realpath "$(dirname "$0")/../../..")
ghidra_dir=$(realpath "$1")
shift
targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then
    targets=(x86_64 mips32be)
fi
result_root="$repository_dir/build/test-results/bitfield-values"
mkdir -p "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
emulator_pid=
cleanup() {
    if [[ -n "$emulator_pid" ]]; then
        kill "$emulator_pid" 2>/dev/null || true
        wait "$emulator_pid" 2>/dev/null || true
    fi
    echo "bitfield-values results: $result_dir"
}
trap cleanup EXIT
port=$((27000 + ($$ % 10000)))

symbol_address() {
    readelf -Ws "$1" | awk -v symbol="$2" '$8 == symbol { print "0x" $2; exit }'
}

run_gdb() {
    local executable=$1 sidecar=$2 log=$3
    local load_symbols=() run_command=(-ex run)
    if [[ -n "$sidecar" ]]; then
        load_symbols=(-ex "symbol-file \"$sidecar\"")
    fi
    if [[ -n "$emulator" ]]; then
        "$emulator" -L "$sysroot" -g "$port" "$executable" \
            > "$log.emulator" 2>&1 &
        emulator_pid=$!
        sleep 0.2
        run_command=(-ex "set sysroot $sysroot" -ex "target remote :$port" -ex continue)
    fi
    timeout 45 gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' \
        -ex "directory $(dirname "$log")" \
        -ex "file $executable" "${load_symbols[@]}" \
        -ex 'ptype word_value' -ex 'ptype byte_value' \
        -ex 'break inspect_flags' "${run_command[@]}" \
        -ex 'printf "word={a=%u,b=%u}\n", word_value.a, word_value.b' \
        -ex 'printf "byte={a=%u,b=%u}\n", byte_value.a, byte_value.b' \
        -ex 'print sizeof(word_value)' -ex 'print sizeof(byte_value)' \
        -ex continue > "$log" 2> "$log.stderr"
    if [[ -n "$emulator_pid" ]]; then
        wait "$emulator_pid"
        emulator_pid=
    fi
    if [[ -s "$log.stderr" ]]; then
        # Some QEMU AArch64/GDB combinations diagnose QEMU's synthetic vDSO even
        # with the original compiler DWARF. Retain it, and only accept the exact
        # known diagnostic when the independent compiler oracle agrees.
        local vdso_warning='^warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index$'
        if [[ "$target" != aarch64 ]] || grep -Ev "$vdso_warning" "$log.stderr" ||
                { [[ -n "$sidecar" ]] &&
                    ! grep -Eq "$vdso_warning" "$(dirname "$log")/compiler-gdb.txt.stderr"; }; then
            cat "$log.stderr" >&2
            return 1
        fi
        echo 'Known QEMU vDSO warning also present in the compiler oracle' \
            >> "$log"
    fi
    grep -Fxq 'word={a=5,b=17}' "$log"
    grep -Fxq 'byte={a=5,b=17}' "$log"
    grep -Fxq '$1 = 4' "$log"
    grep -Fxq '$2 = 1' "$log"
    grep -Fq 'exited normally' "$log"
}

for target in "${targets[@]}"; do
    compiler= strip_tool= emulator= sysroot=
    compile_flags=()
    case "$target" in
        x86_64) compiler=gcc; strip_tool=strip ;;
        aarch64)
            compiler=aarch64-linux-gnu-gcc; strip_tool=aarch64-linux-gnu-strip
            emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
        arm32)
            compiler=arm-linux-gnueabihf-gcc; strip_tool=arm-linux-gnueabihf-strip
            emulator=qemu-arm-static; sysroot=/usr/arm-linux-gnueabihf
            compile_flags=(-march=armv7-a -marm -mfpu=vfpv3-d16) ;;
        mips32be)
            compiler=mips-linux-gnu-gcc; strip_tool=mips-linux-gnu-strip
            emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
        mips32le)
            compiler=mipsel-linux-gnu-gcc; strip_tool=mipsel-linux-gnu-strip
            emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
        *) echo "unsupported fixture target: $target" >&2; exit 64 ;;
    esac
    case_dir="$result_dir/$target"
    mkdir -p "$case_dir/project"
    reference="$case_dir/bitfield.reference"
    input="$case_dir/bitfield.stripped"
    output="$case_dir/bitfield.dbg"
    "$compiler" "${compile_flags[@]}" -O0 -g -gdwarf-5 -fno-pie -no-pie \
        "$repository_dir/src/test/fixtures/bitfield-values.c" -o "$reference"
    cp "$reference" "$input"
    "$strip_tool" --strip-all "$input"
    sha256sum "$input" > "$case_dir/input.sha256"
    run_gdb "$reference" "" "$case_dir/compiler-gdb.txt"
    inspect_address=$(symbol_address "$reference" inspect_flags)
    word_address=$(symbol_address "$reference" word_value)
    byte_address=$(symbol_address "$reference" byte_value)
    test -n "$inspect_address"
    test -n "$word_address"
    test -n "$byte_address"
    "$ghidra_dir/support/analyzeHeadless" "$case_dir/project" BitFieldValues \
        -deleteProject -import "$input" -analysisTimeoutPerFile 120 \
        -scriptPath "$repository_dir/src/test/integration/ghidra_scripts" \
        -postScript ApplyBitFieldFixture.java "$inspect_address" "$word_address" "$byte_address" \
        -postScript GhidraDwarfForge.java --packaged-natives "--output=$output" \
        > "$case_dir/export.log" 2>&1
    grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export.log"
    grep -Fq 'storage=1 base=4' "$case_dir/export.log"
    sha256sum -c "$case_dir/input.sha256" > "$case_dir/input-preservation.txt"
    readelf -h -SW -n "$output" > "$case_dir/elf.txt" 2> "$case_dir/readelf.stderr"
    for dump in info abbrev aranges decodedline Ranges loc; do
        readelf "--debug-dump=$dump" "$output" > "$case_dir/$dump.txt" \
            2>> "$case_dir/readelf.stderr"
    done
    test ! -s "$case_dir/readelf.stderr"
    llvm-dwarfdump --verify "$output" > "$case_dir/llvm.txt" 2>&1
    dwarfdump -ka -ks "$output" > "$case_dir/dwarfdump.txt" 2>&1
    if grep -Ei '(^|[[:space:]])(warning|error):' \
            "$case_dir/llvm.txt" "$case_dir/dwarfdump.txt"; then
        echo "bit-field validator reported a warning or error" >&2
        exit 1
    fi
    run_gdb "$input" "$output" "$case_dir/forge-gdb.txt"
    awk '
        function finish_member() {
            if (member && bits) {
                count++
                if (!bit_offset || byte_offset) bad = 1
            }
        }
        /DW_TAG_/ {
            finish_member()
            member = /DW_TAG_member/
            bits = bit_offset = byte_offset = 0
        }
        /DW_AT_bit_size/ { bits = 1 }
        /DW_AT_data_bit_offset/ { bit_offset = 1 }
        /DW_AT_data_member_location/ { byte_offset = 1 }
        END { finish_member(); exit bad || count != 4 }
    ' "$case_dir/info.txt"
    sha256sum -c "$case_dir/input.sha256" > "$case_dir/input-preservation.txt"
    echo "bitfield-values-$target=PASS"
done

echo 'bitfield-values=PASS'
