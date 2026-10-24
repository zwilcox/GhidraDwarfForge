#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
if [[ $# -lt 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp> [x86_64 aarch64 ...]" >&2
    exit 2
fi
ghidra=$(realpath "$1")
consumer=$(realpath "$2")
producer=$(realpath "$3")
shift 3
targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then targets=(x86_64 aarch64); fi
repository=$(realpath "$(dirname "$0")/../../..")
root="$repository/build/test-results/register-prefix-export"
mkdir -p "$root"
results=$(mktemp -d "$root/run.XXXXXXXX")
projects=$(mktemp -d /tmp/forge-register-prefix.XXXXXXXX)
emulator_pid=
cleanup() {
    if [[ -n "$emulator_pid" ]]; then
        kill "$emulator_pid" 2>/dev/null || true
        wait "$emulator_pid" 2>/dev/null || true
    fi
    rm -rf -- "$projects"
}
trap cleanup EXIT
port=$((28000 + $$ % 10000))
echo "register-prefix-results=$results"

run_gdb() {
    local executable=$1 sidecar=$2 mode=$3 log=$4
    local options=() remote=
    if [[ -n "$sidecar" ]]; then options=(-ex "symbol-file \"$sidecar\""); fi
    if [[ "$target" == aarch64 ]]; then
        qemu-aarch64-static -L /usr/aarch64-linux-gnu -g "$port" "$executable" \
            >"$log.qemu" 2>&1 &
        emulator_pid=$!
        remote=$port
        options+=(-ex 'set sysroot /usr/aarch64-linux-gnu')
        sleep 0.2
    fi
    FORGE_PREFIX_LABELS="$case_root/labels.txt" FORGE_PREFIX_MODE="$mode" \
        FORGE_PREFIX_REMOTE="$remote" timeout 45s gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' -ex "file \"$executable\"" "${options[@]}" \
        -x "$repository/src/test/integration/register-prefix-gdb.py" \
        >"$log" 2>"$log.stderr"
    if [[ -n "$emulator_pid" ]]; then wait "$emulator_pid"; emulator_pid=; fi
    if [[ -s "$log.stderr" ]]; then
        local vdso='^warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index$'
        if [[ "$target" != aarch64 ]] || grep -Ev "$vdso" "$log.stderr" ||
                { [[ "$mode" != compiler ]] &&
                    ! grep -Eq "$vdso" "$case_root/compiler-gdb.txt.stderr"; }; then
            cat "$log.stderr" >&2
            return 1
        fi
    fi
    grep -Fxq "register-prefix-gdb=$mode PASS" "$log"
}

for target in "${targets[@]}"; do
    case "$target" in
        x86_64) cc=gcc; objcopy=objcopy; register=EDI; return_bytes=1
            extra=(-fcf-protection=none) ;;
        aarch64) cc=aarch64-linux-gnu-gcc; objcopy=aarch64-linux-gnu-objcopy
            register=w0; return_bytes=4; extra=() ;;
        *) echo "unsupported prefix fixture target $target" >&2; exit 2 ;;
    esac
    for role in exec pie; do
        case_root="$results/$target/$role"
        mkdir -p "$case_root/artifacts"
        flags=(-fno-pie -no-pie)
        if [[ "$role" == pie ]]; then flags=(-fPIE -pie); fi
        reference="$case_root/prefix.reference"
        input="$case_root/prefix.stripped"
        output="$case_root/artifacts/prefix.dbg"
        "$cc" -Og -g -gdwarf-5 "${extra[@]}" "${flags[@]}" -Wl,--build-id=sha1 \
            "$repository/src/test/fixtures/register_prefix.c" -o "$reference"
        "$objcopy" --strip-all "$reference" "$input"
        readelf -Ws "$reference" >"$case_root/reference-symbols.txt"
        readelf -hSWn "$input" >"$case_root/input-elf.txt"
        if grep -Eq '[[:space:]][.](debug_|symtab)' "$case_root/input-elf.txt"; then exit 1; fi
        : >"$case_root/labels.txt"
        for symbol in prefix_value prefix_before prefix_write prefix_after prefix_sink; do
            address=$(awk -v name="$symbol" '$8 == name {print "0x" $2}' "$case_root/reference-symbols.txt")
            test -n "$address"
            printf '%s 0x%x\n' "$symbol" "$((address))" >>"$case_root/labels.txt"
        done
        entry=$(awk '$1 == "prefix_value" { print $2 }' "$case_root/labels.txt")
        sink=$(awk '$1 == "prefix_sink" { print $2 }' "$case_root/labels.txt")
        size=$(awk '$8 == "prefix_value" { print $3 }' "$case_root/reference-symbols.txt")
        printf 'prefix_return 0x%x\n' "$((entry + size - return_bytes))" >>"$case_root/labels.txt"
        sha256sum "$input" >"$case_root/input.sha256"
        run_gdb "$reference" "" compiler "$case_root/compiler-gdb.txt"
        for name in baseline rebased repeat; do
            sample="$case_root/$name"
            mkdir -p "$sample"
            rebase=()
            if [[ "$name" == rebased ]]; then
                rebase=(-postScript RebaseFixtureProgram.java 0x2000000)
            fi
            "$ghidra/support/analyzeHeadless" "$projects" "Prefix_${target}_${role}_${name}" \
                -deleteProject -import "$input" -analysisTimeoutPerFile 120 \
                -scriptPath "$repository/src/test/integration/ghidra_scripts" "${rebase[@]}" \
                -postScript PrepareRegisterPrefix.java "$entry" "$sink" "$register" \
                -postScript GhidraDwarfForge.java "--libdwarf=$consumer" "--libdwarfp=$producer" \
                "--output=$output" >"$sample/headless.txt" 2>&1
            grep -Fq 'register-prefix-preparation=PASS' "$sample/headless.txt"
            grep -Fq 'GhidraDwarfForge symbol export PASS' "$sample/headless.txt"
            grep -Fq 'Limited location to proven incoming-register lifetime for prefix_value::value' \
                "$sample/headless.txt"
            if [[ "$name" == rebased ]]; then
                grep -Eq 'Rebased fixture image from .* by 0x2000000 ' "$sample/headless.txt"
            fi
            readelf -hSWn "$output" >"$sample/elf.txt" 2>"$sample/readelf.stderr"
            for kind in info abbrev aranges decodedline Ranges loc; do
                readelf "--debug-dump=$kind" "$output" >"$sample/$kind.txt" 2>>"$sample/readelf.stderr"
            done
            test ! -s "$sample/readelf.stderr"
            llvm-dwarfdump --verify "$output" >"$sample/llvm.txt" 2>&1
            dwarfdump -ka -ks "$output" >"$sample/dwarfdump.txt" 2>&1
            diff <(awk '/Build ID:/ {print $3}' "$case_root/input-elf.txt") \
                <(awk '/Build ID:/ {print $3}' "$sample/elf.txt")
            run_gdb "$input" "$output" forge "$sample/gdb.txt"
            sha256sum -c "$case_root/input.sha256" >"$sample/input-preservation.txt"
            cp "$output" "$sample/prefix.dbg"
            cp "$output.c" "$sample/prefix.dbg.c"
            printf 'register-prefix-case=%s/%s/%s PASS\n' "$target" "$role" "$name" | tee "$sample/result.txt"
        done
        cmp "$case_root/baseline/prefix.dbg" "$case_root/repeat/prefix.dbg"
        cmp "$case_root/baseline/prefix.dbg.c" "$case_root/repeat/prefix.dbg.c"
    done
done
echo 'register-prefix-export=PASS'
