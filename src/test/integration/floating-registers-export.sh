#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
if [[ $# -lt 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp> [target ...]" >&2
    exit 64
fi
ghidra=$(realpath "$1")
consumer=$(realpath "$2")
producer=$(realpath "$3")
shift 3
abi_profile=${FORGE_FP_ABI_PROFILE:-default}
if [[ "$abi_profile" != default && "$abi_profile" != mips-fp32 ]]; then
    echo 'FORGE_FP_ABI_PROFILE must be default or mips-fp32' >&2
    exit 64
fi
export FORGE_FP_ABI_PROFILE="$abi_profile"
storage_form=${FORGE_FP_STORAGE_FORM:-register-alias}
if [[ "$storage_form" != register-alias && "$storage_form" != explicit-pieces ]] ||
        [[ "$storage_form" == explicit-pieces && "$abi_profile" != mips-fp32 ]]; then
    echo 'FORGE_FP_STORAGE_FORM must be register-alias, or explicit-pieces with mips-fp32' >&2
    exit 64
fi
export FORGE_FP_STORAGE_FORM="$storage_form"
targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then
    if [[ "$abi_profile" == mips-fp32 ]]; then targets=(mips32be mips32le)
    else targets=(x86_64 aarch64 mips32be mips32le); fi
fi
if [[ "$abi_profile" == mips-fp32 ]]; then
    for target in "${targets[@]}"; do
        if [[ "$target" != mips32be && "$target" != mips32le ]]; then
            echo 'mips-fp32 requires MIPS32 target fixtures' >&2
            exit 64
        fi
    done
fi
repository=$(realpath "$(dirname "$0")/../../..")
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
root="$repository/build/test-results/floating-registers"
if [[ "$abi_profile" == mips-fp32 ]]; then root+="-fp32"; fi
if [[ "$storage_form" == explicit-pieces ]]; then root+="-pieces"; fi
mkdir -p "$root"
results=$(mktemp -d "$root/run.XXXXXXXX")
projects=$(mktemp -d /tmp/forge-floating-registers.XXXXXXXX)
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
echo "floating-register-results=$results"
snapshot_fp32_inputs() {
    python3 - "$repository" "$ghidra" "$consumer" "$producer" "$results" "$1" <<'PYTHON'
import hashlib
import json
from pathlib import Path
import sys
repository, ghidra, consumer, producer, results = map(Path, sys.argv[1:6])
phase = sys.argv[6]
files = [consumer, producer] + [repository / name for name in (
    'src/test/fixtures/fp_register_aliases.c',
    'src/test/integration/floating-registers-export.sh',
    'src/test/integration/floating-registers-gdb.py',
    'src/test/integration/check-fp32-register-pieces.py',
    'src/test/integration/ghidra_scripts/PrepareFloatingRegisters.java',
    'src/test/integration/ghidra_scripts/RebaseFixtureProgram.java')]
files += [p for p in (ghidra / 'Ghidra/Extensions/GhidraDwarfForge').rglob('*') if p.is_file()]
snapshot = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
(results / ('protected-' + phase + '.json')).write_text(json.dumps(snapshot, indent=4) + '\n')
if phase == 'after':
    assert snapshot == json.loads((results / 'protected-before.json').read_text())
PYTHON
}
if [[ "$abi_profile" == mips-fp32 ]]; then snapshot_fp32_inputs before; fi
run_gdb() {
    local executable=$1 sidecar=$2 mode=$3 log=$4
    local options=() remote=
    if [[ -n "$sidecar" ]]; then options=(-ex "symbol-file \"$sidecar\""); fi
    if [[ -n "$emulator" ]]; then
        "$emulator" -L "$sysroot" -g "$port" "$executable" >"$log.emulator" 2>&1 &
        emulator_pid=$!
        remote=$port
        options+=(-ex "set sysroot $sysroot")
        sleep 0.2
    fi
    FORGE_FP_LABELS="$case_root/labels.txt" FORGE_FP_MODE="$mode" \
        FORGE_FP_TARGET="$target" FORGE_FP_REMOTE="$remote" \
        timeout 45s gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' -ex "file \"$executable\"" "${options[@]}" \
        -x "$repository/src/test/integration/floating-registers-gdb.py" >"$log" 2>&1
    if [[ -n "$emulator_pid" ]]; then wait "$emulator_pid"; emulator_pid=; fi
    local oracle="$case_root/compiler-gdb.txt" diagnostics="$log.diagnostics"
    if [[ "$mode" == compiler ]]; then oracle=$log; fi
    if [[ "$target" == mips* && "$role" == pie && -n "$sidecar" ]]; then
        # This exact GDB 15.1 return-unwind warning also occurs with the
        # untouched compiler ELF as separate symbols. Require its exact text,
        # address and count within the same return operation; other warnings
        # remain fatal. The direct compiler-symbol run stays strict.
        oracle="$case_root/compiler-separate-gdb.txt"
        awk '
            /FP_RETURN_BEGIN/ { returning = 1 }
            /FP_RETURN_END/ { returning = 0 }
            NR == FNR {
                if (returning && $0 ~ /^warning: GDB can\047t find the start of the function at 0x[[:xdigit:]]+\.$/) {
                    known[$0]++
                }
                next
            }
            returning && known[$0] > 0 { known[$0]--; next }
            { print }
        ' "$oracle" "$log" >"$diagnostics"
    else
        cp "$log" "$diagnostics"
    fi
    layout_validate_gdb_diagnostics "$diagnostics" "$executable" floating "$target" "$oracle"
    grep -Fxq "floating-registers-gdb=$mode PASS" "$log"
}
for target in "${targets[@]}"; do
    emulator= sysroot= extra=()
    case "$target" in
        x86_64) cc=gcc; strip_tool=strip; extra=(-fcf-protection=none) ;;
        aarch64) cc=aarch64-linux-gnu-gcc; strip_tool=aarch64-linux-gnu-strip
            emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
        arm32) cc=arm-linux-gnueabihf-gcc; strip_tool=arm-linux-gnueabihf-strip
            emulator=qemu-arm-static; sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf}
            extra=(-march=armv7-a -marm -mfpu=vfpv3-d16) ;;
        mips32be) cc=mips-linux-gnu-gcc; strip_tool=mips-linux-gnu-strip
            emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
        mips32le) cc=mipsel-linux-gnu-gcc; strip_tool=mipsel-linux-gnu-strip
            emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
        *) echo "unsupported floating fixture target: $target" >&2; exit 64 ;;
    esac
    if [[ "$abi_profile" == mips-fp32 ]]; then extra+=(-mfp32); fi
    roles=(exec pie)
    samples=(baseline rebased repeat)
    if [[ ${FORGE_FP_BASELINE:-0} == 1 ]]; then roles=(exec); samples=(baseline); fi
    for role in "${roles[@]}"; do
        case_root="$results/$target/$role"
        mkdir -p "$case_root/artifacts"
        reference="$case_root/floating.reference"
        input="$case_root/floating.stripped"
        output="$case_root/artifacts/floating.dbg"
        flags=(-fno-pie -no-pie)
        if [[ "$role" == pie ]]; then flags=(-fPIE -pie); fi
        "$cc" -Og -g -gdwarf-5 -fasynchronous-unwind-tables "${extra[@]}" "${flags[@]}" \
            -Wl,--build-id=sha1 "$repository/src/test/fixtures/fp_register_aliases.c" -o "$reference"
        cp "$reference" "$input"
        "$strip_tool" --strip-all "$input"
        readelf -Ws "$reference" >"$case_root/reference-symbols.txt"
        awk '$8 ~ /^fp_/ { print $8, "0x" $2 }' "$case_root/reference-symbols.txt" \
            | LC_ALL=C sort -u >"$case_root/labels.txt"
        readelf -hSWnA "$input" >"$case_root/input-elf.txt"
        if [[ "$abi_profile" == mips-fp32 ]]; then
            grep -Fq 'Tag_GNU_MIPS_ABI_FP: Hard float (double precision)' "$case_root/input-elf.txt"
            grep -Fxq 'CPR1 size: 32' "$case_root/input-elf.txt"
            grep -Fxq 'FP ABI: Hard float (double precision)' "$case_root/input-elf.txt"
        fi
        if grep -Eq '[[:space:]][.](debug_|symtab)' "$case_root/input-elf.txt"; then exit 1; fi
        sha256sum "$input" >"$case_root/input.sha256"
        run_gdb "$reference" "" compiler "$case_root/compiler-gdb.txt"
        if [[ "$abi_profile" == mips-fp32 ]]; then
            [[ $(grep -c '^compiler-fp32-double-location=PASS ' "$case_root/compiler-gdb.txt") == 6 ]]
            if grep -Fq 'UNVERIFIED' "$case_root/compiler-gdb.txt"; then exit 1; fi
        fi
        if [[ "$target" == mips* && "$role" == pie ]]; then
            run_gdb "$input" "$reference" compiler-separate "$case_root/compiler-separate-gdb.txt"
        fi
        for sample in "${samples[@]}"; do
            case_dir="$case_root/$sample"
            mkdir -p "$case_dir"
            rebase=()
            if [[ "$sample" == rebased ]]; then
                rebase=(-postScript RebaseFixtureProgram.java 0x2000000)
            fi
            "$ghidra/support/analyzeHeadless" "$projects" "FP_${target}_${role}_${sample}" \
                -deleteProject -import "$input" -analysisTimeoutPerFile 120 \
                -scriptPath "$repository/src/test/integration/ghidra_scripts" "${rebase[@]}" \
                -postScript PrepareFloatingRegisters.java "$target" "$case_root/labels.txt" \
                -postScript GhidraDwarfForge.java "--libdwarf=$consumer" "--libdwarfp=$producer" \
                "--output=$output" >"$case_dir/headless.txt" 2>&1
            grep -Fq 'floating-register-preparation=PASS' "$case_dir/headless.txt"
            if [[ "$abi_profile" == mips-fp32 ]]; then
                python3 - "$case_dir/headless.txt" "$ghidra" <<'PYTHON'
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit
log, ghidra = map(Path, sys.argv[1:])
origin, = re.findall(r'floating-storage-origin=(\S+)', log.read_text())
assert Path(unquote(urlsplit(origin).path)).resolve() == (ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar').resolve()
PYTHON
            fi
            grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/headless.txt"
            if [[ "$sample" == rebased ]]; then
                grep -Eq 'Rebased fixture image from .* by 0x2000000 ' "$case_dir/headless.txt"
            fi
            if [[ "$target" == mips* ]]; then
                if [[ "$storage_form" == explicit-pieces ]]; then
                    grep -Fq 'floating-fp32-pieces=first ' "$case_dir/headless.txt"
                    grep -Fq 'floating-fp32-pieces=second ' "$case_dir/headless.txt"
                    if grep -Fq 'Omitted location for fp_double::' "$case_dir/headless.txt"; then exit 1; fi
                else
                    grep -Fq 'Omitted location for fp_double::first' "$case_dir/headless.txt"
                    grep -Fq 'no audited DWARF mapping for Ghidra register f12_13' "$case_dir/headless.txt"
                fi
            fi
            if [[ "$target" == arm32 ]]; then
                grep -Fq 'floating-register-arm-opaque-return=PASS' "$case_dir/headless.txt"
                grep -Fq 'Limited location to proven incoming-register lifetime for fp_clobbered::value:' \
                    "$case_dir/headless.txt"
                python3 - "$case_dir/headless.txt" "$case_root/labels.txt" <<'PY'
import json
import pathlib
import sys

reports = [json.loads(line[line.index('{'):line.rindex('}') + 1])
    for line in pathlib.Path(sys.argv[1]).read_text().splitlines()
    if 'GhidraDwarfForge report:' in line]
assert len(reports) == 1, 'expected one exporter report'
entries = [item for item in reports[0]['omittedLocations']
    if item['function'] == 'fp_clobbered' and item['variable'] == 'value']
assert len(entries) == 1 and entries[0]['reason'] == 'REGISTER_MODIFIED', entries
labels = {name: int(address, 16) for name, address in
    (line.split() for line in pathlib.Path(sys.argv[2]).read_text().splitlines())}
assert int(entries[0]['startAddress'], 16) == labels['fp_clobber_after'], entries
assert int(entries[0]['endAddress'], 16) > labels['fp_clobber_after'], entries
PY
            fi
            readelf -hSWn "$output" >"$case_dir/elf.txt" 2>"$case_dir/readelf.stderr"
            for kind in info abbrev aranges decodedline Ranges loc; do
                readelf "--debug-dump=$kind" "$output" >"$case_dir/$kind.txt" 2>>"$case_dir/readelf.stderr"
            done
            test ! -s "$case_dir/readelf.stderr"
            if [[ "$storage_form" == explicit-pieces ]]; then
                python3 "$repository/src/test/integration/check-fp32-register-pieces.py" \
                    "$output" "$target" > "$case_dir/fp32-pieces.json"
            fi
            llvm-dwarfdump --verify "$output" >"$case_dir/llvm.txt" 2>&1
            python3 "$repository/src/test/integration/check-dwarfdump.py" \
                "$output" "$case_dir/dwarfdump.txt" --original "$input"
            diff <(awk '/Build ID:/ {print $3}' "$case_root/input-elf.txt") \
                <(awk '/Build ID:/ {print $3}' "$case_dir/elf.txt")
            run_gdb "$input" "$output" forge "$case_dir/gdb.txt"
            sha256sum -c "$case_root/input.sha256" >"$case_dir/input-preservation.txt"
            cp "$output" "$case_dir/floating.dbg"
            cp "$output.c" "$case_dir/floating.dbg.c"
            echo "floating-register-case=$target/$role/$sample PASS" | tee "$case_dir/result.txt"
        done
        if [[ ${FORGE_FP_BASELINE:-0} != 1 ]]; then
            cmp "$case_root/baseline/floating.dbg" "$case_root/repeat/floating.dbg"
            cmp "$case_root/baseline/floating.dbg.c" "$case_root/repeat/floating.dbg.c"
        fi
    done
done
if [[ "$abi_profile" == mips-fp32 ]]; then snapshot_fp32_inputs after; fi
echo 'floating-registers-export=PASS'
