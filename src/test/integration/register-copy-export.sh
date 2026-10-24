#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
if [[ $# -lt 1 ]]; then
    echo "usage: $0 <ghidra-dir-with-packaged-natives> [x86_64 aarch64]" >&2
    exit 64
fi
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
shift
targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then targets=(x86_64 aarch64); fi
root="$repository/build/test-results/register-copy"
mkdir -p "$root"
results=$(mktemp -d "$root/run.XXXXXXXX")
source "$repository/src/test/integration/qemu-socket.sh"
cleanup() {
    qemu_socket_cleanup
    echo "register-copy-results=$results"
}
trap cleanup EXIT
echo "register-copy-results=$results"
sha256sum "$repository/src/test/fixtures/register-copy.c" \
    "$ghidra/Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar" \
    > "$results/source-and-exporter.sha256"

run_gdb() {
    local symbols=$1 mode=$2 log=$3 remote=
    local options=()
    if [[ "$target" == aarch64 ]]; then
        qemu_socket_start "$log.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$input"
        remote=$qemu_socket_path
        options+=(-ex 'set sysroot /usr/aarch64-linux-gnu')
    fi
    FORGE_COPY_LABELS="$case_dir/labels.json" FORGE_COPY_MODE="$mode" \
        FORGE_COPY_TARGET="$target" FORGE_COPY_REMOTE="$remote" \
        timeout 90s gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' "${options[@]}" \
        -ex "file \"$input\"" -ex "symbol-file \"$symbols\"" \
        -x "$repository/src/test/integration/register-copy-gdb.py" \
        > "$log" 2> "$log.stderr"
    grep -Fxq "register-copy-gdb=$mode PASS" "$log"
    grep -Fq 'exited normally' "$log"
    if [[ -n "$remote" ]]; then qemu_socket_wait; fi
    python3 - "$log.stderr" "$case_dir/compiler-gdb.txt.stderr" "$target" "$mode" <<'PY'
from collections import Counter
from pathlib import Path
import re
import sys

actual = Path(sys.argv[1]).read_text().splitlines()
if sys.argv[3] == 'x86_64':
    assert not actual, actual
else:
    pattern = r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index'
    assert all(re.fullmatch(pattern, line) for line in actual), actual
    if sys.argv[4] == 'forge':
        assert Counter(actual) == Counter(Path(sys.argv[2]).read_text().splitlines()), actual
PY
}

for target in "${targets[@]}"; do
    case "$target" in
        x86_64) cc=gcc; objcopy=objcopy; objdump=objdump; extra=(-fcf-protection=none) ;;
        aarch64) cc=aarch64-linux-gnu-gcc; objcopy=aarch64-linux-gnu-objcopy
            objdump=aarch64-linux-gnu-objdump; extra=() ;;
        *) echo "unsupported copy fixture target: $target" >&2; exit 64 ;;
    esac
    for role in exec pie pie-rebased; do
        case_dir="$results/$target/$role"
        mkdir -p "$case_dir/project"
        reference="$case_dir/copy.reference"
        input="$case_dir/copy.stripped"
        output="$case_dir/copy.dbg"
        flags=(-fno-pie -no-pie)
        rebase=()
        if [[ "$role" != exec ]]; then flags=(-fPIE -pie); fi
        if [[ "$role" == pie-rebased ]]; then
            rebase=(-postScript RebaseFixtureProgram.java 0x2000000)
        fi
        "$cc" -Og -g -gdwarf-5 -fasynchronous-unwind-tables "${extra[@]}" "${flags[@]}" \
            -Wl,--build-id=sha1 "$repository/src/test/fixtures/register-copy.c" -o "$reference"
        "$objcopy" --strip-all "$reference" "$input"
        "$objdump" -d "$reference" > "$case_dir/reference-disassembly.txt"
        "$cc" --version > "$case_dir/compiler-version.txt"
        gdb-multiarch --version > "$case_dir/gdb-version.txt"
        readelf -Ws "$reference" > "$case_dir/symbols.txt"
        readelf -hSWn "$input" > "$case_dir/input-elf.txt" 2> "$case_dir/input-elf.stderr"
        test ! -s "$case_dir/input-elf.stderr"
        if grep -Eq '[[:space:]][.](debug_|symtab)' "$case_dir/input-elf.txt"; then exit 1; fi
        python3 - "$case_dir" "$target" <<'PY'
from pathlib import Path
import json
import sys

directory, target = Path(sys.argv[1]), sys.argv[2]
symbols = {}
for line in (directory / 'symbols.txt').read_text().splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7].startswith(('copy32_', 'copy64_')):
        assert fields[7] not in symbols
        symbols[fields[7]] = (int(fields[1], 16), int(fields[2]))
records, preparation = {}, []
for name in ['copy32_keep', 'copy32_kill', 'copy64_keep', 'copy64_kill']:
    entry, size = symbols[name]
    width = 8 if '64' in name else 4
    record = {'entry': entry, 'end': entry + size,
              'return': entry + size - (1 if target == 'x86_64' else 4)}
    markers = ['saved', 'write', 'after', 'sink']
    if name.endswith('_kill'):
        markers += ['kill', 'unavailable']
    record.update({marker: symbols[name + '_' + marker][0] for marker in markers})
    ordered = ['entry', 'saved', 'write', 'after']
    if name.endswith('_kill'):
        ordered += ['kill', 'unavailable']
    ordered += ['return', 'end']
    assert all(record[a] < record[b] for a, b in zip(ordered, ordered[1:])), record
    register = ('RDI' if width == 8 else 'EDI') if target == 'x86_64' else ('x0' if width == 8 else 'w0')
    preparation.append(' '.join([name, hex(entry), hex(entry + size), hex(record['sink']), str(width), register]))
    records[name] = record
(directory / 'labels.json').write_text(json.dumps(records, indent=4) + '\n')
(directory / 'preparation.txt').write_text('\n'.join(preparation) + '\n')
PY
        sha256sum "$reference" "$input" > "$case_dir/originals.sha256"
        llvm-dwarfdump --verify "$reference" > "$case_dir/compiler-llvm.txt" 2>&1
        run_gdb "$reference" compiler "$case_dir/compiler-gdb.txt"
        for iteration in first repeat; do
            "$ghidra/support/analyzeHeadless" "$case_dir/project" RegisterCopy \
                -deleteProject -import "$input" -loader ElfLoader -analysisTimeoutPerFile 120 \
                -scriptPath "$repository/src/test/integration/ghidra_scripts" "${rebase[@]}" \
                -postScript PrepareRegisterCopy.java "$case_dir/preparation.txt" \
                -postScript GhidraDwarfForge.java --packaged-natives "--output=$output" \
                > "$case_dir/export-$iteration.log" 2>&1
            grep -Fq 'register-copy-preparation=PASS' "$case_dir/export-$iteration.log"
            grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$iteration.log"
            if [[ "$role" == pie-rebased ]]; then
                grep -Eq 'Rebased fixture image from .* by 0x2000000 ' "$case_dir/export-$iteration.log"
            fi
            if [[ "$iteration" == first ]]; then
                cp "$output" "$case_dir/first.dbg"
                cp "$output.c" "$case_dir/first.dbg.c"
            else
                cmp "$output" "$case_dir/first.dbg"
                cmp "$output.c" "$case_dir/first.dbg.c"
            fi
            sha256sum -c "$case_dir/originals.sha256" > "$case_dir/input-preservation.txt"
        done
        readelf -hSWn "$output" > "$case_dir/elf.txt" 2> "$case_dir/readelf.stderr"
        for dump in info abbrev aranges decodedline Ranges loc; do
            readelf "--debug-dump=$dump" "$output" > "$case_dir/$dump.txt" \
                2>> "$case_dir/readelf.stderr"
        done
        test ! -s "$case_dir/readelf.stderr"
        python3 "$repository/src/test/integration/check-code-address-index.py" \
            "$output" --negative-controls > "$case_dir/address-index.json"
        python3 "$repository/src/test/integration/check-register-copy-locations.py" \
            "$output" "$case_dir/labels.json" "$target" > "$case_dir/copy-locations.json"
        llvm-dwarfdump --verify "$output" > "$case_dir/llvm.txt" 2> "$case_dir/llvm.stderr"
        test ! -s "$case_dir/llvm.stderr"
        if grep -Ei '(^|[[:space:]])(warning|error):' "$case_dir/llvm.txt"; then exit 1; fi
        python3 "$repository/src/test/integration/check-dwarfdump.py" \
            "$output" "$case_dir/dwarfdump.txt" --original "$input"
        diff <(awk '/Build ID:/ { print $3 }' "$case_dir/input-elf.txt") \
            <(awk '/Build ID:/ { print $3 }' "$case_dir/elf.txt")
        run_gdb "$output" forge "$case_dir/forge-gdb.txt"
        sha256sum -c "$case_dir/originals.sha256" > "$case_dir/input-preservation.txt"
        printf 'register-copy-case=%s/%s PASS\n' "$target" "$role" | tee "$case_dir/result.txt"
    done
done
sha256sum -c "$results/source-and-exporter.sha256" > "$results/exporter-preservation.txt"
echo 'register-copy-export=PASS' | tee "$results/result.txt"
