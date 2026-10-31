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
root="$repository/build/test-results/stack-local-definitions"
mkdir -p "$root"
results=$(mktemp -d "$root/run.XXXXXXXX")
source "$repository/src/test/integration/qemu-socket.sh"
cleanup() {
    qemu_socket_cleanup
    echo "stack-local-definitions-results=$results"
}
trap cleanup EXIT
echo "stack-local-definitions-results=$results"
sha256sum "$repository/src/test/fixtures/stack-local-definitions.c" \
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
    FORGE_STACK_LABELS="$case_dir/labels.json" FORGE_STACK_MODE="$mode" \
        FORGE_STACK_STORAGE="$case_dir/compiler-storage.json" \
        FORGE_STACK_REMOTE="$remote" \
        timeout 90s gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' "${options[@]}" \
        -ex "file \"$input\"" -ex "symbol-file \"$symbols\"" \
        -x "$repository/src/test/integration/stack-local-definitions-gdb.py" \
        > "$log" 2> "$log.stderr"
    grep -Fxq "stack-local-definitions-gdb=$mode PASS" "$log"
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
    if sys.argv[4] != 'compiler':
        assert Counter(actual) == Counter(Path(sys.argv[2]).read_text().splitlines()), actual
PY
}

for target in "${targets[@]}"; do
    case "$target" in
        x86_64) cc=gcc; objcopy=objcopy; objdump=objdump; extra=(-fcf-protection=none) ;;
        aarch64) cc=aarch64-linux-gnu-gcc; objcopy=aarch64-linux-gnu-objcopy
            objdump=aarch64-linux-gnu-objdump; extra=() ;;
        *) echo "unsupported stack fixture target: $target" >&2; exit 64 ;;
    esac
    for width in ${FORGE_STACK_LOCAL_WIDTHS:-32 64}; do
        case "$width" in 32|64) ;; *) echo "unsupported local width: $width" >&2; exit 64 ;; esac
        for role in ${FORGE_STACK_LOCAL_ROLES:-exec pie pie-rebased}; do
            case_dir="$results/$target/$width/$role"
            mkdir -p "$case_dir/project"
            reference="$case_dir/stack.reference"
            input="$case_dir/stack.stripped"
            output="$case_dir/stack.dbg"
            flags=(-fno-pie -no-pie)
            rebase=()
            if [[ "$role" != exec ]]; then flags=(-fPIE -pie); fi
            if [[ "$role" == pie-rebased ]]; then
                rebase=(-postScript RebaseFixtureProgram.java 0x2000000)
            fi
            "$cc" -DFORGE_STACK_LOCAL_BITS="$width" -O2 -g -gdwarf-5 -fno-stack-protector -fasynchronous-unwind-tables "${extra[@]}" "${flags[@]}" \
                -Wl,--build-id=sha1 "$repository/src/test/fixtures/stack-local-definitions.c" -o "$reference"
            "$objcopy" --strip-all "$reference" "$input"
            "$objdump" -d "$reference" > "$case_dir/reference-disassembly.txt"
            "$cc" --version > "$case_dir/compiler-version.txt"
            gdb-multiarch --version > "$case_dir/gdb-version.txt"
            readelf -Ws "$reference" > "$case_dir/symbols.txt"
            readelf -hSWn "$input" > "$case_dir/input-elf.txt" 2> "$case_dir/input-elf.stderr"
            test ! -s "$case_dir/input-elf.stderr"
            if grep -Eq '[[:space:]][.](debug_|symtab)' "$case_dir/input-elf.txt"; then exit 1; fi
            python3 - "$case_dir" "$target" "$width" <<'PY'
from pathlib import Path
import json
import sys

directory, target = Path(sys.argv[1]), sys.argv[2]
wanted = {'stack_scope', 'zero_stack', 'scope_sink', 'zero_sink',
          'first_live', 'between_scopes', 'second_live', 'after_scopes', 'zero_live'}
symbols = {}
for line in (directory / 'symbols.txt').read_text().splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in wanted:
        assert fields[7] not in symbols
        symbols[fields[7]] = (int(fields[1], 16), int(fields[2]))
assert set(symbols) == wanted, symbols
width = int(sys.argv[3])
assert width in (32, 64)
records = {'width': width // 8,
           'first_value': -1985229329 if width == 32 else -81985529216486895,
           'second_value': 305419896 if width == 32 else 81985529216486895}
for name, markers in [('stack_scope', ['first_live', 'between_scopes', 'second_live', 'after_scopes']),
                      ('zero_stack', ['zero_live'])]:
    entry, size = symbols[name]
    record = {'entry': entry, 'end': entry + size,
              'return': entry + size - (1 if target == 'x86_64' else 4)}
    record.update({marker: symbols[marker][0] for marker in markers})
    ordered = ['entry'] + markers + ['return', 'end']
    assert all(record[a] < record[b] for a, b in zip(ordered, ordered[1:])), record
    records[name] = record
for name in ['scope_sink', 'zero_sink']:
    records[name] = symbols[name][0]
(directory / 'labels.json').write_text(json.dumps(records, indent=4) + '\n')
PY
            sha256sum "$reference" "$input" > "$case_dir/originals.sha256"
            llvm-dwarfdump --verify "$reference" > "$case_dir/compiler-llvm.txt" 2>&1
            run_gdb "$reference" compiler "$case_dir/compiler-gdb.txt"
            "$ghidra/support/analyzeHeadless" "$case_dir/project" StackLocals \
                -import "$input" -loader ElfLoader -analysisTimeoutPerFile 120 \
                -scriptPath "$repository/src/test/integration/ghidra_scripts" "${rebase[@]}" \
                -postScript PrepareStackLocalDefinitions.java "$case_dir/labels.json" "$case_dir/compiler-storage.json" "$case_dir/prepared.json" \
                > "$case_dir/import.log" 2>&1
            grep -Fq 'stack-local-definitions-preparation=PASS' "$case_dir/import.log"
            if [[ "$role" == pie-rebased ]]; then
                grep -Eq 'Rebased fixture image from .* by 0x2000000 ' "$case_dir/import.log"
            fi
            python3 "$repository/src/test/integration/stack-local-snapshot.py" "$case_dir" before "$ghidra"
            iterations=(first repeat)
            if [[ -n "${FORGE_STACK_LOCAL_PREVIOUS_GHIDRA:-}" ]]; then iterations+=(previous); fi
            for iteration in "${iterations[@]}"; do
                installation="$ghidra"
                destination="$output"
                if [[ "$iteration" == previous ]]; then
                    installation=$(realpath "$FORGE_STACK_LOCAL_PREVIOUS_GHIDRA")
                    destination="$case_dir/previous.dbg"
                fi
                "$installation/support/analyzeHeadless" "$case_dir/project" StackLocals \
                    -process "$(basename "$input")" -readOnly -noanalysis \
                    -scriptPath "$repository/src/test/integration/ghidra_scripts" \
                    -postScript PrepareStackLocalDefinitions.java "$case_dir/labels.json" "$case_dir/compiler-storage.json" "$case_dir/prepared-$iteration.json" observe \
                    -postScript GhidraDwarfForge.java --packaged-natives "--output=$destination" \
                    > "$case_dir/export-$iteration.log" 2>&1
                grep -Fq 'stack-local-definitions-preparation=PASS' "$case_dir/export-$iteration.log"
                grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$iteration.log"
                python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2]))' \
                    "$case_dir/prepared.json" "$case_dir/prepared-$iteration.json"
                if [[ "$iteration" == first ]]; then
                    cp "$output" "$case_dir/first.dbg"
                    cp "$output.c" "$case_dir/first.dbg.c"
                elif [[ "$iteration" == repeat ]]; then
                    cmp "$output" "$case_dir/first.dbg"
                    cmp "$output.c" "$case_dir/first.dbg.c"
                fi
                sha256sum -c "$case_dir/originals.sha256" > "$case_dir/input-preservation.txt"
            done
            python3 "$repository/src/test/integration/stack-local-snapshot.py" "$case_dir" after "$ghidra"
            readelf -hSWn "$output" > "$case_dir/elf.txt" 2> "$case_dir/readelf.stderr"
            for dump in info abbrev aranges decodedline Ranges loc; do
                readelf "--debug-dump=$dump" "$output" > "$case_dir/$dump.txt" \
                    2>> "$case_dir/readelf.stderr"
            done
            test ! -s "$case_dir/readelf.stderr"
            python3 "$repository/src/test/integration/check-code-address-index.py" \
                "$output" --negative-controls > "$case_dir/address-index.json"
            llvm-dwarfdump --verify "$output" > "$case_dir/llvm.txt" 2> "$case_dir/llvm.stderr"
            test ! -s "$case_dir/llvm.stderr"
            if grep -Ei '(^|[[:space:]])(warning|error):' "$case_dir/llvm.txt"; then exit 1; fi
            python3 "$repository/src/test/integration/check-dwarfdump.py" \
                "$output" "$case_dir/dwarfdump.txt" --original "$input"
            diff <(awk '/Build ID:/ { print $3 }' "$case_dir/input-elf.txt") \
                <(awk '/Build ID:/ { print $3 }' "$case_dir/elf.txt")
            run_gdb "$output" forge "$case_dir/forge-gdb.txt"
            if [[ -n "${FORGE_STACK_LOCAL_PREVIOUS_GHIDRA:-}" ]]; then
                run_gdb "$case_dir/previous.dbg" previous "$case_dir/previous-gdb.txt"
                readelf -hSWn "$case_dir/previous.dbg" > "$case_dir/previous-elf.txt" 2> "$case_dir/previous-readelf.stderr"
                for dump in info abbrev aranges decodedline Ranges loc; do
                    readelf "--debug-dump=$dump" "$case_dir/previous.dbg" > "$case_dir/previous-$dump.txt" \
                        2>> "$case_dir/previous-readelf.stderr"
                done
                test ! -s "$case_dir/previous-readelf.stderr"
                llvm-dwarfdump --verify "$case_dir/previous.dbg" > "$case_dir/previous-llvm.txt" 2>&1
                grep -Fq 'No errors.' "$case_dir/previous-llvm.txt"
                python3 "$repository/src/test/integration/check-dwarfdump.py" \
                    "$case_dir/previous.dbg" "$case_dir/previous-dwarfdump.txt" --original "$input"
            fi
            python3 "$repository/src/test/integration/check-stack-local-definitions.py" "$case_dir" "$target" \
                > "$case_dir/locations.json"
            sha256sum -c "$case_dir/originals.sha256" > "$case_dir/input-preservation.txt"
            printf 'stack-local-definitions-case=%s/%s/%s PASS\n' "$target" "$width" "$role" | tee "$case_dir/result.txt"
        done
    done
done
sha256sum -c "$results/source-and-exporter.sha256" > "$results/exporter-preservation.txt"
echo 'stack-local-definitions-export=PASS' | tee "$results/result.txt"
