#!/usr/bin/env bash
set -euo pipefail

# Linux host, AArch64 GCC/binutils, QEMU-user and GDB required. The baseline
# mode records a known wrong-value reproduction; CI only accepts fixed mode.
if [[ $# -lt 1 ]]; then
    echo "usage: $0 <ghidra-dir-with-packaged-natives> [exec pie pie-rebased ...]" >&2
    exit 64
fi
export LC_ALL=C
expectation=${FORGE_OPAQUE_EXPECTATION:-fixed}
listing=${FORGE_OPAQUE_LISTING:-complete}
case "$listing" in
    complete|gap) ;;
    *) echo 'FORGE_OPAQUE_LISTING must be complete or gap' >&2; exit 64 ;;
esac
if [[ "$expectation" != fixed && "$expectation" != baseline-reproducer ]]; then
    echo 'FORGE_OPAQUE_EXPECTATION must be fixed or baseline-reproducer' >&2
    exit 64
fi
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
shift
roles=("$@")
if [[ ${#roles[@]} -eq 0 ]]; then roles=(exec pie pie-rebased); fi
for role in "${roles[@]}"; do
    case "$role" in
        exec|pie|pie-rebased) ;;
        *) echo "unsupported fixture role: $role" >&2; exit 64 ;;
    esac
done
for command in aarch64-linux-gnu-gcc aarch64-linux-gnu-objcopy \
        qemu-aarch64-static gdb-multiarch readelf llvm-dwarfdump python3 timeout; do
    command -v "$command" >/dev/null
done
source "$repository/src/test/integration/qemu-socket.sh"
root="$repository/build/test-results/opaque-register-effects"
if [[ "$listing" == gap ]]; then root+="-listing-gap"; fi
mkdir -p "$root"
results=$(mktemp -d "$root/run.XXXXXXXX")
cleanup() {
    qemu_socket_cleanup
    echo "opaque-register-results=$results"
}
trap cleanup EXIT
echo "opaque-register-results=$results expectation=$expectation"
{
    aarch64-linux-gnu-gcc --version
    aarch64-linux-gnu-objcopy --version
    qemu-aarch64-static --version
    gdb-multiarch --version
    readelf --version
    llvm-dwarfdump --version
} > "$results/tool-versions.txt" 2>&1
printf 'expectation=%s\nghidra=%s\n' "$expectation" "$ghidra" > "$results/inputs.txt"
sha256sum "$repository/src/test/fixtures/opaque-register-effects.c" \
    "$ghidra/Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar" \
    "$ghidra/Ghidra/Extensions/GhidraDwarfForge/os/linux_x86_64/libdwarf.so.2.3.2" \
    "$ghidra/Ghidra/Extensions/GhidraDwarfForge/os/linux_x86_64/libdwarfp.so.2.3.2" \
    "$repository/src/test/integration/opaque-register-effects-export.sh" \
    "$repository/src/test/integration/opaque-register-effects-gdb.py" \
    "$repository/src/test/integration/ghidra_scripts/PrepareOpaqueRegisterEffects.java" \
    "$repository/src/test/integration/ghidra_scripts/VerifyOpaqueListing.java" \
    > "$results/source-and-exporter.sha256"

run_gdb() {
    local symbols=$1 mode=$2 log=$3
    qemu_socket_start "$log.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$input"
    FORGE_OPAQUE_LABELS="$case_dir/labels.txt" FORGE_OPAQUE_MODE="$mode" FORGE_OPAQUE_ROLE="$role" \
        FORGE_OPAQUE_EXPECTATION="$expectation" \
        timeout 45s gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set sysroot /usr/aarch64-linux-gnu' \
        -ex "file \"$input\"" -ex "symbol-file \"$symbols\"" \
        -ex "target remote $qemu_socket_path" \
        -x "$repository/src/test/integration/opaque-register-effects-gdb.py" \
        > "$log" 2> "$log.stderr"
    qemu_socket_wait
    # Retain only the existing exact QEMU-vDSO exception, and require the
    # independent compiler run to have the same diagnostic text and count.
    python3 - "$log.stderr" "$case_dir/compiler-gdb.txt.stderr" "$mode" <<'PY'
from collections import Counter
from pathlib import Path
import re
import sys

actual = Path(sys.argv[1]).read_text().splitlines()
pattern = r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index'
assert all(re.fullmatch(pattern, line) for line in actual), actual
if sys.argv[3] == 'forge' and actual:
    assert Counter(actual) == Counter(Path(sys.argv[2]).read_text().splitlines()), actual
PY
    if [[ "$mode" == forge && "$expectation" == baseline-reproducer ]]; then
        grep -Fxq 'baseline-incorrect-register-location=REPRODUCED' "$log"
    else
        grep -Fxq "opaque-register-effects-gdb=$mode PASS" "$log"
    fi
    grep -Fq 'exited normally' "$log"
}

for role in "${roles[@]}"; do
    case_dir="$results/$role"
    mkdir -p "$case_dir/project"
    reference="$case_dir/opaque.reference"
    input="$case_dir/opaque.stripped"
    output="$case_dir/opaque.dbg"
    flags=(-fno-pie -no-pie)
    rebase=()
    if [[ "$role" != exec ]]; then flags=(-fPIE -pie); fi
    if [[ "$role" == pie-rebased ]]; then
        rebase=(-postScript RebaseFixtureProgram.java 0x2000000)
    fi
    aarch64-linux-gnu-gcc -Og -g -gdwarf-5 -fasynchronous-unwind-tables \
        "${flags[@]}" -Wl,--build-id=sha1 \
        "$repository/src/test/fixtures/opaque-register-effects.c" -o "$reference"
    aarch64-linux-gnu-objcopy --strip-all "$reference" "$input"
    readelf -Ws "$reference" > "$case_dir/reference-symbols.txt"
    python3 - "$case_dir/reference-symbols.txt" "$case_dir/labels.txt" <<'PY'
from pathlib import Path
import sys

wanted = {'opaque_value', 'opaque_before', 'opaque_store', 'opaque_return', 'opaque_sink'}
found = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    columns = line.split()
    if len(columns) == 8 and columns[7] in wanted:
        assert columns[7] not in found, 'duplicate fixture symbol'
        found[columns[7]] = int(columns[1], 16)
assert set(found) == wanted, found
assert found['opaque_value'] < found['opaque_before'] < found['opaque_store'] < found['opaque_return']
Path(sys.argv[2]).write_text(''.join(name + ' ' + hex(found[name]) + '\n' for name in sorted(found)))
PY
    readelf -hSWn "$input" > "$case_dir/input-elf.txt" 2> "$case_dir/input-elf.stderr"
    test ! -s "$case_dir/input-elf.stderr"
    if grep -Eq '[[:space:]][.](debug_|symtab)' "$case_dir/input-elf.txt"; then
        echo 'compiler debug/symbol tables remain in Ghidra input' >&2
        exit 1
    fi
    sha256sum "$reference" "$input" > "$case_dir/originals.sha256"
    run_gdb "$reference" compiler "$case_dir/compiler-gdb.txt"
    for iteration in first repeat; do
        "$ghidra/support/analyzeHeadless" "$case_dir/project" OpaqueRegisters \
            -deleteProject -import "$input" -loader ElfLoader -analysisTimeoutPerFile 120 \
            -scriptPath "$repository/src/test/integration/ghidra_scripts" "${rebase[@]}" \
            -postScript PrepareOpaqueRegisterEffects.java "$case_dir/labels.txt" "$listing" \
            -postScript GhidraDwarfForge.java --packaged-natives "--output=$output" \
            -postScript VerifyOpaqueListing.java "$case_dir/labels.txt" "$listing" \
            > "$case_dir/export-$iteration.log" 2>&1
        grep -Fq 'opaque-register-preparation=PASS' "$case_dir/export-$iteration.log"
        grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$iteration.log"
        grep -Fq "opaque-listing-preservation=PASS profile=$listing" "$case_dir/export-$iteration.log"
        if [[ "$expectation" == fixed ]]; then
            python3 - "$case_dir/export-$iteration.log" "$case_dir/report-$iteration.json" "$listing" <<'PY'
from pathlib import Path
import json
import sys

marker = 'GhidraDwarfForge report: '
reports = [json.JSONDecoder().raw_decode(line.split(marker, 1)[1])[0]
           for line in Path(sys.argv[1]).read_text().splitlines() if marker in line]
assert len(reports) == 1, reports
report = reports[0]
omitted = [entry for entry in report['omittedLocations']
           if entry['function'] == 'opaque_value' and entry['kind'] == 'PARAMETER']
assert len(omitted) == 2 and {entry['variable'] for entry in omitted} == {'value', 'destination'}
assert all(entry['reason'] == 'UNKNOWN_LIFETIME' and
           ('incomplete instruction coverage' if sys.argv[3] == 'gap' else
            'opaque instruction effects') in entry['diagnostic'] for entry in omitted), omitted
assert not any(entry['name'] == 'opaque_value' for entry in report['failedFunctions'])
Path(sys.argv[2]).write_text(json.dumps(report, indent=4) + '\n')
PY
        fi
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
    if [[ "$expectation" == fixed ]]; then
        python3 - "$case_dir/info.txt" > "$case_dir/parameter-locations.txt" <<'PY'
from pathlib import Path
import re
import sys

records = []
for line in Path(sys.argv[1]).read_text().splitlines():
    header = re.match(r'^\s*<(\d+)><[0-9a-f]+>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?', line)
    if header:
        records.append({'depth': int(header[1]), 'tag': header[2], 'attributes': {}})
    elif records:
        attribute = re.search(r'\b(DW_AT_\w+)\s+:\s*(.*)', line)
        if attribute:
            records[-1]['attributes'][attribute[1]] = attribute[2]

def name(record):
    return record['attributes'].get('DW_AT_name', '').rsplit(': ', 1)[-1]

functions = [index for index, record in enumerate(records)
             if record['tag'] == 'DW_TAG_subprogram' and name(record) == 'opaque_value']
assert len(functions) == 1, functions
function = records[functions[0]]
parameters = {}
for record in records[functions[0] + 1:]:
    if record['depth'] <= function['depth']:
        break
    if record['tag'] == 'DW_TAG_formal_parameter':
        assert record['depth'] == function['depth'] + 1
        assert name(record) not in parameters
        parameters[name(record)] = record['attributes']
assert set(parameters) == {'value', 'destination'}, parameters
for parameter, attributes in parameters.items():
    assert 'DW_AT_type' in attributes, (parameter, attributes)
    assert 'DW_AT_location' not in attributes, (parameter, attributes)
print('opaque-formal-parameter-locations=absent-for-entire-function')
PY
    fi
    llvm-dwarfdump --verify "$output" > "$case_dir/llvm.txt" 2> "$case_dir/llvm.stderr"
    test ! -s "$case_dir/llvm.stderr"
    if grep -Ei '(^|[[:space:]])(warning|error):' "$case_dir/llvm.txt"; then exit 1; fi
    python3 "$repository/src/test/integration/check-dwarfdump.py" \
        "$output" "$case_dir/dwarfdump.txt" --original "$input"
    diff <(awk '/Build ID:/ { print $3 }' "$case_dir/input-elf.txt") \
        <(awk '/Build ID:/ { print $3 }' "$case_dir/elf.txt")
    run_gdb "$output" forge "$case_dir/forge-gdb.txt"
    sha256sum -c "$case_dir/originals.sha256" > "$case_dir/input-preservation.txt"
    if [[ "$expectation" == baseline-reproducer ]]; then
        echo "baseline-incorrect-register-location-$role=REPRODUCED" | tee "$case_dir/result.txt"
    else
        echo "opaque-register-effects-$role=PASS" | tee "$case_dir/result.txt"
    fi
done
sha256sum -c "$results/source-and-exporter.sha256" > "$results/exporter-preservation.txt"
if [[ "$expectation" == baseline-reproducer ]]; then
    echo 'baseline-incorrect-register-location=REPRODUCED' | tee "$results/result.txt"
else
    echo 'opaque-register-effects=PASS' | tee "$results/result.txt"
fi
