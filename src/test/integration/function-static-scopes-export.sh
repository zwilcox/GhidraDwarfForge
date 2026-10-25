#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <ghidra-dir-with-packaged-natives> [target ...]" >&2
    exit 64
fi
export LC_ALL=C
qualified=${FORGE_SCOPE_QUALIFIED:-0}
class_names=${FORGE_SCOPE_CLASS_NAMES:-0}
if [[ "$qualified" != 0 && "$qualified" != 1 ]]; then
    echo 'FORGE_SCOPE_QUALIFIED must be 0 or 1' >&2
    exit 64
fi
if [[ "$class_names" != 0 && "$class_names" != 1 ]] ||
        [[ "$class_names" == 1 && "$qualified" != 1 ]]; then
    echo 'FORGE_SCOPE_CLASS_NAMES must be 0 or 1; class names require qualified mode' >&2
    exit 64
fi
export FORGE_SCOPE_QUALIFIED="$qualified"
repository_dir=$(realpath "$(dirname "$0")/../../..")
ghidra_dir=$(realpath "$1")
shift
targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then
    targets=(x86_64 mips32be)
fi
source "$repository_dir/src/test/integration/elf-layout-gdb-oracle.sh"
result_root="$repository_dir/build/test-results/function-static-scopes"
if [[ "$qualified" == 1 ]]; then
    result_root="$repository_dir/build/test-results/qualified-function-names"
fi
if [[ "$class_names" == 1 ]]; then
    result_root="$repository_dir/build/test-results/class-function-names"
fi
mkdir -p "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
snapshot_class_inputs() {
    python3 - "$repository_dir" "$ghidra_dir" "$result_dir" "$1" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
repository, ghidra, result = map(Path, sys.argv[1:4])
phase = sys.argv[4]
files = [repository / name for name in (
    'src/test/fixtures/function-static-scopes.c',
    'src/test/integration/function-static-scopes-export.sh',
    'src/test/integration/function-static-scopes-gdb.py',
    'src/test/integration/ghidra_scripts/PrepareFunctionStaticScopes.java')]
files += [p for p in (ghidra / 'Ghidra/Extensions/GhidraDwarfForge').rglob('*') if p.is_file()]
snapshot = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
(result / ('protected-' + phase + '.json')).write_text(json.dumps(snapshot, indent=4) + '\n')
if phase == 'after':
    assert snapshot == json.loads((result / 'protected-before.json').read_text())
PY
}
if [[ "$class_names" == 1 ]]; then snapshot_class_inputs before; fi
emulator_pid=
port=$((29000 + ($$ % 10000)))
cleanup() {
    if [[ -n "$emulator_pid" ]]; then
        kill "$emulator_pid" 2>/dev/null || true
        wait "$emulator_pid" 2>/dev/null || true
    fi
    echo "function-static-scopes results: $result_dir"
}
trap cleanup EXIT

run_gdb() {
    local executable=$1 sidecar=$2 kind=$3 log=$4
    local load_symbols=() connect=() run_command=run
    if [[ -n "$sidecar" ]]; then
        load_symbols=(-ex "symbol-file \"$sidecar\"")
    fi
    if [[ -n "$emulator" ]]; then
        "$emulator" -L "$sysroot" -g "$port" "$executable" \
            > "$log.emulator" 2>&1 &
        emulator_pid=$!
        sleep 0.2
        connect=(-ex "set sysroot $sysroot" -ex "target remote :$port")
        run_command=continue
    fi
    FORGE_SCOPE_ADDRESSES="$addresses" FORGE_SCOPE_KIND="$kind" \
        FORGE_SCOPE_RUN="$run_command" \
        timeout 45 gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' \
        -ex "file \"$executable\"" "${load_symbols[@]}" "${connect[@]}" \
        -x "$repository_dir/src/test/integration/function-static-scopes-gdb.py" \
        > "$log" 2>&1
    if [[ -n "$emulator_pid" ]]; then
        wait "$emulator_pid"
        emulator_pid=
    fi
    local oracle="$case_dir/compiler-gdb.txt" diagnostics="$log.diagnostics"
    if [[ "$kind" != forge ]]; then
        oracle=$log
    fi
    if [[ ( "$target" == mips32be || "$target" == mips32le ) &&
            "$role" != exec && -n "$sidecar" ]]; then
        # GDB 15.1 can warn while returning to main in this MIPS PIE fixture
        # under file <stripped>; symbol-file <separate ELF>. The full, untouched
        # compiler ELF reproduces it as the symbol file. Match both the exact
        # diagnostic (including its address) and its count within that same
        # owner-return operation; reference-only loading remains a strict check.
        awk '
            /SCOPE_RETURN_BEGIN/ { returning = 1 }
            /SCOPE_RETURN_END/ { returning = 0 }
            NR == FNR {
                if (returning && $0 ~ /^warning: GDB can\047t find the start of the function at 0x[[:xdigit:]]+\.$/) {
                    known[$0]++
                }
                next
            }
            returning && known[$0] > 0 { known[$0]--; next }
            { print }
        ' "$oracle" "$log" > "$diagnostics"
    else
        cp "$log" "$diagnostics"
    fi
    layout_validate_gdb_diagnostics "$diagnostics" "$executable" static-scopes \
        "$target" "$oracle"
    grep -Fxq "function-static-scopes-gdb=$kind PASS" "$log"
    grep -Fq 'exited normally' "$log"
}

validate_sidecar() {
    readelf -h -SW -n "$output" > "$case_dir/elf.txt" 2> "$case_dir/readelf.stderr"
    for dump in info abbrev aranges decodedline Ranges loc; do
        readelf "--debug-dump=$dump" "$output" > "$case_dir/$dump.txt" \
            2>> "$case_dir/readelf.stderr"
    done
    test ! -s "$case_dir/readelf.stderr"
    python3 "$repository_dir/src/test/integration/check-code-address-index.py" \
        "$output" --negative-controls > "$case_dir/address-index.json"
    llvm-dwarfdump --verify "$output" > "$case_dir/llvm.txt" 2>&1
    python3 "$repository_dir/src/test/integration/check-dwarfdump.py" \
        "$output" "$case_dir/dwarfdump.txt" --original "$input"
    if grep -Ei '(^|[[:space:]])(warning|error):' \
            "$case_dir/llvm.txt" "$case_dir/dwarfdump.txt"; then
        echo "function-static-scopes validator reported a warning or error" >&2
        return 1
    fi
    awk '
        function finish() {
            if (external) {
                declarations++
                if (!declaration || !external_flag || location) bad = 1
            }
        }
        /Abbrev Number:.*DW_TAG_/ {
            finish()
            depth = $1
            sub(/^</, "", depth)
            sub(/>.*/, "", depth)
            variable = /DW_TAG_variable/
            external = declaration = external_flag = location = 0
        }
        /DW_AT_name.*private_count$/ {
            if (variable && depth == 2) private++
            else if (variable && depth == 1) global++
            else bad = 1
        }
        /DW_AT_name.*declared_external$/ { external = 1 }
        /DW_AT_name.*analyst_scope$/ { namespaces++ }
        /DW_AT_declaration/ { declaration = 1 }
        /DW_AT_external/ { external_flag = 1 }
        /DW_AT_location/ { location = 1 }
        END {
            finish()
            exit bad || private != 2 || global != 1 || declarations != 1 || namespaces != 1
        }
    ' "$case_dir/info.txt"
    if [[ "$qualified" == 1 ]]; then
        python3 - "$case_dir/info.txt" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text()
assert re.search(r'DW_AT_language\s*:\s*29\b', text), 'synthetic CU language changed'
for name in ('analysis_left::nested::curated_same',
             'analysis_right::nested::curated_same'):
    # These are qualified display strings at CU scope, not C++ namespace DIEs.
    dies = re.split(r'(?m)^\s*<(?=\d+><[0-9a-fA-F]+>:\s+Abbrev Number:)', text)
    matching = [die for die in dies if 'DW_TAG_subprogram' in die and
                re.search(r'DW_AT_name\s*:.*\b' + re.escape(name) + r'\s*$', die, re.M)]
    assert len(matching) == 1 and matching[0].startswith('1>'), name
    assert 'DW_AT_decl_line' in matching[0], 'source declaration lost: ' + name
    assert 'DW_AT_linkage_name' not in matching[0], 'fabricated linkage identity'
PY
    fi
}

for target in "${targets[@]}"; do
    compiler= strip_tool= emulator= sysroot=
    compile_flags=()
    if [[ "$qualified" == 1 ]]; then
        compile_flags+=(-DFORGE_QUALIFIED_NAMES)
    fi
    case "$target" in
        x86_64) compiler=gcc; strip_tool=strip ;;
        aarch64)
            compiler=aarch64-linux-gnu-gcc; strip_tool=aarch64-linux-gnu-strip
            emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
        arm32)
            compiler=arm-linux-gnueabihf-gcc; strip_tool=arm-linux-gnueabihf-strip
            emulator=qemu-arm-static; sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf}
            compile_flags+=(-march=armv7-a -marm -mfpu=vfpv3-d16) ;;
        mips32be)
            compiler=mips-linux-gnu-gcc; strip_tool=mips-linux-gnu-strip
            emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
        mips32le)
            compiler=mipsel-linux-gnu-gcc; strip_tool=mipsel-linux-gnu-strip
            emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
        *) echo "unsupported fixture target: $target" >&2; exit 64 ;;
    esac
    for role in exec pie pie-rebased; do
        case_dir="$result_dir/$target/$role"
        mkdir -p "$case_dir/project"
        reference="$case_dir/scopes.reference"
        input="$case_dir/scopes.stripped"
        output="$case_dir/scopes.dbg"
        executable_flags=(-fPIE -pie)
        rebase=()
        if [[ "$role" == exec ]]; then
            executable_flags=(-fno-pie -no-pie)
        elif [[ "$role" == pie-rebased ]]; then
            rebase=(-postScript RebaseFixtureProgram.java 0x2000000)
        fi
        # Keep real compiler unwind information in the stripped original. MIPS
        # otherwise loses useful .debug_frame; ARM32 uses native EHABI tables.
        "$compiler" "${compile_flags[@]}" -O0 -g -gdwarf-5 \
            -fno-omit-frame-pointer -fasynchronous-unwind-tables \
            "${executable_flags[@]}" \
            "$repository_dir/src/test/fixtures/function-static-scopes.c" -o "$reference"
        cp "$reference" "$input"
        "$strip_tool" --strip-all "$input"
        readelf --debug-dump=frames "$input" > "$case_dir/input-frames.txt" \
            2> "$case_dir/input-frames.stderr"
        test ! -s "$case_dir/input-frames.stderr"
        if [[ "$target" == arm32 ]]; then
            "$repository_dir/src/test/integration/verify-arm-ehabi.py" \
                "$input" "$reference" "$case_dir/ehabi"
            if [[ "$role" == exec ]]; then
                "$repository_dir/src/test/integration/arm-ehabi-regression.sh" \
                    "$input" "$reference"
            fi
        else
            grep -Fq ' FDE ' "$case_dir/input-frames.txt"
        fi
        sha256sum "$input" > "$case_dir/input.sha256"
        gdb-multiarch -q -nx -batch -ex 'set debuginfod enabled off' \
            -ex "file \"$reference\"" \
            -ex 'python print("SCOPE_ADDRESSES " + " ".join(hex(int(gdb.parse_and_eval("&" + name))) for name in ["first_scope", "second_scope", "first_scope::private_count", "second_scope::private_count", "private_count", "scoped_value"]))' \
            > "$case_dir/compiler-addresses.txt" 2>&1
        addresses=$(sed -n 's/^SCOPE_ADDRESSES //p' "$case_dir/compiler-addresses.txt")
        read -r -a address_arguments <<< "$addresses"
        test "${#address_arguments[@]}" -eq 6
        preparation_arguments=("${address_arguments[@]}")
        if [[ "$qualified" == 1 ]]; then
            gdb-multiarch -q -nx -batch -ex 'set debuginfod enabled off' \
                -ex "file \"$reference\"" \
                -ex 'python print("GLOBAL_ADDRESS " + hex(int(gdb.parse_and_eval("&curated_same"))))' \
                > "$case_dir/compiler-global-address.txt" 2>&1
            global_address=$(sed -n 's/^GLOBAL_ADDRESS //p' "$case_dir/compiler-global-address.txt")
            [[ "$global_address" =~ ^0x[[:xdigit:]]+$ ]]
            preparation_mode=qualified
            if [[ "$class_names" == 1 ]]; then preparation_mode=class-qualified; fi
            preparation_arguments+=("$preparation_mode" "$global_address")
            addresses+=" $global_address"
        fi
        run_gdb "$reference" "" compiler-reference "$case_dir/compiler-reference-gdb.txt"
        run_gdb "$input" "$reference" compiler "$case_dir/compiler-gdb.txt"
        for iteration in first repeat; do
            project_arguments=(-deleteProject -import "$input" -analysisTimeoutPerFile 120)
            script_arguments=("${rebase[@]}" -postScript PrepareFunctionStaticScopes.java
                "$target" "${preparation_arguments[@]}")
            if [[ "$class_names" == 1 ]]; then
                project_arguments=(-import "$input" -analysisTimeoutPerFile 120)
                if [[ "$iteration" == repeat ]]; then
                    project_arguments=(-process "$(basename "$input")" -readOnly -noanalysis)
                    script_arguments=()
                fi
            fi
            "$ghidra_dir/support/analyzeHeadless" "$case_dir/project" StaticScopes \
                "${project_arguments[@]}" \
                -scriptPath "$repository_dir/src/test/integration/ghidra_scripts" \
                "${script_arguments[@]}" \
                -postScript GhidraDwarfForge.java --packaged-natives "--output=$output" \
                > "$case_dir/export-$iteration.log" 2>&1
            grep -Fq 'GhidraDwarfForge symbol export PASS' "$case_dir/export-$iteration.log"
            if [[ "$class_names" == 0 || "$iteration" == first ]]; then
                grep -Fq 'function-static-scopes preparation PASS; missing owner diagnosed' \
                    "$case_dir/export-$iteration.log"
            fi
            grep -Fq '"functionStaticVariables":2' "$case_dir/export-$iteration.log"
            if [[ "$iteration" == first ]]; then
                cp "$output" "$case_dir/first.dbg"
                cp "$output.c" "$case_dir/first.dbg.c"
            else
                cmp "$output" "$case_dir/first.dbg"
                cmp "$output.c" "$case_dir/first.dbg.c"
            fi
            sha256sum -c "$case_dir/input.sha256" > "$case_dir/input-preservation.txt"
            if [[ "$class_names" == 1 ]]; then
                python3 - "$case_dir" "$iteration" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
case, iteration = Path(sys.argv[1]), sys.argv[2]
project = case / 'project'
snapshot = {str(p.relative_to(project)): hashlib.sha256(p.read_bytes()).hexdigest()
    for p in project.rglob('*') if p.is_file()}
(case / ('project-' + iteration + '.json')).write_text(json.dumps(snapshot, indent=4) + '\n')
if iteration == 'repeat':
    before = json.loads((case / 'project-first.json').read_text())
    changes = sorted(k for k in before.keys() | snapshot.keys() if before.get(k) != snapshot.get(k))
    assert set(changes) <= {'StaticScopes.rep/idata/~index.bak', 'StaticScopes.rep/idata/~journal.bak'}, changes
    (case / 'project-preservation.json').write_text(json.dumps({'status': 'PASS', 'backupChanges': changes}, indent=4) + '\n')
PY
            fi
        done
        if [[ "$class_names" == 1 ]]; then
            grep -Fq 'display-owner=analysis_left type=CLASS' "$case_dir/export-first.log"
            grep -Fq 'display-owner=analysis_right type=CLASS' "$case_dir/export-first.log"
            if grep -Fq 'Omitted function display namespace' "$case_dir/export-first.log"; then
                echo 'class display unexpectedly lost its owner' >&2
                exit 1
            fi
            python3 - "$case_dir/export-first.log" "$ghidra_dir" <<'PY'
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit
log, ghidra = map(Path, sys.argv[1:])
origin, = re.findall(r'function-symbol-origin=(\S+)', log.read_text())
assert Path(unquote(urlsplit(origin).path)).resolve() == (ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar').resolve()
PY
        fi
        validate_sidecar
        run_gdb "$input" "$output" forge "$case_dir/forge-gdb.txt"
        sha256sum -c "$case_dir/input.sha256" > "$case_dir/input-preservation.txt"
        echo "function-static-scopes-$target-$role=PASS"
    done
done
if [[ "$class_names" == 1 ]]; then snapshot_class_inputs after; fi
echo 'function-static-scopes=PASS'
