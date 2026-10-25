#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
if [[ $# != 1 ]]; then
    echo "usage: $0 <ghidra-dir>" >&2
    exit 2
fi
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf}
source "$repository/src/test/integration/qemu-socket.sh"
source "$repository/src/test/integration/elf-layout-gdb-oracle.sh"
trap qemu_socket_cleanup EXIT
mkdir -p "$repository/build/test-results/terminal-composite"
results=$(mktemp -d "$repository/build/test-results/terminal-composite/run.XXXXXXXX")
echo "terminal-composite-results=$results"
python3 - "$repository" "$ghidra" "$results/protected.sha256" <<'PY'
import hashlib
from pathlib import Path
import sys
repo, ghidra, output = map(Path, sys.argv[1:])
files = [repo / name for name in ('src/test/fixtures/terminal-composite.c',
    'src/test/integration/terminal-composite-export.sh', 'src/test/integration/terminal-composite-gdb.py',
    'src/test/integration/terminal-composite-check.py', 'src/test/integration/qemu-socket.sh',
    'src/test/integration/elf-layout-gdb-oracle.sh', 'src/test/integration/check-dwarfdump.py',
    'src/test/integration/ghidra_scripts/RebaseFixtureProgram.java',
    'src/test/integration/ghidra_scripts/PrepareTerminalComposite.java')]
files += [p for p in (ghidra / 'Ghidra/Extensions/GhidraDwarfForge').rglob('*') if p.is_file()]
output.write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p) + '\n' for p in files))
PY
run_gdb() {
    local mode=$1 log=$2 executable=$3 sidecar=${4:-}
    local options=()
    if [[ -n "$sidecar" ]]; then options=(-ex "symbol-file $sidecar"); fi
    qemu_socket_start "$log.qemu" qemu-arm-static "$sysroot" "$executable"
    FORGE_TERMINAL_CASE="$case_dir" FORGE_TERMINAL_MODE="$mode" \
        FORGE_TERMINAL_REMOTE="$qemu_socket_path" FORGE_TERMINAL_RESULT="$log.json" \
        timeout 45s gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
        -ex 'set auto-solib-add off' -ex "set sysroot $sysroot" -ex "file $executable" \
        "${options[@]}" -x "$repository/src/test/integration/terminal-composite-gdb.py" > "$log" 2>&1
    qemu_socket_wait
    layout_validate_gdb_diagnostics "$log" "$executable" "$mode" arm32 "$case_dir/compiler-gdb.txt"
}
for role in exec pie; do
    case_dir="$results/$role"
    mkdir -p "$case_dir/project"
    flags=(-fno-pie -no-pie)
    if [[ "$role" == pie ]]; then flags=(-fPIE -pie); fi
    arm-linux-gnueabihf-gcc -Og -g3 -gdwarf-5 -marm -march=armv7-a -mfpu=vfpv3-d16 \
        "${flags[@]}" "$repository/src/test/fixtures/terminal-composite.c" -o "$case_dir/terminal.reference" \
        > "$case_dir/compile.stdout" 2> "$case_dir/compile.stderr"
    test ! -s "$case_dir/compile.stderr"
    arm-linux-gnueabihf-objcopy --strip-all "$case_dir/terminal.reference" "$case_dir/terminal.stripped"
    readelf -Ws "$case_dir/terminal.reference" > "$case_dir/symbols.txt"
    awk '$8 ~ /^terminal_pair/ {print $8, "0x" $2}' "$case_dir/symbols.txt" | LC_ALL=C sort -u > "$case_dir/labels.txt"
    sha256sum "$case_dir/terminal.reference" "$case_dir/terminal.stripped" > "$case_dir/originals.sha256"
    run_gdb compiler "$case_dir/compiler-gdb.txt" "$case_dir/terminal.reference"
    for sample in baseline rebased repeat; do
        sample_dir="$case_dir/$sample"
        mkdir "$sample_dir"
        rebase=()
        if [[ "$sample" == rebased ]]; then rebase=(-postScript RebaseFixtureProgram.java 0x2000000); fi
        output="$case_dir/terminal.dbg"
        "$ghidra/support/analyzeHeadless" "$case_dir/project" "Terminal_$sample" -deleteProject \
            -import "$case_dir/terminal.stripped" -analysisTimeoutPerFile 120 \
            -scriptPath "$repository/src/test/integration/ghidra_scripts" "${rebase[@]}" \
            -postScript PrepareTerminalComposite.java "$case_dir/labels.txt" "$sample_dir/model.json" \
            -postScript GhidraDwarfForge.java --packaged-natives "--output=$output" > "$sample_dir/headless.txt" 2>&1
        grep -Fq 'terminal-composite-preparation=PASS' "$sample_dir/headless.txt"
        grep -Fq 'GhidraDwarfForge symbol export PASS' "$sample_dir/headless.txt"
        readelf -hSWn --debug-dump=info --debug-dump=abbrev --debug-dump=aranges \
            --debug-dump=decodedline --debug-dump=loc --debug-dump=Ranges "$output" \
            > "$sample_dir/readelf.txt" 2> "$sample_dir/readelf.stderr"
        test ! -s "$sample_dir/readelf.stderr"
        llvm-dwarfdump --verify "$output" > "$sample_dir/llvm.txt" 2>&1
        python3 "$repository/src/test/integration/check-dwarfdump.py" "$output" \
            "$sample_dir/strict.txt" --original "$case_dir/terminal.stripped"
        run_gdb forge "$sample_dir/gdb.txt" "$case_dir/terminal.stripped" "$output"
        sha256sum -c "$case_dir/originals.sha256" > "$sample_dir/preservation.txt"
        cp "$output" "$sample_dir/terminal.dbg"
        cp "$output.c" "$sample_dir/terminal.dbg.c"
        echo "terminal-composite-case=$role/$sample PASS"
    done
    cmp "$case_dir/baseline/terminal.dbg" "$case_dir/repeat/terminal.dbg"
    cmp "$case_dir/baseline/terminal.dbg.c" "$case_dir/repeat/terminal.dbg.c"
done
sha256sum -c "$results/protected.sha256" > "$results/protected-after.txt"
python3 "$repository/src/test/integration/terminal-composite-check.py" "$results" "$ghidra"
echo 'terminal-composite-export=PASS'
