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
mkdir -p "$repository/build/test-results/mixed-incoming-prefix"
results=$(mktemp -d "$repository/build/test-results/mixed-incoming-prefix/run.XXXXXXXX")
echo "mixed-incoming-prefix-results=$results"
python3 - "$repository" "$ghidra" "$results/protected.sha256" <<'PY'
import hashlib
from pathlib import Path
import sys
repo, ghidra, output = map(Path, sys.argv[1:])
files = [repo / name for name in ('src/test/fixtures/mixed-incoming-prefix.c',
    'src/test/integration/mixed-incoming-prefix-export.sh', 'src/test/integration/mixed-incoming-prefix-gdb.py',
    'src/test/integration/mixed-incoming-prefix-check.py', 'src/test/integration/qemu-socket.sh',
    'src/test/integration/elf-layout-gdb-oracle.sh', 'src/test/integration/check-dwarfdump.py',
    'src/test/integration/ghidra_scripts/RebaseFixtureProgram.java',
    'src/test/integration/ghidra_scripts/PrepareMixedIncomingPrefix.java')]
files += [p for p in (ghidra / 'Ghidra/Extensions/GhidraDwarfForge').rglob('*') if p.is_file()]
output.write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p) + '\n' for p in files))
PY
run_gdb() {
    local mode=$1 log=$2 executable=$3 sidecar=${4:-}
    local options=()
    if [[ -n "$sidecar" ]]; then options=(-ex "symbol-file $sidecar"); fi
    qemu_socket_start "$log.qemu" qemu-arm-static "$sysroot" "$executable"
    FORGE_MIXED_CASE="$case_dir" FORGE_MIXED_MODE="$mode" \
        FORGE_MIXED_REMOTE="$qemu_socket_path" FORGE_MIXED_RESULT="$log.json" FORGE_MIXED_MODEL="$sample_dir/model.json" \
        timeout 45s gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
        -ex 'set auto-solib-add off' -ex "set sysroot $sysroot" -ex "file $executable" \
        "${options[@]}" -x "$repository/src/test/integration/mixed-incoming-prefix-gdb.py" > "$log" 2>&1
    qemu_socket_wait
    layout_validate_gdb_diagnostics "$log" "$executable" "$mode" arm32 "$case_dir/compiler-gdb.txt"
}
for role in exec pie; do
    case_dir="$results/$role"
    mkdir -p "$case_dir/project"
    flags=(-fno-pie -no-pie)
    if [[ "$role" == pie ]]; then flags=(-fPIE -pie); fi
    arm-linux-gnueabihf-gcc -Og -g3 -gdwarf-5 -marm -march=armv7-a -mfpu=vfpv3-d16 \
        "${flags[@]}" "$repository/src/test/fixtures/mixed-incoming-prefix.c" -o "$case_dir/mixed.reference" \
        > "$case_dir/compile.stdout" 2> "$case_dir/compile.stderr"
    test ! -s "$case_dir/compile.stderr"
    arm-linux-gnueabihf-objcopy --strip-all "$case_dir/mixed.reference" "$case_dir/mixed.stripped"
    readelf -Ws "$case_dir/mixed.reference" > "$case_dir/symbols.txt"
    awk '$8 ~ /^mixed/ {print $8, "0x" $2}' "$case_dir/symbols.txt" | LC_ALL=C sort -u > "$case_dir/labels.txt"
    sha256sum "$case_dir/mixed.reference" "$case_dir/mixed.stripped" > "$case_dir/originals.sha256"
    for form in computed custom; do
        mkdir "$case_dir/$form"
        for sample in baseline rebased repeat; do
            sample_dir="$case_dir/$form/$sample"
            mkdir "$sample_dir"
            rebase=()
            if [[ "$sample" == rebased ]]; then rebase=(-postScript RebaseFixtureProgram.java 0x2000000); fi
            output="$case_dir/mixed.dbg"
            "$ghidra/support/analyzeHeadless" "$case_dir/project" "Mixed_${form}_$sample" -deleteProject \
                -import "$case_dir/mixed.stripped" -analysisTimeoutPerFile 120 \
                -scriptPath "$repository/src/test/integration/ghidra_scripts" "${rebase[@]}" \
                -postScript PrepareMixedIncomingPrefix.java "$case_dir/labels.txt" "$sample_dir/model.json" "$form" \
                -postScript GhidraDwarfForge.java --packaged-natives "--output=$output" > "$sample_dir/headless.txt" 2>&1
            grep -Fq 'mixed-argument-observation=PASS' "$sample_dir/headless.txt"
            grep -Fq 'GhidraDwarfForge symbol export PASS' "$sample_dir/headless.txt"
            readelf -hSWn --debug-dump=info --debug-dump=abbrev --debug-dump=aranges \
                --debug-dump=decodedline --debug-dump=loc --debug-dump=Ranges "$output" \
                > "$sample_dir/readelf.txt" 2> "$sample_dir/readelf.stderr"
            test ! -s "$sample_dir/readelf.stderr"
            llvm-dwarfdump --verify "$output" > "$sample_dir/llvm.txt" 2>&1
            python3 "$repository/src/test/integration/check-dwarfdump.py" "$output" \
                "$sample_dir/strict.txt" --original "$case_dir/mixed.stripped"
            if [[ "$form" == computed && "$sample" == baseline ]]; then
                run_gdb compiler "$case_dir/compiler-gdb.txt" "$case_dir/mixed.reference"
            fi
            run_gdb forge "$sample_dir/gdb.txt" "$case_dir/mixed.stripped" "$output"
            sha256sum -c "$case_dir/originals.sha256" > "$sample_dir/preservation.txt"
            cp "$output" "$sample_dir/mixed.dbg"
            cp "$output.c" "$sample_dir/mixed.dbg.c"
            echo "mixed-incoming-prefix-case=$role/$form/$sample PASS"
        done
        cmp "$case_dir/$form/baseline/mixed.dbg" "$case_dir/$form/repeat/mixed.dbg"
        cmp "$case_dir/$form/baseline/mixed.dbg.c" "$case_dir/$form/repeat/mixed.dbg.c"
    done
done
sha256sum -c "$results/protected.sha256" > "$results/protected-after.txt"
python3 "$repository/src/test/integration/mixed-incoming-prefix-check.py" "$results" "$ghidra"
echo 'mixed-incoming-prefix-export=PASS'
