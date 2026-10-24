#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
if [[ $# -ne 1 ]]; then
    echo "usage: $0 <isolated-ghidra-with-packaged-extension>" >&2
    exit 64
fi
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
fixture="$repository/build/fixtures/x86_64/semantic.exec.stripped"
reference="$repository/build/fixtures/x86_64/semantic.exec.reference"
root="$repository/build/test-results/saved-program-determinism"
mkdir -p "$root"
work=$(mktemp -d "$root/run.XXXXXXXX")
mkdir -p "$work/project"
echo "saved-program-results=$work"
{
    java -version
    gdb-multiarch --version
    readelf --version
    llvm-dwarfdump --version
    dwarfdump --version
} > "$work/versions.txt" 2>&1
sha256sum "$ghidra/Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar" \
    > "$work/exporter.sha256"
input="$work/original.elf"
output="$work/original.dbg"
cp --preserve=all "$fixture" "$input"
sha256sum "$repository/src/test/fixtures/semantic.c" "$fixture" "$reference" "$input" \
    > "$work/originals.sha256"
entry=$(readelf -h "$input" | awk '/Entry point address:/ { print $NF }')
readelf -Ws "$reference" > "$work/reference-symbols.txt"
add=$(awk '$8 == "recovered_add" { print "0x" $2 }' "$work/reference-symbols.txt")
sink=$(awk '$8 == "fixture_sink" { print "0x" $2 }' "$work/reference-symbols.txt")
counter=$(awk '$8 == "scoped_counter" { print "0x" $2 }' "$work/reference-symbols.txt")
for phase in initial reopened repeat; do
    options=(-process original.elf -noanalysis -readOnly)
    if [[ "$phase" == initial ]]; then
        options=(-import "$input" -loader ElfLoader -analysisTimeoutPerFile 120
            -postScript PrepareSavedProgramTypes.java "$entry" "$add" "$sink" "$counter")
    fi
    command=("$ghidra/support/analyzeHeadless" "$work/project" SavedProgramTypes
        -scriptPath "$repository/src/test/integration/ghidra_scripts" "${options[@]}"
        -postScript SnapshotSavedProgramModel.java "$input" "$work/$phase.before"
        -postScript GhidraDwarfForge.java --packaged-natives "--input=$input" "--output=$output"
        -postScript SnapshotSavedProgramModel.java "$input" "$work/$phase.after")
    printf '%q ' "${command[@]}" > "$work/$phase.command.txt"
    printf '\n' >> "$work/$phase.command.txt"
    "${command[@]}" > "$work/$phase.log" 2>&1
    grep -Fq 'GhidraDwarfForge symbol export PASS' "$work/$phase.log"
    test -f "$work/$phase.after.semantic.txt"
    cmp "$work/$phase.before.raw.txt" "$work/$phase.after.raw.txt"
    cmp "$work/$phase.before.source.c" "$work/$phase.after.source.c"
    cp "$output" "$work/$phase.dbg"
    cp "$output.c" "$work/$phase.dbg.c"
    readelf -hSWn "$output" > "$work/$phase.elf.txt" 2> "$work/$phase.readelf.stderr"
    for kind in info abbrev aranges decodedline Ranges loc; do
        readelf "--debug-dump=$kind" "$output" > "$work/$phase.$kind.txt" \
            2>> "$work/$phase.readelf.stderr"
    done
    test ! -s "$work/$phase.readelf.stderr"
    llvm-dwarfdump --verify "$output" > "$work/$phase.llvm.txt" 2>&1
    python3 "$repository/src/test/integration/check-dwarfdump.py" \
        "$output" "$work/$phase.dwarfdump.txt" --original "$input"
    FORGE_SAVED_ADD="$add" FORGE_SAVED_SOURCE="$output.c" \
        timeout 45s gdb-multiarch -q -nx -batch -ex 'set pagination off' \
        -ex 'set confirm off' -ex 'set debuginfod enabled off' \
        -ex 'set auto-solib-add off' -ex 'set disable-randomization off' \
        -ex "file \"$input\"" -ex "symbol-file \"$output\"" \
        -x "$repository/src/test/integration/saved-program-gdb.py" \
        > "$work/$phase.gdb.txt" 2>&1
    if grep -Ei 'warning:|error:|malformed|corrupt|could not find' "$work/$phase.gdb.txt"; then
        exit 1
    fi
    grep -Fxq 'saved-program-gdb=PASS' "$work/$phase.gdb.txt"
done
grep -Fq 'saved-program-analysis=SETTLED' "$work/initial.log"
for phase in reopened repeat; do
    cmp "$work/initial.before.semantic.txt" "$work/$phase.before.semantic.txt"
    cmp "$work/initial.dbg.c" "$work/$phase.dbg.c"
    cmp "$work/initial.before.source.c" "$work/$phase.before.source.c"
done
cmp "$work/reopened.dbg" "$work/repeat.dbg"
if [[ ${FORGE_EXPECT_DEFAULT_UID_DRIFT:-0} == 1 ]]; then
    if cmp -s "$work/initial.dbg" "$work/reopened.dbg"; then
        echo 'baseline did not reproduce undefined type ordering drift' >&2
        exit 1
    fi
    diff -u "$work/initial.before.raw.txt" "$work/reopened.before.raw.txt" \
        > "$work/model.diff" || test "$?" == 1
    echo 'initial-versus-reopened=REPRODUCED_BASELINE_DIFFERENCE' > "$work/result.txt"
else
    for phase in reopened repeat; do
        cmp "$work/initial.dbg" "$work/$phase.dbg"
        cmp "$work/initial.before.raw.txt" "$work/$phase.before.raw.txt"
    done
    echo 'initial-versus-reopened=BYTE_IDENTICAL' > "$work/result.txt"
fi
sha256sum -c "$work/originals.sha256" > "$work/original-preservation.txt"
sha256sum "$work/initial.dbg" "$work/reopened.dbg" "$work/repeat.dbg" \
    "$work/initial.dbg.c" "$work/reopened.dbg.c" "$work/repeat.dbg.c" \
    > "$work/artifacts.sha256"
printf '%s\n' 'before-after-export-model=UNCHANGED' 'normalized-model=IDENTICAL' \
    'synthetic-source=IDENTICAL' 'repeat-reopened=BYTE_IDENTICAL' >> "$work/result.txt"
cat "$work/result.txt"
echo 'saved-program-determinism=PASS'
