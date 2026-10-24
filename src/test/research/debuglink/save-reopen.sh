#!/usr/bin/env bash
set -euo pipefail

# Isolate export stability across save/reopen. No debuglink attachment occurs here.
if [[ $# -ne 2 ]]; then
    echo "usage: $0 <isolated-ghidra-with-packaged-extension> <source-built-x86-64-exec.stripped>" >&2
    exit 64
fi
repository=$(realpath "$(dirname "$0")/../../../..")
ghidra=$(realpath "$1")
fixture=$(realpath "$2")
root="$repository/build/test-results/debuglink-save-reopen"
mkdir -p "$root"
work=$(mktemp -d "$root/run.XXXXXXXX")
mkdir -p "$work/project"
echo "save-reopen-results=$work"
input="$work/original.elf"
output="$input.dbg"
cp --preserve=all "$fixture" "$input"
sha256sum "$fixture" "$input" > "$work/originals.sha256"
entry=$(readelf -h "$input" | awk '/Entry point address:/ { print $NF }')
for phase in initial reopened repeat; do
    options=(-process original.elf -noanalysis -readOnly)
    if [[ "$phase" == initial ]]; then
        options=(-import "$input" -loader ElfLoader -analysisTimeoutPerFile 120
            -postScript CurateDebuglinkEntry.java "$entry")
    fi
    "$ghidra/support/analyzeHeadless" "$work/project" SaveReopenResearch \
        -scriptPath "$repository/src/test/research/debuglink/ghidra_scripts" "${options[@]}" \
        -postScript SnapshotDebuglinkModel.java "$input" "$work/$phase.before" \
        -postScript GhidraDwarfForge.java --packaged-natives "--input=$input" "--output=$output" \
        -postScript SnapshotDebuglinkModel.java "$input" "$work/$phase.after" \
        > "$work/$phase.log" 2>&1
    grep -Fq 'GhidraDwarfForge symbol export PASS' "$work/$phase.log"
    test -f "$work/$phase.after.semantic.txt"
    cmp "$work/$phase.before.raw.txt" "$work/$phase.after.raw.txt"
    cp "$output" "$work/$phase.dbg"
    cp "$output.c" "$work/$phase.dbg.c"
    readelf --debug-dump=info "$output" > "$work/$phase.info.txt" 2> "$work/$phase.info.stderr"
    test ! -s "$work/$phase.info.stderr"
done
for phase in reopened repeat; do
    cmp "$work/initial.before.semantic.txt" "$work/$phase.before.semantic.txt"
    cmp "$work/initial.dbg.c" "$work/$phase.dbg.c"
done
cmp "$work/reopened.dbg" "$work/repeat.dbg"
sha256sum -c "$work/originals.sha256" > "$work/original-preservation.txt"
sha256sum "$work/initial.dbg" "$work/reopened.dbg" "$work/repeat.dbg" \
    "$work/initial.dbg.c" "$work/reopened.dbg.c" > "$work/artifacts.sha256"
if cmp -s "$work/initial.dbg" "$work/reopened.dbg"; then
    echo 'initial-versus-reopened=BYTE_IDENTICAL' > "$work/result.txt"
else
    echo 'initial-versus-reopened=DIFFERS_WITH_EQUAL_NORMALIZED_MODEL' > "$work/result.txt"
    diff -u "$work/initial.before.raw.txt" "$work/reopened.before.raw.txt" \
        > "$work/model.diff" || test "$?" == 1
    diff -u "$work/initial.info.txt" "$work/reopened.info.txt" \
        > "$work/dwarf-info.diff" || test "$?" == 1
fi
printf '%s\n' 'before-after-export-model=UNCHANGED' 'normalized-model=IDENTICAL' \
    'synthetic-source=IDENTICAL' 'repeat-reopened=BYTE_IDENTICAL' >> "$work/result.txt"
cat "$work/result.txt"
