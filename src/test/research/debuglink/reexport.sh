#!/usr/bin/env bash
set -euo pipefail

# Research only. The target and backup below are private copies created by this test.
if [[ $# -ne 2 ]]; then
    echo "usage: $0 <isolated-ghidra-with-packaged-extension> <source-built-x86-64-exec.stripped>" >&2
    exit 64
fi
repository=$(realpath "$(dirname "$0")/../../../..")
ghidra=$(realpath "$1")
fixture=$(realpath "$2")
root="$repository/build/test-results/debuglink-reexport"
mkdir -p "$root"
work=$(mktemp -d "$root/run.XXXXXXXX")
mkdir -p "$work/project" "$work/classes" "$work/empty-debug-root"
echo "debuglink-reexport-results=$work"
input="$work/original.elf"
backup="$work/original.elf.pre-debuglink"
output="$input.dbg"
cp --preserve=all "$fixture" "$input"
sha256sum "$fixture" > "$work/fixture.sha256"
input_hash=$(sha256sum "$input" | cut -d' ' -f1)
entry=$(readelf -h "$input" | awk '/Entry point address:/ { print $NF }')
"$ghidra/support/analyzeHeadless" "$work/project" DebuglinkResearch \
    -import "$input" -loader ElfLoader -analysisTimeoutPerFile 120 \
    -scriptPath "$repository/src/test/research/debuglink/ghidra_scripts" \
    -postScript CurateDebuglinkEntry.java "$entry" \
    > "$work/import-and-curate.log" 2>&1
grep -Fq 'debuglink-research-analyst-name=APPLIED' "$work/import-and-curate.log"
# Export the saved curated project. The independent save-reopen.sh records the
# separate initial-import versus reopened type-ordering finding.
wrapper="$ghidra/Ghidra/Extensions/GhidraDwarfForge/support/ghidra-dwarf-forge-headless"
"$wrapper" "--ghidra-dir=$ghidra" "--project-dir=$work/project" \
    --project-name=DebuglinkResearch --program=original.elf \
    "--input=$input" "--output=$output" "--log=$work/initial-export.log" \
    > "$work/initial-export-console.txt" 2>&1
grep -Fq 'GhidraDwarfForge symbol export PASS' "$work/initial-export.log"
cp "$output" "$work/initial.dbg"
cp "$output.c" "$work/initial.dbg.c"
test ! -e "$backup"
cp --preserve=all "$input" "$backup"
objcopy "--add-gnu-debuglink=$output" "$input" "$work/attached.stage"
javac --release 21 -d "$work/classes" \
    "$repository/src/main/java/ghidradwarfforge/elf/ElfImage.java" \
    "$repository/src/main/java/ghidradwarfforge/elf/ExecutableProgramBytes.java" \
    "$repository/src/main/java/ghidradwarfforge/elf/DebuglinkCandidateContent.java" \
    "$repository/src/main/java/ghidradwarfforge/output/FileDigests.java" \
    "$repository/src/test/research/debuglink/DebuglinkToolProbe.java"
java -cp "$work/classes" ghidradwarfforge.elf.DebuglinkToolProbe \
    "$input" "$work/attached.stage" "$output" \
    "$(python3 -c 'import base64,os,sys; print(base64.b64encode(os.fsencode(os.path.basename(sys.argv[1]))).decode("ascii"))' "$output")" > "$work/attachment-probe.txt"
mv "$work/attached.stage" "$input"
attached_hash=$(sha256sum "$input" | cut -d' ' -f1)
test "$attached_hash" != "$input_hash"
status=0
"$wrapper" "--ghidra-dir=$ghidra" "--project-dir=$work/project" \
    --project-name=DebuglinkResearch --program=original.elf \
    "--output=$work/rejected.dbg" > "$work/imported-hash-rejection.log" 2>&1 || status=$?
test "$status" == 10
grep -Fq "does not match Ghidra's imported executable SHA-256" "$work/imported-hash-rejection.log"
test ! -e "$work/rejected.dbg" && test ! -e "$work/rejected.dbg.c"
"$wrapper" "--ghidra-dir=$ghidra" "--project-dir=$work/project" \
    --project-name=DebuglinkResearch --program=original.elf \
    "--input=$backup" "--output=$output" "--log=$work/backup-reexport.log" \
    > "$work/backup-reexport-console.txt" 2>&1
grep -Fq 'GhidraDwarfForge symbol export PASS' "$work/backup-reexport.log"
cmp "$work/initial.dbg" "$output"
cmp "$work/initial.dbg.c" "$output.c"
readelf -h -S -n --debug-dump=info --debug-dump=abbrev --debug-dump=aranges \
    --debug-dump=decodedline --debug-dump=Ranges --debug-dump=loc "$output" \
    > "$work/readelf.txt" 2> "$work/readelf.stderr"
llvm-dwarfdump --verify "$output" > "$work/llvm.txt" 2> "$work/llvm.stderr"
dwarfdump "$output" > "$work/dwarfdump.txt" 2> "$work/dwarfdump.stderr"
for validator in readelf llvm dwarfdump; do
    test ! -s "$work/$validator.stderr"
    if grep -Ei 'warning:|error:' "$work/$validator.txt"; then
        echo "unexpected $validator diagnostic" >&2
        exit 1
    fi
done
test "$(sha256sum "$input" | cut -d' ' -f1)" == "$attached_hash"
test "$(sha256sum "$backup" | cut -d' ' -f1)" == "$input_hash"
sha256sum -c "$work/fixture.sha256" > "$work/fixture-preservation.txt"
gdb -q -nx -batch -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex "set debug-file-directory $work/empty-debug-root" -ex "file $input" \
    -ex 'info functions debuglink_analyst_entry' \
    -ex 'python symbol=gdb.lookup_global_symbol("debuglink_analyst_entry") or gdb.lookup_static_symbol("debuglink_analyst_entry"); assert symbol is not None; print("OBJFILE="+symbol.symtab.objfile.filename)' \
    > "$work/gdb.txt" 2> "$work/gdb.stderr"
test ! -s "$work/gdb.stderr"
grep -Fxq "OBJFILE=$output" "$work/gdb.txt"
printf '%s\n' 'mutated-original-imported-hash-rejected=PASS' \
    'explicit-backup-reexport=PASS' 'curated-program-name-preserved=PASS' \
    'reopened-program-byte-identical-rerun=PASS' 'fixture-and-backup-preserved=PASS' \
    'structural-validators=PASS' 'automatic-debuglink-lookup=PASS' > "$work/result.txt"
echo debuglink-backup-reexport=PASS
