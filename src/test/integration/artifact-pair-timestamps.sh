#!/usr/bin/env bash
set -euo pipefail

# Native Linux x86-64: no Ghidra/native producer needed for publication metadata.
repository=$(realpath "$(dirname "$0")/../../..")
for tool in gcc objcopy javac java gdb readelf llvm-dwarfdump dwarfdump python3; do
    command -v "$tool" >/dev/null
done
root="$repository/build/test-results/artifact-pair-timestamps"
mkdir -p "$root"
work=$(mktemp -d "$root/run.XXXXXXXX")
mkdir -p "$work/compiler" "$work/published" "$work/classes"
echo "artifact-pair-timestamp-results=$work"
source="$work/compiler/fixture.dbg.c"
artifact="$work/published/fixture.dbg"
published_source="$artifact.c"
original="$work/original.elf"
cat > "$source" <<'SOURCE'
__attribute__((noinline)) int timestamp_function(void) {
    int value = 7;
    return value;
}
int main(void) {
    return timestamp_function() != 7;
}
SOURCE
gcc -g -gdwarf-5 -O0 -fno-pie -no-pie \
    "-fdebug-prefix-map=$work/compiler=$work/published" "$source" -o "$original"
# A complete compiler-DWARF ELF is a valid symbol-file fixture; objcopy's
# --only-keep-debug container retains empty PT_INTERP payloads that warn in readelf.
cp "$original" "$work/template.dbg"
objcopy --strip-debug "$original"
cp "$work/template.dbg" "$artifact"
cp "$source" "$published_source"
python3 - "$original" "$artifact" "$published_source" <<'PY'
import os, sys
for path, seconds in zip(sys.argv[1:], [1700000010, 1700000001, 1700000002]):
    os.utime(path, ns=(seconds * 1000000000, seconds * 1000000000))
PY
sha256sum "$original" > "$work/original.sha256"
stat -c '%y' "$original" > "$work/original.mtime"

gdb_source() {
    gdb -q -nx -batch -ex 'set pagination off' -ex 'set debuginfod enabled off' \
        -ex 'set auto-solib-add off' -ex "file $original" -ex "symbol-file $artifact" \
        -ex 'python print("SOURCE_OBJFILE=" + gdb.lookup_global_symbol("timestamp_function").symtab.objfile.filename)' \
        -ex 'info files' -ex 'list timestamp_function' "$@"
}

# Force the previously intermittent ordering, with the original executable
# newer than both artifacts. This warning belongs to the .dbg objfile.
gdb_source > "$work/before.txt" 2> "$work/before.stderr"
grep -Fxq "SOURCE_OBJFILE=$artifact" "$work/before.txt"
grep -Fq "$original'" "$work/before.txt"
test "$(cat "$work/before.stderr")" = 'warning: Source file is more recent than executable.'

javac --release 21 -d "$work/classes" \
    "$repository/src/main/java/ghidradwarfforge/output/ArtifactPairPublisher.java" \
    "$repository/src/test/java/ghidradwarfforge/output/ArtifactPairTimestampFixture.java"
java -cp "$work/classes" ghidradwarfforge.output.ArtifactPairTimestampFixture \
    "$work/template.dbg" "$source" "$artifact" "$published_source" > "$work/publication.txt"
readelf -h -S -n --debug-dump=info --debug-dump=abbrev --debug-dump=aranges \
    --debug-dump=decodedline --debug-dump=Ranges --debug-dump=loc \
    "$artifact" > "$work/readelf.txt" 2> "$work/readelf.stderr"
test ! -s "$work/readelf.stderr"
llvm-dwarfdump --verify "$artifact" > "$work/llvm.txt" 2>&1
python3 "$repository/src/test/integration/check-dwarfdump.py" \
    "$artifact" "$work/dwarfdump.txt" --original "$original"
gdb_source -ex 'ptype timestamp_function' -ex 'break timestamp_function' \
    -ex 'python exits=[]; gdb.events.exited.connect(lambda event: exits.append(event.exit_code))' \
    -ex run -ex 'python assert gdb.selected_frame().name() == "timestamp_function"' \
    -ex next -ex 'python assert int(gdb.parse_and_eval("value")) == 7' -ex step \
    -ex 'disable breakpoints' -ex continue -ex 'python assert exits == [0], exits' \
    -ex 'echo TIMESTAMP_GDB_PASS\n' > "$work/after.txt" 2> "$work/after.stderr"
test ! -s "$work/after.stderr"
grep -Fxq 'TIMESTAMP_GDB_PASS' "$work/after.txt"
grep -Fxq "SOURCE_OBJFILE=$artifact" "$work/after.txt"
if grep -Ei '^(warning:|error:|Traceback|AssertionError)' "$work/after.txt"; then
    exit 1
fi

# Later edits must still warn; no GDB warning filter or original-file touch is used.
printf '\n/* later analyst edit */\n' >> "$published_source"
python3 - "$published_source" <<'PY'
import os, sys
os.utime(sys.argv[1], ns=(1700000003000000000, 1700000003000000000))
PY
gdb_source > "$work/edited.txt" 2> "$work/edited.stderr"
test "$(cat "$work/edited.stderr")" = 'warning: Source file is more recent than executable.'
sha256sum -c "$work/original.sha256" > "$work/preservation.txt"
stat -c '%y' "$original" > "$work/original-after.mtime"
cmp "$work/original.mtime" "$work/original-after.mtime"
if find "$work/published" -maxdepth 1 -name '.*' -print | grep -q .; then
    echo 'publication left a staging/backup file' >&2
    exit 1
fi
printf '%s\n' 'separate-debug-objfile-freshness=PASS' 'published-pair-no-warning=PASS' \
    'later-source-edit-warning=PASS' 'original-bytes-and-mtime-preserved=PASS' > "$work/result.txt"
echo artifact-pair-timestamps=PASS
