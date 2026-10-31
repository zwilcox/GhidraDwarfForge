#!/usr/bin/env bash
set -euo pipefail

# Linux x86-64 compiler-DWARF container oracle, independent of Ghidra/native producers.
# Requires Java 21+, a C compiler, GNU binutils, LLVM dwarfdump, libdwarf dwarfdump,
# and gdb-multiarch (or gdb). About 5 GiB of temporary disk space is needed; the
# large sparse input and sidecars are removed after validation, including failures.
# This bounds source-copy memory, not Ghidra analysis or generated DWARF/model memory.
if [[ $# -gt 1 ]]; then
    echo "usage: $0 [result-root]" >&2
    exit 64
fi
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
    echo "large ELF runtime oracle requires a Linux x86-64 host" >&2
    exit 64
fi
repository_dir=$(realpath "$(dirname "$0")/../../..")
result_root=${1:-"$repository_dir/build/test-results/large-elf-sidecar"}
mkdir -p "$result_root"
result_root=$(realpath "$result_root")
work=$(mktemp -d "$result_root/run.XXXXXXXX")
cleanup() {
    rm -f -- "$work/large.elf" "$work/large.dbg" "$work/large.repeat.dbg" \
        "$work/overflow32.elf"
}
trap cleanup EXIT
debugger=${GDB:-gdb-multiarch}
if ! command -v "$debugger" >/dev/null 2>&1; then
    debugger=gdb
fi
for dependency in java javac cc readelf llvm-dwarfdump dwarfdump "$debugger"; do
    command -v "$dependency" >/dev/null || {
        echo "missing dependency: $dependency" >&2
        exit 69
    }
done
cat >"$work/fixture.c" <<'EOF'
volatile int large_value = 7;

__attribute__((noinline)) int large_entry(int value)
{
    large_value = value;
    return large_value;
}

int main(void)
{
    return large_entry(42) == 42 ? 0 : 1;
}
EOF
cc -O0 -g -gdwarf-5 -fno-pie -no-pie "$work/fixture.c" -o "$work/fixture.elf"
mkdir "$work/classes"
javac -d "$work/classes" \
    "$repository_dir/src/main/java/ghidradwarfforge/elf/ElfImage.java" \
    "$repository_dir/src/main/java/ghidradwarfforge/elf/ElfLocalFunctionSymbol.java" \
    "$repository_dir/src/main/java/ghidradwarfforge/elf/DynamicSymbolMirror.java" \
    "$repository_dir/src/main/java/ghidradwarfforge/elf/ElfLoadAllocations.java" \
    "$repository_dir/src/main/java/ghidradwarfforge/elf/MipsDynamicSymbols.java" \
    "$repository_dir/src/main/java/ghidradwarfforge/elf/SectionlessDynamicSymbols.java" \
    "$repository_dir/src/main/java/ghidradwarfforge/elf/SectionlessUnwind.java" \
    "$repository_dir/src/main/java/ghidradwarfforge/elf/MatchedElfSidecarWriter.java" \
    "$repository_dir/src/test/java/ghidradwarfforge/elf/LargeElfSidecarSmoke.java"
java -Xmx64m -cp "$work/classes" ghidradwarfforge.elf.LargeElfSidecarSmoke \
    "$work/fixture.elf" "$work" | tee "$work/writer.txt"

readelf -h -W "$work/large.elf" >"$work/input-header.txt" 2>"$work/readelf.stderr"
readelf -h -S -n -W "$work/large.dbg" >"$work/sidecar-elf.txt" 2>>"$work/readelf.stderr"
for section in info abbrev aranges decodedline Ranges loc; do
    readelf --debug-dump="$section" "$work/large.dbg" \
        >"$work/readelf-$section.txt" 2>>"$work/readelf.stderr"
done
llvm-dwarfdump --verify "$work/large.dbg" \
    >"$work/llvm-verify.txt" 2>"$work/llvm.stderr"
python3 "$repository_dir/src/test/integration/check-dwarfdump.py" \
    "$work/large.dbg" "$work/dwarfdump.txt" --original "$work/large.elf"
for diagnostic in "$work/readelf.stderr" "$work/llvm.stderr"; do
    if [[ -s "$diagnostic" ]]; then
        cat "$diagnostic" >&2
        exit 1
    fi
done
if grep -Ein '(warning:|error:|FAIL)' "$work"/readelf-*.txt "$work/sidecar-elf.txt" \
        "$work/llvm-verify.txt" "$work/dwarfdump.txt"; then
    echo "large sidecar validator reported a diagnostic" >&2
    exit 1
fi

cat >"$work/commands.gdb" <<EOF
set pagination off
set confirm off
set debuginfod enabled off
set auto-solib-add off
set disable-randomization off
file "$work/large.elf"
symbol-file "$work/large.dbg"
info functions large_entry
ptype large_entry
list large_entry
break large_entry
run
print value
print large_value
next
print large_value
step
continue
EOF
"$debugger" -q -nx -batch -x "$work/commands.gdb" \
    >"$work/gdb.txt" 2>"$work/gdb.stderr"
if [[ -s "$work/gdb.stderr" ]]; then
    cat "$work/gdb.stderr" >&2
    exit 1
fi
grep -Fq 'type = int (int)' "$work/gdb.txt"
grep -Fq 'Breakpoint 1, large_entry (value=42)' "$work/gdb.txt"
grep -Fq 'large_value = value;' "$work/gdb.txt"
grep -Fq '$1 = 42' "$work/gdb.txt"
grep -Fq '$2 = 7' "$work/gdb.txt"
grep -Fq '$3 = 42' "$work/gdb.txt"
grep -Eq 'exited normally' "$work/gdb.txt"
if grep -Eiq 'warning:|error:|No such file|No source file' "$work/gdb.txt"; then
    echo "large sidecar GDB reported a diagnostic" >&2
    exit 1
fi
{
    cat "$work/writer.txt"
    echo 'structural_validators=PASS'
    echo 'gdb_values_source_and_exit=PASS'
    echo 'large-elf-sidecar=PASS'
} >"$work/result.txt"
echo "large-elf-sidecar=PASS results=$work"
