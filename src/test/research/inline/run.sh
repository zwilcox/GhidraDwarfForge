#!/usr/bin/env bash
set -euo pipefail

# Research fixture: Linux x86-64, GCC, GDB and Ghidra 12.0.3; no Forge natives.
if [[ $# -ne 1 ]]; then
    echo "usage: $0 <ghidra-12.0.3-directory>" >&2
    exit 64
fi
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
    echo "this bounded research probe requires a Linux x86-64 host" >&2
    exit 69
fi
for dependency in gcc objcopy readelf llvm-dwarfdump gdb python3 sha256sum; do
    command -v "$dependency" >/dev/null || {
        echo "missing research dependency: $dependency" >&2
        exit 69
    }
done
ghidra=$(realpath "$1")
grep -Fxq 'application.version=12.0.3' "$ghidra/Ghidra/application.properties"
test -x "$ghidra/support/analyzeHeadless"
script_directory=$(realpath "$(dirname "$0")")
repository=$(realpath "$script_directory/../../../..")
result_root="$repository/build/test-results/inline-evidence"
mkdir -p "$result_root"
work=$(mktemp -d "$result_root/run.XXXXXXXX")
echo "inline-evidence-results=$work"
export LC_ALL=C.UTF-8
export TZ=UTC
export DEBUGINFOD_URLS=

cp "$script_directory/inline-evidence.c" "$work/inline-evidence.c"
gcc -O2 -g -gdwarf-5 -fno-pie -no-pie -fno-omit-frame-pointer \
    -fno-optimize-sibling-calls -Wall -Wextra -Werror \
    "$work/inline-evidence.c" -o "$work/inline.debug"
objcopy --strip-debug "$work/inline.debug" "$work/inline.no-debug"
sha256sum "$work/inline.debug" "$work/inline.no-debug" > "$work/originals.sha256"
"$work/inline.debug"
"$work/inline.no-debug"
gcc --version > "$work/gcc-version.txt"
gdb --version > "$work/gdb-version.txt"
readelf --version > "$work/readelf-version.txt"
llvm-dwarfdump --version > "$work/llvm-version.txt"
cp "$ghidra/Ghidra/application.properties" "$work/ghidra-application.properties"
readelf --debug-dump=info "$work/inline.debug" > "$work/compiler-info.txt" \
    2> "$work/compiler-info.stderr"
readelf --debug-dump=decodedline "$work/inline.debug" > "$work/compiler-lines.txt" \
    2> "$work/compiler-lines.stderr"
readelf --debug-dump=Ranges "$work/inline.debug" > "$work/compiler-ranges.txt" \
    2> "$work/compiler-ranges.stderr"
test ! -s "$work/compiler-info.stderr"
test ! -s "$work/compiler-lines.stderr"
test ! -s "$work/compiler-ranges.stderr"
test "$(grep -c 'DW_TAG_inlined_subroutine' "$work/compiler-info.txt")" -ge 2
grep -Fq 'DW_AT_abstract_origin' "$work/compiler-info.txt"
grep -Fq 'DW_AT_call_line' "$work/compiler-info.txt"
llvm-dwarfdump --verify "$work/inline.debug" > "$work/llvm-verify.txt" 2>&1

inline_line=$(awk '/INLINE_BREAK/ { print NR }' "$work/inline-evidence.c")
cat > "$work/compiler.gdb" <<EOF
set pagination off
set confirm off
set debuginfod enabled off
set auto-solib-add off
file $work/inline.debug
break $work/inline-evidence.c:$inline_line
run
bt
printf "compiler-inline-value=%d\\n", value
printf "compiler-inline-local=%d\\n", inline_local
disable breakpoints
continue
quit
EOF
gdb --nx --batch -x "$work/compiler.gdb" > "$work/compiler-gdb.txt" \
    2> "$work/compiler-gdb.stderr"
test ! -s "$work/compiler-gdb.stderr"
grep -Eq '^#0[[:space:]]+compiler_inline' "$work/compiler-gdb.txt"
grep -Eq '^#1[[:space:]].*inline_caller' "$work/compiler-gdb.txt"
grep -Fxq 'compiler-inline-value=4' "$work/compiler-gdb.txt"
grep -Fxq 'compiler-inline-local=11' "$work/compiler-gdb.txt"
grep -Eq 'exited normally' "$work/compiler-gdb.txt"

# Retain the exact installed sources/help used by the decision, not a moving branch.
python3 - "$ghidra" "$work" <<'PY'
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile
import sys

ghidra, work = map(Path, sys.argv[1:])
files = {
    'Framework/SoftwareModeling/lib/SoftwareModeling-src.zip': [
        'ghidra/program/model/listing/Function.java',
        'ghidra/program/database/function/FunctionDB.java',
        'ghidra/program/model/pcode/HighFunction.java',
        'ghidra/program/model/sourcemap/SourceMapEntry.java',
    ],
    'Features/Base/lib/Base-src.zip': [
        'ghidra/app/util/bin/format/dwarf/DWARFFunction.java',
        'ghidra/app/util/bin/format/dwarf/DWARFFunctionImporter.java',
        'ghidra/app/util/bin/format/dwarf/DWARFImportOptions.java',
    ],
    'Features/Decompiler/lib/Decompiler-src.zip': [
        'ghidra/app/decompiler/ClangFunction.java',
        'ghidra/app/decompiler/ClangNode.java',
    ],
    'Features/Base/lib/Base.jar': ['help/topics/FunctionPlugin/Variables.htm'],
    'Features/Decompiler/lib/Decompiler.jar': [
        'help/topics/DecompilePlugin/DecompilerAnnotations.html',
    ],
}
manifest = []
for archive_path, names in files.items():
    with ZipFile(ghidra / 'Ghidra' / archive_path) as archive:
        for name in names:
            data = archive.read(name)
            output = work / 'pinned-source' / name
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
            manifest.append(f'{sha256(data).hexdigest()}  {archive_path}!/{name}')
(work / 'pinned-source-sha256.txt').write_text('\n'.join(manifest) + '\n')
PY

for mode in debug no-debug; do
    mkdir -p "$work/project-$mode" "$work/$mode"
    "$ghidra/support/analyzeHeadless" "$work/project-$mode" InlineResearch \
        -import "$work/inline.$mode" -loader ElfLoader \
        -scriptPath "$script_directory" \
        -preScript InlineEvidenceProbe.java configure \
        -postScript InlineEvidenceProbe.java "$work/$mode" "$mode" \
        -deleteProject > "$work/headless-$mode.log" 2>&1
    grep -Fxq 'inline-evidence-probe=PASS' "$work/$mode/observations.txt"
done
sha256sum -c "$work/originals.sha256" > "$work/input-preservation.txt"
printf '%s\n' 'compiler-inline-dwarf-and-gdb=PASS' \
    'debug-and-no-debug-ghidra-probes=PASS' \
    'ordinary-call-versus-decompiler-inline-flag=PASS' \
    'original-input-preservation=PASS' 'inline-evidence=PASS' | tee "$work/result.txt"
