#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
    echo "usage: $0 <installed-ghidra-dir>" >&2
    exit 64
fi
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
root="$repository/build/test-results/compression-cancellation"
mkdir -p "$root"
work=$(mktemp -d "$root/run.XXXXXXXX")
mkdir "$work/projects" "$work/output"
echo "compression-cancellation results=$work"
input="$repository/build/fixtures/x86_64/semantic.exec.stripped"
output="$work/output/previous.dbg"
sha256sum "$input" > "$work/input.sha256"
printf 'previous artifact\n' > "$output"
printf 'previous source\n' > "$output.c"
"$ghidra/support/analyzeHeadless" "$work/projects" CompressionCancellation \
    -deleteProject -import "$input" -analysisTimeoutPerFile 120 \
    -scriptPath "$repository/src/test/integration/ghidra_scripts" \
    -postScript CancelDuringCompression.java "$input" "$output" > "$work/export.log" 2>&1
grep -Fq 'production-compression-cancellation=PASS polls=5' "$work/export.log"
grep -Fq 'production-compression-retry=PASS' "$work/export.log"
test "$(grep -c 'GhidraDwarfForge report: {.*"status":"CANCELLED"' "$work/export.log")" = 1
test "$(grep -c 'GhidraDwarfForge report: {.*"status":"PARTIAL"' "$work/export.log")" = 1
sha256sum -c "$work/input.sha256" > "$work/preservation.txt"
readelf --debug-dump=info --debug-dump=abbrev --debug-dump=decodedline \
    --debug-dump=Ranges --debug-dump=loc --debug-dump=aranges "$output" \
    > "$work/readelf.txt" 2> "$work/readelf.stderr"
test ! -s "$work/readelf.stderr"
llvm-dwarfdump --verify "$output" > "$work/llvm.txt" 2>&1
python3 "$repository/src/test/integration/check-dwarfdump.py" \
    "$output" "$work/strict.txt" --original "$input"
echo 'compression-cancellation=PASS'
