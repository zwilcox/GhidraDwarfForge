#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp>" >&2
    exit 2
fi

repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture="$repository_dir/build/fixtures/x86_64/semantic.exec.stripped"
sidecar="$fixture.dbg"
source="$sidecar.c"
result_dir="$repository_dir/build/test-results/output-path-policy"
missing="$result_dir/original-was-moved"
mkdir -p "$result_dir"
test ! -e "$missing"

before=$(sha256sum "$fixture" | cut -d' ' -f1)
GHIDRA_USE_DEFAULT_OUTPUT=1 GHIDRA_STALE_EXECUTABLE_PATH="$missing" \
    FIXTURE_ROLE=exec "$repository_dir/src/test/integration/headless-symbol-export.sh" \
    "$1" "$2" "$3" x86_64
after=$(sha256sum "$fixture" | cut -d' ' -f1)
test "$before" = "$after"
test -s "$sidecar"
test -s "$source"
if find "$(dirname "$fixture")" -maxdepth 1 \
    \( -name ".$(basename "$sidecar")-*.staged" \
    -o -name ".$(basename "$source")-*.staged" \) -print -quit | grep -q .; then
    echo "default output left a staging file behind" >&2
    exit 1
fi

wrong_input="$repository_dir/build/fixtures/x86_64/semantic.pie.stripped"
failure_output="$result_dir/mismatched-input.dbg"
failure_source="$failure_output.c"
failure_log="$result_dir/fatal-report.log"
failure_projects=$(mktemp -d -t ghidra-dwarf-forge-fatal-report.XXXXXXXX)
test -f "$wrong_input"
rm -f -- "$failure_output" "$failure_source"
"$1/support/analyzeHeadless" \
    "$failure_projects" GhidraDwarfForgeFatalReport \
    -deleteProject \
    -import "$fixture" \
    -analysisTimeoutPerFile 120 \
    -scriptPath "$repository_dir/src/test/integration/ghidra_scripts" \
    -postScript GhidraDwarfForge.java \
    "--libdwarf=$2" "--libdwarfp=$3" \
    "--input=$wrong_input" "--output=$failure_output" \
    >"$failure_log" 2>&1 || true
case "$failure_projects" in
    /tmp/ghidra-dwarf-forge-fatal-report.*) rm -rf -- "$failure_projects" ;;
    *) echo "refusing to remove unexpected temporary path: $failure_projects" >&2; exit 1 ;;
esac
grep -Fq 'GhidraDwarfForge report: {"schemaVersion":1,"status":"FATAL"' \
    "$failure_log"
grep -Fq 'selected original ELF does not match Ghidra' "$failure_log"
test ! -e "$failure_output"
test ! -e "$failure_source"

{
    echo "input_sha256=$after"
    echo "sidecar_sha256=$(sha256sum "$sidecar" | cut -d' ' -f1)"
    echo "source_sha256=$(sha256sum "$source" | cut -d' ' -f1)"
    echo "default_sidecar=$sidecar"
    echo "stale_program_path=$missing"
    echo "output_path_policy=PASS"
    echo "fatal_report=PASS"
} | tee "$result_dir/result.txt"
