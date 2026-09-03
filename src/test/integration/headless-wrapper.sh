#!/usr/bin/env bash
set -euo pipefail

repository_dir=$(realpath "$(dirname "$0")/../../..")
wrapper="$repository_dir/support/ghidra-dwarf-forge-headless"
fake_ghidra="$repository_dir/src/test/integration/fixtures/fake-ghidra"
work=$(mktemp -d -t ghidra-dwarf-forge-wrapper-test.XXXXXXXX)

cleanup() {
    case "$work" in
        /tmp/ghidra-dwarf-forge-wrapper-test.*) rm -rf -- "$work" ;;
        *) echo "refusing to remove unexpected test path: $work" >&2 ;;
    esac
}
trap cleanup EXIT

consumer="$work/libdwarf.so"
producer="$work/libdwarfp.so"
input="$work/fixture.elf"
output="$work/fixture.elf.dbg"
argument_log="$work/arguments.txt"
touch "$consumer" "$producer" "$input"

run_status() {
    local expected=$1 report_status=$2 launcher_status=$3
    shift 3
    set +e
    FAKE_ARGUMENT_LOG="$argument_log" FAKE_REPORT_STATUS="$report_status" \
        FAKE_HEADLESS_EXIT="$launcher_status" "$wrapper" \
        --ghidra-dir="$fake_ghidra" --libdwarf="$consumer" --libdwarfp="$producer" \
        "$@" >"$work/output.txt" 2>"$work/error.txt"
    local actual=$?
    set -e
    if [[ "$actual" != "$expected" ]]; then
        echo "expected wrapper exit $expected, found $actual" >&2
        cat "$work/output.txt" "$work/error.txt" >&2
        exit 1
    fi
}

run_status 0 SUCCESS 0 --import="$input" --output="$output" \
    --analysis-timeout=45 --log="$work/success.log"
grep -Fxq -- '-deleteProject' "$argument_log"
grep -Fxq -- '-import' "$argument_log"
grep -Fxq -- "$input" "$argument_log"
grep -Fxq -- '-analysisTimeoutPerFile' "$argument_log"
grep -Fxq -- '45' "$argument_log"
grep -Fxq -- "--input=$input" "$argument_log"
grep -Fxq -- "--output=$output" "$argument_log"

run_status 0 PARTIAL 0 --import="$input"
run_status 10 FATAL 0 --import="$input"
run_status 11 CANCELLED 0 --import="$input"
run_status 12 NONE 0 --import="$input"
run_status 12 MULTIPLE 0 --import="$input"
run_status 12 SUCCESS 9 --import="$input"

project_dir="$work/projects"
mkdir "$project_dir"
run_status 0 SUCCESS 0 --project-dir="$project_dir" --project-name=Existing \
    --program=/folder/program --input="$input"
grep -Fxq -- '-readOnly' "$argument_log"
grep -Fxq -- '-noanalysis' "$argument_log"
grep -Fxq -- '-process' "$argument_log"
grep -Fxq -- '/folder/program' "$argument_log"
if grep -Fxq -- '-deleteProject' "$argument_log"; then
    echo "existing-project wrapper would delete the project" >&2
    exit 1
fi

run_status 64 NONE 0 --import="$input" --unknown=value

set +e
FAKE_ARGUMENT_LOG="$argument_log" FAKE_REPORT_STATUS=SUCCESS FAKE_HEADLESS_EXIT=0 \
    "$wrapper" --ghidra-dir="$fake_ghidra" --import="$input" \
    >"$work/output.txt" 2>"$work/error.txt"
packaged_status=$?
set -e
test "$packaged_status" = 0
grep -Fxq -- '--packaged-natives' "$argument_log"

echo headless-wrapper=PASS
