#!/usr/bin/env bash
set -euo pipefail

repository_dir=$(realpath "$(dirname "$0")/../../..")
wrapper="$repository_dir/support/ghidra-dwarf-forge-headless"
work=$(mktemp -d -t ghidra-dwarf-forge-wrapper-test.XXXXXXXX)
fake_ghidra="$work/fake-ghidra"
cp -R "$repository_dir/src/test/integration/fixtures/fake-ghidra" "$fake_ghidra"

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
printf 'consumer sentinel\n' >"$consumer"
printf 'producer sentinel\n' >"$producer"
printf 'input sentinel\n' >"$input"

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
awk '$0 == "-loader" { getline; if ($0 == "ElfLoader") found = 1 }
    END { exit !found }' "$argument_log"
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
if grep -Fxq -- '-loader' "$argument_log"; then
    echo "existing-project wrapper would select an import loader" >&2
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

override="$work/override.elf"
explicit_output="$work/explicit.dbg"
project_database="$project_dir/Existing.rep/db.1"
packaged_library="$fake_ghidra/Ghidra/Extensions/GhidraDwarfForge/os/linux_x86_64/libdwarf.so"
mkdir -p "$(dirname "$project_database")" "$(dirname "$packaged_library")"
mkdir -p "$work/lexical" "$work/physical/child"
ln -s "$work/physical/child" "$work/lexical/alias"
ambiguous_input="$work/lexical/alias/../original.elf"
protected=("$input" "$consumer" "$producer" "$fake_ghidra/support/analyzeHeadless")
for protected_file in "$override" "$output" "$output.c" \
        "$override.dbg" "$override.dbg.c" "$explicit_output" "$explicit_output.c" \
        "$project_dir/Existing.gpr" "$project_dir/Existing.lock" \
        "$project_database" "$packaged_library" \
        "$work/lexical/original.elf" "$work/physical/original.elf" \
        "$work/lexical/original.elf.dbg" "$work/lexical/original.elf.dbg.c"; do
    printf 'preserve this file: %s\n' "$protected_file" >"$protected_file"
    protected+=("$protected_file")
done
sha256sum "${protected[@]}" >"$work/protected.sha256"

# A project can hide its original path from the wrapper until after launch.
# An explicit log therefore requires an explicit original in this mode.
rm -f -- "$argument_log"
run_status 64 SUCCESS 0 --project-dir="$project_dir" --project-name=Existing \
    --program=/folder/program --log="$input"
test ! -e "$argument_log"
grep -Fq 'requires --input' "$work/error.txt"
sha256sum -c "$work/protected.sha256" >"$work/preservation.txt"
run_status 0 SUCCESS 0 --project-dir="$project_dir" --project-name=Existing \
    --program=/folder/program

reject_log() {
    local log=$1
    shift
    rm -f -- "$argument_log"
    run_status 64 SUCCESS 0 "$@" --log="$log"
    if [[ -e "$argument_log" ]]; then
        echo "colliding log launched Ghidra: $log" >&2
        exit 1
    fi
    grep -Eq 'log path (aliases|is inside)' "$work/error.txt"
    sha256sum -c "$work/protected.sha256" >"$work/preservation.txt"
}

reject_log "$input" --import="$input"
reject_log "$work/./fixture.elf" --import="$input"
ln -s "$input" "$work/input-symlink.log"
reject_log "$work/input-symlink.log" --import="$input"
ln "$input" "$work/input-hardlink.log"
reject_log "$work/input-hardlink.log" --import="$input"
ln -s "$work" "$work/alias-directory"
reject_log "$work/alias-directory/fixture.elf" --import="$input"
reject_log "$work/lexical/original.elf" --project-dir="$project_dir" \
    --project-name=Existing --program=/program --input="$ambiguous_input"
reject_log "$work/physical/original.elf" --import="$ambiguous_input"
reject_log "$work/lexical/original.elf.dbg" --import="$input" --input="$ambiguous_input"
reject_log "$work/lexical/original.elf.dbg.c" --import="$input" --input="$ambiguous_input"
reject_log "$work/lexical/original.elf.dbg" --import="$input" --output="$ambiguous_input.dbg"
reject_log "$work/lexical/original.elf.dbg.c" --import="$input" --output="$ambiguous_input.dbg"
# tee itself follows the raw path; log normalization must not change its meaning.
reject_log "$ambiguous_input" --import="$work/physical/original.elf"
reject_log "$input" --import="$input" --input="$override"
reject_log "$override" --import="$input" --input="$override"
reject_log "$explicit_output" --import="$input" --output="$explicit_output"
reject_log "$explicit_output.c" --import="$input" --output="$explicit_output"
ln "$explicit_output" "$work/output-hardlink.log"
reject_log "$work/output-hardlink.log" --import="$input" --output="$explicit_output"
ln -s "$explicit_output.c" "$work/source-symlink.log"
reject_log "$work/source-symlink.log" --import="$input" --output="$explicit_output"
reject_log "$output" --import="$input"
reject_log "$output.c" --import="$input"
reject_log "$override.dbg" --import="$input" --input="$override"
reject_log "$override.dbg.c" --import="$input" --input="$override"
reject_log "$work/new.dbg" --import="$input" --output="$work/new.dbg"
test ! -e "$work/new.dbg"
reject_log "$work/new.dbg.c" --import="$input" --output="$work/new.dbg"
test ! -e "$work/new.dbg.c"
ln -s "$work/new.dbg" "$work/dangling-output.log"
reject_log "$work/dangling-output.log" --import="$input" --output="$work/new.dbg"
test ! -e "$work/new.dbg"
reject_log "$consumer" --import="$input"
ln "$producer" "$work/producer-hardlink.log"
reject_log "$work/producer-hardlink.log" --import="$input"
reject_log "$fake_ghidra/support/analyzeHeadless" --import="$input"
reject_log "$packaged_library" --import="$input"
ln "$packaged_library" "$work/packaged-hardlink.log"
reject_log "$work/packaged-hardlink.log" --import="$input"
for project_file in "$project_dir/Existing.gpr" "$project_dir/Existing.lock" \
        "$project_database" "$project_dir/Existing.rep/new-file"; do
    reject_log "$project_file" --project-dir="$project_dir" --project-name=Existing \
        --program=/folder/program --input="$input"
done
test ! -e "$project_dir/Existing.rep/new-file"
ln "$project_database" "$work/project-hardlink.log"
reject_log "$work/project-hardlink.log" --project-dir="$project_dir" \
    --project-name=Existing --program=/folder/program --input="$input"
ln -s "$project_dir/Existing.rep" "$work/project-symlink"
reject_log "$work/project-symlink/db.1" --project-dir="$project_dir" \
    --project-name=Existing --program=/folder/program --input="$input"

# Independent logs remain usable, including symlink and hardlink spellings.
touch "$work/independent.log"
ln -s "$work/independent.log" "$work/independent-symlink.log"
run_status 0 SUCCESS 0 --import="$input" --log="$work/independent-symlink.log"
ln "$work/independent.log" "$work/independent-hardlink.log"
run_status 0 SUCCESS 0 --import="$input" --log="$work/independent-hardlink.log"
(
    cd "$work"
    run_status 0 SUCCESS 0 --import="$input" --log=-report.log
    grep -Fq -- 'GhidraDwarfForge report: ' -report.log
)
sha256sum -c "$work/protected.sha256" >"$work/preservation.txt"

echo headless-wrapper=PASS
