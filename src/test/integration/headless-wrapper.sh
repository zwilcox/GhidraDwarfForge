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
run_status 0 SUCCESS 0 --import="$input" --output="$output" --gdb-loader
grep -Fxq -- '--gdb-loader' "$argument_log"
selection="$work/formatter selection λ.json"
printf 'selection sentinel\n' >"$selection"
run_status 0 SUCCESS 0 --import="$input" --output="$output" --formatters="$selection"
grep -Fxq -- "--formatters=$selection" "$argument_log"
run_status 64 SUCCESS 0 --import="$input" --formatters=
run_status 0 SUCCESS 0 --import="$input" --output="$output" --compress-debug-sections=zlib
grep -Fxq -- '--compress-debug-sections=zlib' "$argument_log"
run_status 0 SUCCESS 0 --import="$input" --output="$output" --compress-debug-sections=none
if grep -Fq -- '--compress-debug-sections=' "$argument_log"; then
    echo 'explicit none unexpectedly changed default exporter arguments' >&2
    exit 1
fi
run_status 64 SUCCESS 0 --import="$input" --output="$output" --compress-debug-sections=zstd
for mode in assembly pcode both; do
    run_status 0 SUCCESS 0 --import="$input" --output="$output" --source-context="$mode"
    grep -Fxq -- "--source-context=$mode" "$argument_log"
done
run_status 0 SUCCESS 0 --import="$input" --output="$output" --source-context=off
if grep -Fq -- '--source-context=' "$argument_log"; then
    echo 'off unexpectedly changed default exporter arguments' >&2
    exit 1
fi
run_status 64 SUCCESS 0 --import="$input" --source-context=invalid
for target in 1 8 1000 2147483647; do
    run_status 0 SUCCESS 0 --import="$input" --output="$output" --source-lines="$target"
    grep -Fxq -- "--source-lines=$target" "$argument_log"
done
run_status 0 SUCCESS 0 --import="$input"
if grep -Fq -- '--source-lines=' "$argument_log"; then
    echo 'default unexpectedly selected multiple source files' >&2
    exit 1
fi
for target in '' 0 -1 +1 01 ' 8' 1.5 2147483648 999999999999999999999999; do
    rm -f -- "$argument_log"
    run_status 64 SUCCESS 0 --import="$input" --source-lines="$target" --log="$input"
    test ! -e "$argument_log"
    grep -Fq -- '--source-lines must be' "$work/error.txt"
done
run_status 0 SUCCESS 0 --import="$input" --output="$output" \
    --annotation-record-limit=123 --annotation-text-limit=456 --annotation-source-limit=789
for option in --annotation-record-limit=123 --annotation-text-limit=456 --annotation-source-limit=789; do
    grep -Fxq -- "$option" "$argument_log"
done

run_status 0 SUCCESS 0 --import="$input" --synthesize-unwind=conditioned \
    --unwind-stack-separation=100:107 --unwind-relocated-pointers=fixed
for option in --synthesize-unwind=conditioned --unwind-stack-separation=100:107 --unwind-relocated-pointers=fixed; do
    grep -Fxq -- "$option" "$argument_log"
done

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
formatter_hash=$(printf '%s' "$(basename "$explicit_output")" | sha256sum | cut -d ' ' -f 1)
formatter_output="$work/forge_formatters_$formatter_hash.py"
protected=("$input" "$consumer" "$producer" "$selection" "$fake_ghidra/support/analyzeHeadless")
for protected_file in "$override" "$output" "$output.c" "$output.gdb.py" "$output.unwind.json" \
        "$override.dbg" "$override.dbg.c" "$override.dbg.gdb.py" "$override.dbg.unwind.json" \
        "$explicit_output" "$explicit_output.c" "$explicit_output.gdb.py" "$explicit_output.unwind.json" \
        "$project_dir/Existing.gpr" "$project_dir/Existing.lock" \
        "$project_database" "$packaged_library" "$formatter_output" \
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

# Protect previous generations even when this export keeps the single-file default.
source_hash=$(printf '%064d' 0)
source_part="forge-src-000001-$source_hash.c"
source_manifest="forge-src-$source_hash.json"
for name in "$source_part" "$source_manifest"; do
    printf 'source bundle sentinel\n' > "$work/$name"
    sha256sum "$work/$name" >> "$work/protected.sha256"
    reject_log "$work/$name" --import="$input"
    ln "$work/$name" "$work/$name-hard.log"
    ln -s "$work/$name" "$work/$name-symbolic.log"
    reject_log "$work/$name-hard.log" --import="$input" --source-lines=8
    reject_log "$work/$name-symbolic.log" --import="$input"
    for kind in lexical physical; do
        cp "$work/$name" "$work/$kind/$name"
        sha256sum "$work/$kind/$name" >> "$work/protected.sha256"
        reject_log "$work/$kind/$name" --import="$input" --output="$ambiguous_input.dbg"
    done
done
future_manifest="$work/forge-src-$(printf '%064d' 1).json"
reject_log "$future_manifest" --import="$input" --source-lines=8
test ! -e "$future_manifest"
ln -s "$future_manifest" "$work/dangling-part.log"
reject_log "$work/dangling-part.log" --import="$input"
test ! -e "$future_manifest"
mkdir "$work/independent-sources"
run_status 0 SUCCESS 0 --import="$input" --log="$work/independent-sources/$source_part"
reverse_log="$work/independent-sources/preserved.log"
printf 'reverse source alias sentinel\n' > "$reverse_log"
sha256sum "$reverse_log" >> "$work/protected.sha256"
ln -s "$reverse_log" "$work/forge-src-000002-$source_hash.c"
reject_log "$reverse_log" --import="$input"
reverse_future="$work/independent-sources/not-created.log"
ln -s "$reverse_future" "$work/forge-src-000003-$source_hash.c"
reject_log "$reverse_future" --import="$input"
test ! -e "$reverse_future"

reject_log "$input" --import="$input"
reject_log "$selection" --import="$input" --formatters="$selection"
reject_log "$formatter_output" --import="$input" --output="$explicit_output" --formatters="$selection"
ln "$selection" "$work/selection-hardlink.log"
reject_log "$work/selection-hardlink.log" --import="$input" --formatters="$selection"
ln -s "$formatter_output" "$work/formatter-symlink.log"
reject_log "$work/formatter-symlink.log" --import="$input" --output="$explicit_output" --formatters="$selection"
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
reject_log "$explicit_output.unwind.json" --import="$input" --output="$explicit_output" --synthesize-unwind=strict
ln "$explicit_output.unwind.json" "$work/unwind-hardlink.log"
reject_log "$work/unwind-hardlink.log" --import="$input" --output="$explicit_output"
ln -s "$explicit_output.unwind.json" "$work/unwind-symlink.log"
reject_log "$work/unwind-symlink.log" --import="$input" --output="$explicit_output"
reject_log "$output.unwind.json" --import="$input"
reject_log "$override.dbg.unwind.json" --import="$input" --input="$override"
reject_log "$explicit_output.gdb.py" --import="$input" --output="$explicit_output" --gdb-loader
ln "$explicit_output.gdb.py" "$work/companion-hardlink.log"
reject_log "$work/companion-hardlink.log" --import="$input" --output="$explicit_output"
ln -s "$explicit_output.gdb.py" "$work/companion-symlink.log"
reject_log "$work/companion-symlink.log" --import="$input" --output="$explicit_output"
ln "$explicit_output" "$work/output-hardlink.log"
reject_log "$work/output-hardlink.log" --import="$input" --output="$explicit_output"
ln -s "$explicit_output.c" "$work/source-symlink.log"
reject_log "$work/source-symlink.log" --import="$input" --output="$explicit_output"
reject_log "$output" --import="$input"
reject_log "$output.c" --import="$input"
reject_log "$output.gdb.py" --import="$input"
reject_log "$override.dbg" --import="$input" --input="$override"
reject_log "$override.dbg.c" --import="$input" --input="$override"
reject_log "$override.dbg.gdb.py" --import="$input" --input="$override"
reject_log "$work/new.dbg" --import="$input" --output="$work/new.dbg"
test ! -e "$work/new.dbg"
reject_log "$work/new.dbg.c" --import="$input" --output="$work/new.dbg"
test ! -e "$work/new.dbg.c"
reject_log "$work/new.dbg.gdb.py" --import="$input" --output="$work/new.dbg" --gdb-loader
test ! -e "$work/new.dbg.gdb.py"
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

# A newline at the end of a directory component must not disappear while
# deriving the generated formatter path. The log can reach it through an alias
# in an ordinary directory even when the direct unusual log path is refused.
special_directory="$work/"$'formatter-directory\n'
mkdir -p "$special_directory"
special_output="$special_directory/linebreak.dbg"
special_hash=$(printf '%s' linebreak.dbg | sha256sum)
special_hash=${special_hash%% *}
special_formatter="$special_directory/forge_formatters_$special_hash.py"
printf 'formatter generation sentinel\n' > "$special_formatter"
cp "$special_formatter" "$work/formatter-expected.txt"
for kind in hard symbolic; do
    special_log="$work/formatter-$kind.log"
    if [[ "$kind" == hard ]]; then
        ln -- "$special_formatter" "$special_log"
    else
        ln -s -- "$special_formatter" "$special_log"
    fi
    rm -f "$argument_log"
    run_status 64 SUCCESS 0 --import="$input" --output="$special_output" --log="$special_log"
    test ! -e "$argument_log"
    cmp "$work/formatter-expected.txt" "$special_formatter"
    grep -Fq 'log path aliases a protected input/output file' "$work/error.txt"
done

for name in "$source_part" "$source_manifest"; do
    cp "$work/$name" "$special_directory/$name"
    for kind in hard symbolic; do
        special_log="$work/newline-$name-$kind.log"
        if [[ "$kind" == hard ]]; then ln -- "$special_directory/$name" "$special_log"
        else ln -s -- "$special_directory/$name" "$special_log"; fi
        rm -f "$argument_log"
        run_status 64 SUCCESS 0 --import="$input" --output="$special_output" --log="$special_log"
        test ! -e "$argument_log"
        cmp "$work/$name" "$special_directory/$name"
    done
done

echo headless-wrapper=PASS
