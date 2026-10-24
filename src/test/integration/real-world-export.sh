#!/usr/bin/env bash
set -euo pipefail

# Linux x86-64 integration against the installed GNU coreutils, without fixture
# preparation or analyst changes. Requires Ghidra 12.0.3 with a native-inclusive
# Forge extension, GNU readelf/coreutils, LLVM llvm-dwarfdump, libdwarf dwarfdump,
# and Python-enabled gdb-multiarch. The host must permit debugging child processes.
# Results are retained, including on failure; no system executable is modified.
if [[ $# -ne 1 ]]; then
    echo "usage: $0 <ghidra-dir-with-installed-native-inclusive-extension>" >&2
    exit 64
fi

export LC_ALL=C
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
    echo "real-world-export requires a Linux x86-64 host" >&2
    exit 1
fi
for dependency in realpath sha256sum readelf llvm-dwarfdump dwarfdump \
        gdb-multiarch timeout cmp; do
    command -v "$dependency" >/dev/null
done

repository_dir=$(realpath "$(dirname "$0")/../../..")
ghidra_dir=$(realpath "$1")
wrapper="$ghidra_dir/Ghidra/Extensions/GhidraDwarfForge/support/ghidra-dwarf-forge-headless"
test -x "$wrapper"
inputs=(/usr/bin/true /usr/bin/basename)
for input in "${inputs[@]}"; do
    test -x "$input"
done

result_root="$repository_dir/build/test-results/real-world-export"
mkdir -p "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
debugger_cwd="$result_dir/unrelated debugger cwd"
mkdir -p "$debugger_cwd"
sha256sum "${inputs[@]}" > "$result_dir/inputs.sha256"
finish() {
    local status=$?
    if ! sha256sum -c "$result_dir/inputs.sha256" \
            > "$result_dir/input-preservation.txt" 2>&1; then
        cat "$result_dir/input-preservation.txt" >&2
        status=1
    fi
    echo "real-world-export results: $result_dir"
    exit "$status"
}
trap finish EXIT
{
    uname -a
    readelf --version
    llvm-dwarfdump --version
    dwarfdump --version
    gdb-multiarch --version
} > "$result_dir/tool-versions.txt" 2>&1

require_empty() {
    if [[ -s "$1" ]]; then
        cat "$1" >&2
        echo "unexpected validator/debugger diagnostic: $1" >&2
        return 1
    fi
}

validate_sidecar() {
    local output=$1 validation_dir=$2 original=$3
    mkdir -p "$validation_dir"
    local readelf_stderr="$validation_dir/readelf.stderr"
    readelf -h "$output" > "$validation_dir/header.txt" 2> "$readelf_stderr"
    readelf -SW "$output" > "$validation_dir/sections.txt" 2>> "$readelf_stderr"
    readelf -n "$output" > "$validation_dir/notes.txt" 2>> "$readelf_stderr"
    local dump
    for dump in info abbrev aranges decodedline Ranges loc; do
        readelf "--debug-dump=$dump" "$output" \
            > "$validation_dir/$dump.txt" 2>> "$readelf_stderr"
    done
    require_empty "$readelf_stderr"
    if grep -Eq '\][[:space:]]+([.]gnu_debug(link|altlink|data)|[.]gdb_index|[.]zdebug_[^[:space:]]*)[[:space:]]' \
            "$validation_dir/sections.txt"; then
        echo "sidecar exposes inherited debug associations or compressed/index data" >&2
        return 1
    fi
    grep -Fq 'DW_TAG_subprogram' "$validation_dir/info.txt"
    grep -Fq 'DW_AT_stmt_list' "$validation_dir/info.txt"
    grep -Fq "${output##*/}.c" "$validation_dir/decodedline.txt"
    llvm-dwarfdump --verify "$output" \
        > "$validation_dir/llvm-dwarfdump.txt" 2> "$validation_dir/llvm-dwarfdump.stderr"
    require_empty "$validation_dir/llvm-dwarfdump.stderr"
    python3 "$repository_dir/src/test/integration/check-dwarfdump.py" \
        "$output" "$validation_dir/dwarfdump.txt" --original "$original"
    if grep -Ei '(^|[[:space:]])(warning|error):' \
            "$validation_dir/llvm-dwarfdump.txt" "$validation_dir/dwarfdump.txt"; then
        echo "independent DWARF validator reported a warning or error" >&2
        return 1
    fi
}

for input in "${inputs[@]}"; do
    name=${input##*/}
    case_dir="$result_dir/source files/$name"
    mkdir -p "$case_dir"
    output="$case_dir/$name.dbg"
    "$input" --version > "$case_dir/coreutils-version.txt"
    grep -Fq '(GNU coreutils)' "$case_dir/coreutils-version.txt"
    readelf -h "$input" > "$case_dir/original-header.txt"
    readelf -SW "$input" > "$case_dir/original-sections.txt"
    readelf -n "$input" > "$case_dir/original-notes.txt"
    grep -Eq 'Class:[[:space:]]+ELF64' "$case_dir/original-header.txt"
    grep -Eq 'Data:.*little endian' "$case_dir/original-header.txt"
    grep -Eq 'Type:[[:space:]]+DYN.*Position-Independent Executable' \
        "$case_dir/original-header.txt"
    grep -Eq 'Machine:.*X86-64' "$case_dir/original-header.txt"
    entry_address=$(awk '/Entry point address:/ { print $NF }' \
        "$case_dir/original-header.txt")
    [[ "$entry_address" =~ ^0x[[:xdigit:]]+$ ]]

    for iteration in first second; do
        echo "real-world-export: $name ($iteration independent import)"
        "$wrapper" --ghidra-dir="$ghidra_dir" --import="$input" \
            --output="$output" --log="$case_dir/$iteration.export.log" \
            > "$case_dir/$iteration.wrapper.txt" 2>&1
        test -s "$output"
        test -s "$output.c"
        grep -Fq 'native policy: verified packaged libraries' \
            "$case_dir/$iteration.export.log"
        grep -Fq 'This is decompiler output, not recovered original source' "$output.c"
        grep -Eq '"status":"(SUCCESS|PARTIAL)"' "$case_dir/$iteration.export.log"
        grep -Fq '"failure":null' "$case_dir/$iteration.export.log"
        validate_sidecar "$output" "$case_dir/$iteration.validation" "$input"
        sha256sum "$output" "$output.c" > "$case_dir/$iteration.sha256"
        sha256sum -c "$result_dir/inputs.sha256" \
            > "$case_dir/$iteration.input-preservation.txt"
    done
    cmp "$case_dir/first.sha256" "$case_dir/second.sha256"

    # Recover the application entry symbol from the emitted startup source. This
    # consumes Ghidra's own analysis, with no fixture symbol or address injection.
    # A breakpoint there lets source stepping resume after libc startup; stepping
    # over __libc_start_main at the ELF entry alone can run all the way to exit.
    mapfile -t application_entries < <(sed -n \
        's/.*__libc_start_main([[:space:]]*\([A-Za-z_][A-Za-z0-9_]*\),.*/\1/p' \
        "$output.c" | sort -u)
    if [[ ${#application_entries[@]} -ne 1 ]]; then
        echo "expected one analyzed __libc_start_main target in $output.c" >&2
        exit 1
    fi
    application_entry=${application_entries[0]}
    run_arguments=()
    if [[ "$name" == basename ]]; then
        run_arguments=(/alpha/path)
    fi
    (
        # Absolute sidecar loading must locate its source without a directory
        # command, substitute-path rule, or a convenient debugger CWD.
        cd "$debugger_cwd"
        timeout 120 gdb-multiarch -q -nx -batch \
            -ex 'set pagination off' -ex 'set confirm off' \
            -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
            -ex 'set disable-randomization off' -ex 'set startup-with-shell off' \
            -ex "file $input" -ex "symbol-file \"$output\"" \
            -ex 'info functions' -ex 'ptype entry' -ex 'list entry' \
            -ex "python assert int(gdb.parse_and_eval('&entry')) == $entry_address, 'entry differs from ELF e_entry'" \
            -ex 'break *entry' -ex "break $application_entry" \
            -ex "run ${run_arguments[*]}" \
            -ex "python assert gdb.selected_frame().name() == 'entry'" \
            -ex "python assert int(gdb.parse_and_eval('\$pc')) == int(gdb.parse_and_eval('&entry'))" \
            -ex "python assert gdb.selected_frame().find_sal().symtab.filename.endswith('$name.dbg.c')" \
            -ex 'info source' -ex 'set $forge_previous_pc = $pc' -ex next \
            -ex "python assert int(gdb.parse_and_eval('\$pc')) != int(gdb.parse_and_eval('\$forge_previous_pc'))" \
            -ex continue \
            -ex "python assert gdb.selected_frame().name() == '$application_entry'" \
            -ex "ptype $application_entry" -ex list \
            -ex 'set $forge_previous_pc = $pc' -ex next \
            -ex "python assert int(gdb.parse_and_eval('\$pc')) != int(gdb.parse_and_eval('\$forge_previous_pc'))" \
            -ex "python assert gdb.selected_frame().find_sal().line > 0" \
            -ex 'set $forge_previous_pc = $pc' -ex step \
            -ex "python assert int(gdb.parse_and_eval('\$pc')) != int(gdb.parse_and_eval('\$forge_previous_pc'))" \
            -ex "python assert gdb.selected_frame().find_sal().line > 0" \
            -ex "python assert gdb.selected_frame().find_sal().symtab.filename.endswith('$name.dbg.c')" \
            -ex frame -ex 'disable breakpoints' -ex continue \
            -ex "python assert int(gdb.parse_and_eval('\$_exitcode')) == 0" \
            -ex 'echo real-world-gdb=PASS\n' \
            > "$case_dir/gdb.txt" 2> "$case_dir/gdb.stderr"
    )
    require_empty "$case_dir/gdb.stderr"
    grep -Fq 'Breakpoint 1, entry ()' "$case_dir/gdb.txt"
    grep -Fq "Breakpoint 2, $application_entry" "$case_dir/gdb.txt"
    grep -Fq "Located in $case_dir/" "$case_dir/gdb.txt"
    grep -Fq 'type = ' "$case_dir/gdb.txt"
    grep -Fq 'exited normally' "$case_dir/gdb.txt"
    grep -Fxq 'real-world-gdb=PASS' "$case_dir/gdb.txt"
    if [[ "$name" == basename ]]; then
        grep -Fxq 'path' "$case_dir/gdb.txt"
    fi
    echo "real-world-export: $name PASS"
done

echo 'real-world-export=PASS'
