#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp> [target ...]" >&2
    exit 2
fi

ghidra_dir=$(realpath "$1")
consumer=$(realpath "$2")
producer=$(realpath "$3")
shift 3
if [[ $# -eq 0 ]]; then
    targets=(x86_64 aarch64 arm32 mips32be mips32le)
else
    targets=("$@")
fi

repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture_dir="$repository_dir/build/fixtures"
result_dir="$repository_dir/build/test-results/headless-symbol-export"
temporary_projects=$(mktemp -d -t ghidra-dwarf-forge-symbols.XXXXXXXX)
fixture_role=${FIXTURE_ROLE:-exec}
project_rebase_delta=${GHIDRA_REBASE_DELTA:-0}
project_rebase_delta=$((project_rebase_delta))
stale_executable_path=${GHIDRA_STALE_EXECUTABLE_PATH:-}
use_default_output=${GHIDRA_USE_DEFAULT_OUTPUT:-0}

fixture_stem() {
    local role=$1
    if [[ "$role" == "shared" ]]; then
        echo libsemantic.so
    else
        echo "semantic.$role"
    fi
}

analysis_address() {
    local target=$1 role=$2 symbol=$3
    local reference="$fixture_dir/$target/$(fixture_stem "$role").reference"
    local link_hex
    link_hex=$(readelf -Ws "$reference" | awk -v symbol="$symbol" \
        '$8 == symbol { print $2; exit }')
    if [[ -z "$link_hex" ]]; then
        echo "missing fixture symbol $symbol in $reference" >&2
        return 1
    fi
    local rebase=0
    if [[ "$role" == "pie" || "$role" == "shared" ]]; then
        case "$target" in
            x86_64|aarch64) rebase=$((0x100000)) ;;
            arm32|mips32be|mips32le) rebase=$((0x10000)) ;;
            *) echo "unknown target: $target" >&2; return 2 ;;
        esac
    fi
    printf '0x%x\n' "$((16#$link_hex + rebase + project_rebase_delta))"
}

cleanup() {
    case "$temporary_projects" in
        /tmp/ghidra-dwarf-forge-symbols.*)
            rm -rf -- "$temporary_projects"
            ;;
        *)
            echo "refusing to remove unexpected temporary path: $temporary_projects" >&2
            ;;
    esac
}
trap cleanup EXIT

mkdir -p "$result_dir"

for target in "${targets[@]}"; do
    stem=$(fixture_stem "$fixture_role")
    input="$fixture_dir/$target/$stem.stripped"
    if [[ "$use_default_output" == 1 ]]; then
        output="$input.dbg"
    else
        output="$fixture_dir/$target/$stem.ghidra-forge.dbg"
    fi
    source="$output.c"
    log="$result_dir/$target.$fixture_role.log"
    if [[ ! -f "$input" ]]; then
        echo "missing fixture: $input" >&2
        exit 1
    fi
    before=$(sha256sum "$input" | cut -d' ' -f1)
    prepare_script=()
    if ((project_rebase_delta != 0)); then
        prepare_script=(-postScript RebaseFixtureProgram.java \
            "$(printf '0x%x' "$project_rebase_delta")")
    fi
    if [[ -n "$stale_executable_path" ]]; then
        prepare_script+=(-postScript SetStaleExecutablePath.java \
            "$stale_executable_path")
    fi
    if [[ "$fixture_role" != "exec.no-sections" ]]; then
        rename_address=$(analysis_address "$target" "$fixture_role" recovered_add)
        variadic_address=$(analysis_address "$target" "$fixture_role" recovered_variadic)
        noreturn_address=$(analysis_address "$target" "$fixture_role" recovered_spin)
        composite_address=$(analysis_address "$target" "$fixture_role" recovered_composite)
        global_address=$(analysis_address "$target" "$fixture_role" fixture_sink)
        scoped_global_address=$(analysis_address "$target" "$fixture_role" scoped_counter)
        prepare_script+=(-postScript RenameFixtureFunction.java \
            "$rename_address" "$variadic_address" "$noreturn_address" recovered_add \
            "$global_address" "$composite_address" "$scoped_global_address")
    fi

    export_options=("--libdwarf=$consumer" "--libdwarfp=$producer")
    if [[ -n "$stale_executable_path" ]]; then
        export_options+=("--input=$input")
    fi
    if [[ "$use_default_output" != 1 ]]; then
        export_options+=("--output=$output")
    fi

    "$ghidra_dir/support/analyzeHeadless" \
        "$temporary_projects" "GhidraDwarfForgeSymbols_$target" \
        -deleteProject \
        -import "$input" \
        -analysisTimeoutPerFile 120 \
        -scriptPath "$repository_dir/src/test/integration/ghidra_scripts" \
        "${prepare_script[@]}" \
        -postScript GhidraDwarfForge.java \
        "${export_options[@]}" 2>&1 | tee "$log"

    after=$(sha256sum "$input" | cut -d' ' -f1)
    test "$before" = "$after"
    grep -q "GhidraDwarfForge symbol export PASS" "$log"
    grep -Fq 'GhidraDwarfForge report: {"schemaVersion":1,"status":"PARTIAL"' "$log"
    grep -Eq '"functionsExported":[1-9][0-9]*' "$log"
    grep -Eq '"functionsSkipped":[1-9][0-9]*' "$log"
    grep -Fq '"validation":{"status":"NOT_RUN"}' "$log"
    grep -Fq '"native":{"libdwarfVersion":"2.3.2"}' "$log"
    grep -Fq '"failure":null' "$log"
    grep -q "REPORT: Import succeeded" "$log"
    grep -Eq "output SHA-256: [0-9a-f]{64}" "$log"
    grep -Eq "source SHA-256: [0-9a-f]{64}" "$log"
    if [[ "$use_default_output" == 1 ]]; then
        grep -q "output policy: default beside executable" "$log"
    fi
    if [[ -n "$stale_executable_path" ]]; then
        grep -Fq "Set stale fixture executable path to $stale_executable_path" "$log"
        grep -Fq "  input: $input" "$log"
    fi
    if ((project_rebase_delta != 0)); then
        grep -q "Rebased fixture image .* by $(printf '0x%x' "$project_rebase_delta")" \
            "$log"
        grep -q "Ghidra-to-ELF address delta: $(printf '0x%x' "$project_rebase_delta")" \
            "$log"
    fi
    grep -Eq "mapped source lines: [1-9][0-9]*" "$log"
    grep -Eq "function signatures: [1-9][0-9]*" "$log"
    grep -Eq "local variables: [0-9]+" "$log"
    grep -Eq "defensible variable locations: [0-9]+" "$log"
    grep -Eq "omitted variable locations: [0-9]+" "$log"
    grep -Eq "canonical types: [1-9][0-9]*" "$log"
    grep -Eq "global variables: [0-9]+" "$log"
    grep -Eq "Skipped (external/import|thunk) function" "$log"
    test -s "$source"
    grep -q "This is decompiler output, not recovered original source" "$source"
    if LC_ALL=C grep -q $'\r' "$source"; then
        echo "synthetic source contains a carriage return: $source" >&2
        exit 1
    fi
    if [[ "$fixture_role" != "exec.no-sections" ]]; then
        grep -q "Renamed fixture function .* to recovered_add" "$log"
        grep -q "Applied USER_DEFINED int recovered_add(int left, int right) in" "$log"
        grep -q "Applied default calling convention to recovered_add" "$log"
        grep -q "Applied USER_DEFINED locationless int analyst_local" "$log"
        grep -q "Applied USER_DEFINED int analyst_register in" "$log"
        grep -q "Applied USER_DEFINED int analyst_stack at Ghidra stack offset" "$log"
        grep -q "Applied USER_DEFINED int recovered_variadic(int count, ...)" "$log"
        grep -q "Applied USER_DEFINED noreturn void recovered_spin(int value)" "$log"
        grep -q "Applied USER_DEFINED long long analyst_composite in" "$log"
        grep -q "Applied USER_DEFINED int fixture_sink at" "$log"
        grep -q "Applied USER_DEFINED int analyst_scope::scoped_counter at" "$log"
        grep -q "Applied USER_DEFINED extern int external_counter declaration" "$log"
        grep -q "Applied favorite recursive fixture type" "$log"
        grep -q "Applied favorite bit-field fixture type" "$log"
        grep -Eq "canonical types: ([8-9]|[1-9][0-9]+)" "$log"
        if [[ "$target:$fixture_role" == arm32:shared ]]; then
            grep -Fq "Cleared auto-analysis thunk classification at $rename_address" \
                "$log"
        fi
    fi

    warnings="$result_dir/$target.$fixture_role.readelf.stderr"
    : >"$warnings"
    readelf -h "$output" >/dev/null 2>>"$warnings"
    readelf -S "$output" >/dev/null 2>>"$warnings"
    readelf -n "$output" >/dev/null 2>>"$warnings"
    readelf --debug-dump=info "$output" \
        >"$result_dir/$target.$fixture_role.readelf-info.txt" 2>>"$warnings"
    readelf --debug-dump=abbrev "$output" >/dev/null 2>>"$warnings"
    readelf --debug-dump=aranges "$output" >/dev/null 2>>"$warnings"
    readelf --debug-dump=decodedline "$output" \
        >"$result_dir/$target.$fixture_role.readelf-decodedline.txt" 2>>"$warnings"
    if readelf -S "$output" | grep -q '[.]debug_rnglists'; then
        readelf --debug-dump=Ranges "$output" \
            >"$result_dir/$target.$fixture_role.readelf-ranges.txt" 2>>"$warnings"
    fi
    if readelf -S "$output" | grep -q '[.]debug_loclists'; then
        readelf --debug-dump=loc "$output" \
            >"$result_dir/$target.$fixture_role.readelf-locations.txt" 2>>"$warnings"
    fi
    if [[ -s "$warnings" ]]; then
        cat "$warnings" >&2
        exit 1
    fi
    if [[ "$fixture_role" == "exec.no-build-id" ]]; then
        if readelf -n "$input" | grep -q 'Build ID:' ||
                readelf -n "$output" | grep -q 'Build ID:'; then
            echo "no-build-ID fixture or sidecar unexpectedly has a build ID" >&2
            exit 1
        fi
    fi
    if [[ "$fixture_role" != "exec.no-sections" ]]; then
        grep -q "DW_AT_name.*recovered_add" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_calling_convention.*normal" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_TAG_structure_type" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "fixture_state" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "list_node" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "packed_flags" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_bit_size.*3" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_bit_size.*5" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_TAG_formal_parameter" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_TAG_unspecified_parameters" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_noreturn" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_TAG_variable" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_name.*fixture_sink" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_name.*external_counter" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_TAG_namespace" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_name.*analyst_scope" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_name.*scoped_counter" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        awk '/DW_TAG_/ {
                if (variable && name && declaration && external && !location) found = 1
                variable = /DW_TAG_variable/; name = 0; declaration = 0
                external = 0; location = 0
            }
            variable && /DW_AT_name.*external_counter/ { name = 1 }
            variable && /DW_AT_declaration.*1/ { declaration = 1 }
            variable && /DW_AT_external.*1/ { external = 1 }
            variable && /DW_AT_location/ { location = 1 }
            END {
                if (variable && name && declaration && external && !location) found = 1
                exit !found
            }' \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_name.*analyst_local" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_name.*analyst_register" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_name.*analyst_stack" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        grep -q "DW_AT_name.*analyst_composite" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        readelf -S "$output" | grep -q '[.]debug_loclists'
        locations="$result_dir/$target.$fixture_role.readelf-locations.txt"
        case "$target" in
            x86_64)
                grep -q 'DW_OP_bregx: 7 (rsp) -4' "$locations"
                grep -q 'DW_OP_bregx: 7 (rsp) 12' "$locations"
                ;;
            aarch64)
                grep -q 'DW_OP_bregx: 31 (sp) 28' "$locations"
                grep -q 'DW_OP_bregx: 31 (sp) 44' "$locations"
                ;;
            arm32)
                test "$(grep -Eo 'DW_OP_bregx: 13( \([^)]*\))? -?[0-9]+' \
                    "$locations" | sort -u | wc -l)" -ge 2
                ;;
            mips32be|mips32le)
                grep -q 'DW_OP_bregx: 29 (r29) 4' "$locations"
                grep -q 'DW_OP_bregx: 29 (r29) 20' "$locations"
                ;;
        esac
        if [[ "$target" == "arm32" ]]; then
            grep -q "Omitted location for recovered_composite::analyst_composite:" "$log"
        else
            test "$(grep -o 'DW_OP_bit_piece: size: 32 offset: 0' \
                "$result_dir/$target.$fixture_role.readelf-info.txt" | wc -l)" -ge 2
        fi
        grep -q "DW_AT_location" \
            "$result_dir/$target.$fixture_role.readelf-info.txt"
        if [[ "$target" == "aarch64" ]]; then
            grep -q "Omitted location for recovered_add::left: function writes parameter register x0" \
                "$log"
            grep -q "Omitted location for recovered_add::right: function writes parameter register x1" \
                "$log"
        elif [[ "$target" == "arm32" ]]; then
            grep -q "Omitted location for recovered_add::left: function writes parameter register r0" \
                "$log"
            grep -q "Omitted location for recovered_add::analyst_register: function writes local register r3" \
                "$log"
            grep -q "DW_OP_regx: 1" \
                "$result_dir/$target.$fixture_role.readelf-info.txt"
        else
            grep -Eq "defensible variable locations: [1-9][0-9]*" "$log"
            grep -q "DW_OP_regx: 4" \
                "$result_dir/$target.$fixture_role.readelf-info.txt"
            grep -q "DW_OP_regx: 5" \
                "$result_dir/$target.$fixture_role.readelf-info.txt"
        fi
    fi
    if [[ "$target:$fixture_role" == "x86_64:exec" ]]; then
        ranges="$result_dir/$target.$fixture_role.readelf-ranges.txt"
        grep -Eq '00401090[[:space:]]+00000000004010ae' "$ranges"
        grep -Eq '004010b0[[:space:]]+00000000004010b1' "$ranges"
        grep -q 'DW_AT_ranges' "$result_dir/$target.$fixture_role.readelf-info.txt"
    fi
    grep -q "$(basename "$source")" \
        "$result_dir/$target.$fixture_role.readelf-decodedline.txt"
    llvm-dwarfdump --verify "$output" \
        >"$result_dir/$target.$fixture_role.llvm-dwarfdump.txt" 2>&1
    dwarfdump -ka -ks "$output" \
        >"$result_dir/$target.$fixture_role.dwarfdump.txt" 2>&1
done

echo "headless-symbol-export=PASS"
