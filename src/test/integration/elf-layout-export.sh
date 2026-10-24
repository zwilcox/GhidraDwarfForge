#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp> [target ...]" >&2
    echo "generate inputs first: java src/test/integration/ElfLayoutFixtures.java build/fixtures [target ...]" >&2
    exit 2
fi
export LC_ALL=C
repository_dir=$(realpath "$(dirname "$0")/../../..")
source "$repository_dir/src/test/integration/elf-layout-gdb-oracle.sh"
ghidra_dir=$(realpath "$1")
consumer=$(realpath "$2")
producer=$(realpath "$3")
shift 3
if [[ $# -eq 0 ]]; then
    targets=(x86_64 mips32be)
else
    targets=("$@")
fi
for tool in java readelf llvm-dwarfdump dwarfdump gdb-multiarch sha256sum cmp; do
    command -v "$tool" >/dev/null
done
fixture_dir="$repository_dir/build/fixtures"
generator="$repository_dir/src/test/integration/ElfLayoutFixtures.java"
headless_results="$repository_dir/build/test-results/headless-symbol-export"
gdb_results="$repository_dir/build/test-results/qemu-gdb-symbols"
result_root="$repository_dir/build/test-results/elf-layout-export"
mkdir -p "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
echo "elf-layout-results=$result_dir"
active_case=""
stage=preparation
originals=()
for target in "${targets[@]}"; do
    for role in exec pie; do
        for suffix in reference stripped no-section-names extended-programs; do
            original="$fixture_dir/$target/semantic.$role.$suffix"
            test -f "$original"
            originals+=("$original")
        done
    done
done
sha256sum "${originals[@]}" >"$result_dir/originals.sha256"

archive_case() {
    if [[ -z "$active_case" ]]; then
        return
    fi
    local file
    echo "stage=$stage" >"$active_case/archive-stage.txt"
    for file in "$headless_results/$target.$role."* "$output" "$output.c"; do
        if [[ -f "$file" && -f "$active_case/export-started" &&
                "$file" -nt "$active_case/export-started" ]]; then
            cp -- "$file" "$active_case/"
        fi
    done
    if [[ -f "$active_case/gdb-started" &&
            "$gdb_results/$target.$role.txt" -nt "$active_case/gdb-started" ]]; then
        cp -- "$gdb_results/$target.$role.txt" "$active_case/runtime-gdb.txt"
    fi
}

finish() {
    local status=$?
    archive_case || status=1
    if ! sha256sum -c "$result_dir/originals.sha256" \
            >"$result_dir/input-preservation.txt" 2>&1; then
        cat "$result_dir/input-preservation.txt" >&2
        status=1
    fi
    echo "elf-layout-export results: $result_dir"
    exit "$status"
}
trap finish EXIT

validate_input_diagnostic() {
    local diagnostic=$1 variant=$2 count=$3
    if [[ "$variant" == no-section-names ]]; then
        # GNU readelf locates the dynamic section by name even when shstrndx=0.
        # Permit only that known input-reader limitation; sidecars stay strict.
        if grep -Fvx 'readelf: Error: no .dynamic section in the dynamic segment' "$diagnostic"; then
            echo "unexpected readelf input diagnostic: $diagnostic" >&2
            return 1
        fi
    elif [[ "$variant" == extended-programs ]]; then
        # readelf's section-info checker does not account for PN_XNUM's valid
        # sh0.info escape count, despite decoding it correctly in the ELF header.
        if grep -Fvx "readelf: Warning: [ 0]: Unexpected value ($count) in info field." "$diagnostic"; then
            echo "unexpected readelf input diagnostic: $diagnostic" >&2
            return 1
        fi
    fi
}

for target in "${targets[@]}"; do
    for role in exec pie; do
        oracle_dir="$result_dir/$target/$role"
        mkdir -p "$oracle_dir"
        layout_compiler_oracle "$target" "$fixture_dir/$target/semantic.$role.reference" \
            "$oracle_dir/compiler-gdb.txt"
        readelf -Ws "$fixture_dir/$target/semantic.$role.reference" >"$oracle_dir/reference.symbols.txt"
        function_hex=$(awk '$8 == "recovered_add" && !found { print $2; found = 1 }' \
            "$oracle_dir/reference.symbols.txt")
        global_hex=$(awk '$8 == "fixture_sink" && !found { print $2; found = 1 }' \
            "$oracle_dir/reference.symbols.txt")
        [[ "$function_hex" =~ ^[[:xdigit:]]+$ && "$global_hex" =~ ^[[:xdigit:]]+$ ]]
        printf -v function_address '0x%x' "$((16#$function_hex))"
        printf -v global_address '0x%x' "$((16#$global_hex))"
        for variant in no-section-names extended-programs; do
            case_dir="$result_dir/$target/$role/$variant"
            mkdir -p "$case_dir"
            input="$fixture_dir/$target/semantic.$role.$variant"
            output="$fixture_dir/$target/semantic.$role.ghidra-forge.dbg"
            cp -- "$input" "$case_dir/input.elf"
            program_count=0
            for dump in header sections notes; do
                case "$dump" in
                    header) option=--file-header ;;
                    sections) option=-SW ;;
                    notes) option=--notes ;;
                esac
                readelf "$option" "$input" >"$case_dir/input.$dump.txt" \
                    2>"$case_dir/input.$dump.stderr"
                if [[ "$dump:$variant" == header:extended-programs ]]; then
                    program_count=$(sed -n 's/.*Number of program headers:[[:space:]]*65535 (\([0-9]*\)).*/\1/p' \
                        "$case_dir/input.header.txt")
                    [[ "$program_count" =~ ^[0-9]+$ ]] && ((program_count > 65535))
                fi
                validate_input_diagnostic "$case_dir/input.$dump.stderr" "$variant" "$program_count"
            done
            if [[ "$variant" == no-section-names ]]; then
                grep -Eq 'Section header string table index:[[:space:]]+0$' "$case_dir/input.header.txt"
                grep -Eq 'Number of section headers:[[:space:]]+[1-9][0-9]*$' "$case_dir/input.header.txt"
            else
                grep -Eq 'Number of program headers:[[:space:]]+65535 \([0-9]+\)$' "$case_dir/input.header.txt"
                java "$generator" verify-runtime "$input" \
                    "$fixture_dir/$target/semantic.$role.stripped" >"$case_dir/runtime-equivalence.txt"
            fi
            iterations=(first)
            if [[ "$target:$role" == "${targets[0]}:exec" ]]; then
                iterations+=(second)
            fi
            if [[ "$role:$variant" == exec:extended-programs ]]; then
                iterations+=(rebased)
            fi
            for iteration in "${iterations[@]}"; do
                active_case="$case_dir/$iteration"
                mkdir -p "$active_case"
                stage=headless-export
                rebase_delta=0
                if [[ "$iteration" == rebased ]]; then
                    rebase_delta=0x2000000
                fi
                touch "$active_case/export-started"
                echo "elf-layout-export: $target $role $variant $iteration"
                FIXTURE_ROLE="$role" FIXTURE_INPUT_SUFFIX="$variant" GHIDRA_REBASE_DELTA="$rebase_delta" \
                    "$repository_dir/src/test/integration/headless-symbol-export.sh" \
                    "$ghidra_dir" "$consumer" "$producer" "$target" \
                    >"$active_case/headless-console.txt" 2>&1
                if [[ "$variant" == extended-programs ]]; then
                    # All LOAD headers lie after Ghidra's first-20-header scan;
                    # its recorded loader base is zero even for this ET_EXEC.
                    grep -Fq 'Ghidra original ELF image base: 0x0 (GhidraScript)' \
                        "$active_case/headless-console.txt"
                    if [[ "$role" == exec ]]; then
                        printf -v delta_hex '0x%x' "$((rebase_delta))"
                        printf -v base_display '%08x' "$((rebase_delta))"
                        grep -Fq "image base: $base_display (GhidraScript)" "$active_case/headless-console.txt"
                        grep -Fq "Ghidra-to-ELF address delta: $delta_hex (GhidraScript)" \
                            "$active_case/headless-console.txt"
                    fi
                fi
                stage=metadata
                java "$generator" verify-output "$input" "$output" "$variant" \
                    >"$active_case/output-metadata.txt"
                readelf --notes "$output" >"$active_case/sidecar.notes.txt" \
                    2>"$active_case/sidecar.notes.stderr"
                test ! -s "$active_case/sidecar.notes.stderr"
                grep 'Build ID:' "$case_dir/input.notes.txt" >"$active_case/input.build-id.txt"
                grep 'Build ID:' "$active_case/sidecar.notes.txt" >"$active_case/sidecar.build-id.txt"
                cmp "$active_case/input.build-id.txt" "$active_case/sidecar.build-id.txt"
                stage=static-gdb
                timeout 30s gdb-multiarch -q -nx -batch \
                    -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
                    -ex "file $input" -ex "symbol-file $output" \
                    -ex 'info functions recovered_add' -ex 'ptype recovered_add' \
                    -ex 'ptype struct fixture_state' -ex 'list recovered_add' \
                    -ex 'printf "FORGE_FUNCTION=0x%lx\n", &recovered_add' \
                    -ex 'printf "FORGE_GLOBAL=0x%lx\n", &fixture_sink' \
                    -ex 'info line recovered_add' >"$active_case/static-gdb.txt" 2>&1
                layout_validate_gdb_diagnostics "$active_case/static-gdb.txt" "$input" \
                    "$variant" "$target" "$oracle_dir/compiler-gdb.txt"
                grep -Fq 'type = int (int, int)' "$active_case/static-gdb.txt"
                grep -Fq 'struct fixture_state' "$active_case/static-gdb.txt"
                grep -Fq "$(basename "$output.c")" "$active_case/static-gdb.txt"
                grep -Eq 'starts at address 0x[[:xdigit:]]+' "$active_case/static-gdb.txt"
                grep -Fxq "FORGE_FUNCTION=$function_address" "$active_case/static-gdb.txt"
                grep -Fxq "FORGE_GLOBAL=$global_address" "$active_case/static-gdb.txt"
                stage=runtime-gdb
                runtime_suffix=$variant
                if [[ "$variant" == extended-programs ]]; then
                    # Native Linux rejects PN_XNUM execution (ENOEXEC); QEMU 8.2
                    # also fails this image. Debug the unchanged original load
                    # image separately, without claiming execution of PN_XNUM.
                    runtime_suffix=stripped
                fi
                {
                    echo "export_input=$input"
                    echo "static_gdb_input=$input"
                    echo "runtime_input=$fixture_dir/$target/semantic.$role.$runtime_suffix"
                    echo "runtime_uses_export_input=$([[ "$variant" == "$runtime_suffix" ]] && echo true || echo false)"
                    echo "ghidra_rebase_delta=$rebase_delta"
                } >"$active_case/runtime-policy.txt"
                touch "$active_case/gdb-started"
                FIXTURE_ROLE="$role" FIXTURE_INPUT_SUFFIX="$runtime_suffix" GHIDRA_NAME_REBASE_DELTA="$rebase_delta" \
                    "$repository_dir/src/test/integration/qemu-gdb-symbols.sh" "$target" \
                    >"$active_case/runtime-console.txt" 2>&1
                layout_validate_gdb_diagnostics "$gdb_results/$target.$role.txt" \
                    "$fixture_dir/$target/semantic.$role.$runtime_suffix" "$variant" \
                    "$target" "$oracle_dir/compiler-gdb.txt"
                sha256sum "$output" "$output.c" >"$active_case/artifacts.sha256"
                echo 'elf_layout_export=PASS' >"$active_case/result.txt"
                stage=complete
                archive_case
                active_case=""
            done
            if [[ -d "$case_dir/second" ]]; then
                cmp "$case_dir/first/artifacts.sha256" "$case_dir/second/artifacts.sha256"
                echo 'deterministic_rerun=PASS' >"$case_dir/determinism.txt"
            fi
        done
    done
done
echo 'elf-layout-export=PASS'
