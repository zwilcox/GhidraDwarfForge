#!/usr/bin/env bash
set -euo pipefail

repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture_dir="$repository_dir/build/fixtures"
result_dir="$repository_dir/build/test-results/qemu-gdb-symbols"
base_port=$((24000 + ($$ % 16000)))
active_emulator_pid=""
fixture_role=${FIXTURE_ROLE:-exec}
name_rebase_delta=${GHIDRA_NAME_REBASE_DELTA:-0}
name_rebase_delta=$((name_rebase_delta))
if [[ $# -eq 0 ]]; then
    targets=(x86_64 aarch64 arm32 mips32be mips32le)
else
    targets=("$@")
fi

cleanup() {
    if [[ -n "$active_emulator_pid" ]] && kill -0 "$active_emulator_pid" 2>/dev/null; then
        kill "$active_emulator_pid" 2>/dev/null || true
        wait "$active_emulator_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
mkdir -p "$result_dir"

function_name() {
    if [[ "$fixture_role" == "exec.no-sections" ]]; then
        local symbol=recovered_add
        if [[ "$1" == "aarch64" || "$1" == "arm32" ]]; then
            # Ghidra 12.0.3 does not discover the tiny recovered_add
            # function separately without section headers; main is valid.
            symbol=main
        fi
        local link_hex
        link_hex=$(readelf -Ws "$fixture_dir/$1/semantic.exec.reference" |
            awk -v symbol="$symbol" '$4 == "FUNC" && $8 == symbol { print $2; exit }')
        if [[ -z "$link_hex" ]]; then
            echo "missing fixture symbol $symbol for $1" >&2
            return 1
        fi
        printf 'FUN_%08x\n' "$((16#$link_hex))"
        return
    fi
    case "$1" in
        x86_64|aarch64|arm32|mips32be|mips32le) echo recovered_add ;;
        *) echo "unknown target: $1" >&2; return 2 ;;
    esac
}

symbol_offset() {
    local target=$1 symbol=$2 base=$3
    local reference="$fixture_dir/$target/semantic.$fixture_role.reference"
    local symbol_hex base_hex
    symbol_hex=$(readelf -Ws "$reference" |
        awk -v name="$symbol" '$8 == name { print $2; exit }')
    base_hex=$(readelf -Ws "$reference" |
        awk -v name="$base" '$8 == name { print $2; exit }')
    if [[ -z "$symbol_hex" || -z "$base_hex" ]]; then
        echo "missing fixture symbol $symbol or $base in $reference" >&2
        return 1
    fi
    printf '%d\n' "$((16#$symbol_hex - 16#$base_hex))"
}

validate_transcript() {
    local transcript=$1
    local function=$2
    grep -q "Breakpoint 1," "$transcript"
    grep -q "Breakpoint 2 at" "$transcript"
    grep -q "$function" "$transcript"
    grep -Eq "at ./semantic[.].*[.]ghidra-forge[.]dbg[.]c:[0-9]+" "$transcript"
    if grep -F "No line number information" "$transcript" |
            grep -Fvq "address 0x4010ae"; then
        return 1
    fi
    grep -q "exited normally" "$transcript"
    if [[ "$fixture_role" != "exec.no-sections" ]]; then
        grep -Fq "type = int (int, int)" "$transcript"
        grep -Fq "type = int (int, ...)" "$transcript"
        grep -Fq "type = void (int)" "$transcript"
        grep -Fxq "type = int" "$transcript"
        grep -Fq "EXTERNAL_DECLARATION" "$transcript"
        if grep -Fq 'No symbol "external_counter"' "$transcript"; then
            return 1
        fi
        grep -Fq "SCOPED_GLOBAL" "$transcript"
        grep -Eq '[$][0-9]+ = 7' "$transcript"
        grep -Fq "type = int (*)(int, int)" "$transcript"
        grep -Fq "struct fixture_state" "$transcript"
        grep -Fq "struct list_node" "$transcript"
        grep -Fq "struct packed_flags" "$transcript"
        grep -Fq "low_three : 3" "$transcript"
        grep -Fq "next_five : 5" "$transcript"
        grep -Fq "union word_view" "$transcript"
        grep -Fq "OP_INVALID = -1" "$transcript"
        grep -Fq "analyst_local = <optimized out>" "$transcript"
        grep -Fq "analyst_stack=42" "$transcript"
        grep -Fq "analyst_stack_shifted=42" "$transcript"
        if [[ "$transcript" == *arm32.* ]]; then
            grep -Fq "analyst_register = <optimized out>" "$transcript"
        else
            grep -Fxq "analyst_register = 31" "$transcript"
            grep -Eq '[$][0-9]+ = 0x1122334455667788' "$transcript"
        fi
        case "$transcript" in
            *x86_64.*|*mips32be.*|*mips32le.*)
                grep -Fq "recovered_add (left=19, right=23)" "$transcript"
                grep -Fxq "left = 19" "$transcript"
                grep -Fxq "right = 23" "$transcript"
                ;;
            *aarch64.*)
                grep -Fq "recovered_add (left=<optimized out>, right=<optimized out>)" \
                    "$transcript"
                grep -Fxq "left = <optimized out>" "$transcript"
                grep -Fxq "right = <optimized out>" "$transcript"
                ;;
            *arm32.*)
                grep -Fq "recovered_add (left=<optimized out>, right=23)" "$transcript"
                grep -Fxq "left = <optimized out>" "$transcript"
                grep -Fxq "right = 23" "$transcript"
                ;;
        esac
        grep -Eq '[$][0-9]+ = 0' "$transcript"
        grep -Eq '[$][0-9]+ = 42' "$transcript"
    fi
    if [[ "$function:$fixture_role" == "recovered_add:exec" &&
            "$transcript" == *x86_64.exec.txt ]]; then
        local gap_name
        gap_name=$(printf 'FUN_%08x' "$((0x401090 + name_rebase_delta))")
        grep -Fq "starts at address 0x401090 <$gap_name>" "$transcript"
        grep -Fq "starts at address 0x4010b0 <$gap_name+32>" "$transcript"
        grep -Fq 'No line number information available for address 0x4010ae' "$transcript"
    fi
}

run_native() {
    local target=x86_64
    local function
    function=$(function_name "$target")
    local source_file="$fixture_dir/$target/semantic.$fixture_role.ghidra-forge.dbg.c"
    local definition_line source_break_line
    definition_line=$(grep -n -m1 -E "^[[:alnum:]_* ]+[[:space:]]${function}[(]" \
        "$source_file" | cut -d: -f1)
    source_break_line=$((definition_line + 3))
    local transcript="$result_dir/$target.$fixture_role.txt"
    local type_commands=() print_before=() print_after=() range_commands=()
    local composite_break=() composite_print=() location_break=()
    if [[ "$fixture_role" != "exec.no-sections" ]]; then
        type_commands=(-ex "ptype $function" -ex "ptype binary_operation" \
            -ex "ptype recovered_variadic" -ex "ptype recovered_spin" \
            -ex "ptype fixture_sink" -ex 'echo EXTERNAL_DECLARATION\n' \
            -ex "ptype external_counter" \
            -ex 'echo SCOPED_GLOBAL\n' -ex "ptype scoped_counter" \
            -ex "ptype struct fixture_state" -ex "ptype struct list_node" \
            -ex "ptype struct packed_flags" \
            -ex "ptype union word_view" -ex "ptype enum operation")
        print_before=(-ex "print fixture_sink" -ex "print scoped_counter")
        print_after=(-ex "print fixture_sink")
        composite_break=(-ex "break recovered_composite")
        composite_print=(-ex "print/x analyst_composite" -ex continue)
        local normal_offset changed_offset
        normal_offset=$(symbol_offset "$target" forge_stack_normal recovered_add)
        changed_offset=$(symbol_offset "$target" forge_stack_changed recovered_add)
        location_break=(-ex "break *$function+$normal_offset" \
            -ex "break *$function+$changed_offset")
    fi
    if [[ "$fixture_role" == "exec" ]]; then
        range_commands=(-ex "info line *0x401090" -ex "info line *0x4010b0" \
            -ex "info line *0x4010ae")
    fi
    timeout 30s gdb-multiarch -q -nx -batch \
        -ex "set debuginfod enabled off" \
        -ex "set auto-solib-add off" \
        -ex "directory $fixture_dir/$target" \
        -ex "file $fixture_dir/$target/semantic.$fixture_role.stripped" \
        -ex "symbol-file $fixture_dir/$target/semantic.$fixture_role.ghidra-forge.dbg" \
        "${type_commands[@]}" \
        -ex "info functions $function" \
        -ex "list $function" \
        -ex "info line $function" \
        "${range_commands[@]}" \
        -ex "break $function" \
        -ex "break $source_file:$source_break_line" \
        "${composite_break[@]}" \
        "${location_break[@]}" \
        -ex run \
        -ex "info locals" \
        -ex "info args" \
        "${print_before[@]}" \
        -ex frame \
        -ex list \
        -ex next \
        -ex 'printf "analyst_stack=%d\n", analyst_stack' \
        "${print_after[@]}" \
        -ex frame \
        -ex step \
        -ex 'printf "analyst_stack_shifted=%d\n", analyst_stack' \
        -ex frame \
        -ex nexti \
        -ex continue \
        "${composite_print[@]}" 2>&1 | tee "$transcript"
    validate_transcript "$transcript" "$function"
}

run_emulated() {
    local target=$1 emulator=$2 sysroot=$3 port=$4
    local function
    function=$(function_name "$target")
    local source_file="$fixture_dir/$target/semantic.$fixture_role.ghidra-forge.dbg.c"
    local definition_line source_break_line
    definition_line=$(grep -n -m1 -E "^[[:alnum:]_* ]+[[:space:]]${function}[(]" \
        "$source_file" | cut -d: -f1)
    source_break_line=$((definition_line + 3))
    local transcript="$result_dir/$target.$fixture_role.txt"
    local type_commands=() print_before=() print_after=()
    local composite_break=() composite_print=() location_break=()
    local execution_flow=()
    if [[ "$fixture_role" != "exec.no-sections" ]]; then
        type_commands=(-ex "ptype $function" -ex "ptype binary_operation" \
            -ex "ptype recovered_variadic" -ex "ptype recovered_spin" \
            -ex "ptype fixture_sink" -ex 'echo EXTERNAL_DECLARATION\n' \
            -ex "ptype external_counter" \
            -ex 'echo SCOPED_GLOBAL\n' -ex "ptype scoped_counter" \
            -ex "ptype struct fixture_state" -ex "ptype struct list_node" \
            -ex "ptype struct packed_flags" \
            -ex "ptype union word_view" -ex "ptype enum operation")
        print_before=(-ex "print fixture_sink" -ex "print scoped_counter")
        print_after=(-ex "print fixture_sink")
        composite_break=(-ex "break recovered_composite")
        composite_print=(-ex "print/x analyst_composite" -ex continue)
        local normal_offset changed_offset
        normal_offset=$(symbol_offset "$target" forge_stack_normal recovered_add)
        changed_offset=$(symbol_offset "$target" forge_stack_changed recovered_add)
        location_break=(-ex "break *$function+$normal_offset" \
            -ex "break *$function+$changed_offset")
    fi
    if [[ "$target:$fixture_role" == arm32:exec ||
            "$target:$fixture_role" == arm32:exec.no-build-id ||
            "$target:$fixture_role" == arm32:pie ]]; then
        execution_flow=(-ex continue -ex frame -ex list -ex step \
            -ex 'printf "analyst_stack=%d\n", analyst_stack' \
            "${print_after[@]}" -ex frame -ex continue \
            -ex 'printf "analyst_stack_shifted=%d\n", analyst_stack' \
            -ex frame -ex continue)
    else
        execution_flow=(-ex frame -ex list -ex next \
            -ex 'printf "analyst_stack=%d\n", analyst_stack' \
            "${print_after[@]}" -ex frame -ex step \
            -ex 'printf "analyst_stack_shifted=%d\n", analyst_stack' \
            -ex frame -ex nexti -ex continue)
    fi
    "$emulator" -L "$sysroot" -g "$port" \
        "$fixture_dir/$target/semantic.$fixture_role.stripped" &
    active_emulator_pid=$!
    sleep 0.2
    timeout 30s gdb-multiarch -q -nx -batch \
        -ex "set debuginfod enabled off" \
        -ex "set auto-solib-add off" \
        -ex "set sysroot $sysroot" \
        -ex "directory $fixture_dir/$target" \
        -ex "file $fixture_dir/$target/semantic.$fixture_role.stripped" \
        -ex "symbol-file $fixture_dir/$target/semantic.$fixture_role.ghidra-forge.dbg" \
        -ex "target remote :$port" \
        "${type_commands[@]}" \
        -ex "info functions $function" \
        -ex "list $function" \
        -ex "info line $function" \
        -ex "break $function" \
        -ex "break $source_file:$source_break_line" \
        "${composite_break[@]}" \
        "${location_break[@]}" \
        -ex continue \
        -ex "info locals" \
        -ex "info args" \
        "${print_before[@]}" \
        "${execution_flow[@]}" \
        "${composite_print[@]}" 2>&1 | tee "$transcript"
    wait "$active_emulator_pid"
    active_emulator_pid=""
    validate_transcript "$transcript" "$function"
}

for target in "${targets[@]}"; do
    case "$target" in
        x86_64) run_native ;;
        aarch64) run_emulated "$target" /usr/bin/qemu-aarch64-static \
            /usr/aarch64-linux-gnu "$base_port" ;;
        arm32) run_emulated "$target" /usr/bin/qemu-arm-static \
            /usr/arm-linux-gnueabihf "$((base_port + 3))" ;;
        mips32be) run_emulated "$target" /usr/bin/qemu-mips-static \
            /usr/mips-linux-gnu "$((base_port + 1))" ;;
        mips32le) run_emulated "$target" /usr/bin/qemu-mipsel-static \
            /usr/mipsel-linux-gnu "$((base_port + 2))" ;;
        *) echo "unknown target: $target" >&2; exit 2 ;;
    esac
done

echo "qemu-gdb-symbols=PASS"
