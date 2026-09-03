#!/usr/bin/env bash
set -euo pipefail

repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture_dir="$repository_dir/build/fixtures"
result_dir="$repository_dir/build/test-results/shared-object-gdb"
base_port=$((30000 + ($$ % 15000)))
active_emulator_pid=""
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

symbol_address() {
    local target=$1 file=$2 symbol=$3
    local address
    address=$(readelf -Ws "$fixture_dir/$target/$file" |
        awk -v name="$symbol" '$8 == name { print $2; exit }')
    if [[ -z "$address" ]]; then
        echo "missing $symbol in $target/$file" >&2
        return 1
    fi
    printf '0x%s\n' "$address"
}

text_address() {
    local target=$1
    local address
    address=$(readelf -WS "$fixture_dir/$target/libsemantic.so.reference" |
        awk '$2 == ".text" { print $4; exit }')
    if [[ -z "$address" ]]; then
        echo "missing .text in $target shared-object reference" >&2
        return 1
    fi
    printf '0x%s\n' "$address"
}

main_load_bounds() {
    local target=$1
    local minimum=-1 maximum=0 virtual_address memory_size start end
    while read -r virtual_address memory_size; do
        start=$((virtual_address))
        end=$((virtual_address + memory_size))
        if (( minimum < 0 || start < minimum )); then
            minimum=$start
        fi
        if (( end > maximum )); then
            maximum=$end
        fi
    done < <(readelf -Wl "$fixture_dir/$target/semantic.shared-driver.stripped" |
        awk '$1 == "LOAD" { print $3, $6 }')
    if (( minimum < 0 || maximum <= minimum )); then
        echo "missing main executable PT_LOAD bounds for $target" >&2
        return 1
    fi
    printf '0x%x 0x%x\n' "$minimum" "$maximum"
}

validate_transcript() {
    local target=$1 transcript=$2 main_load_start=$3 main_load_end=$4
    grep -Fq 'BEFORE_LIBRARY_MAP' "$transcript"
    grep -Fq 'AFTER_LIBRARY_MAP' "$transcript"
    if sed -n '/BEFORE_LIBRARY_MAP/,/add symbol table/p' "$transcript" |
        grep -Fq 'libsemantic.so.stripped'; then
        echo "shared library was already mapped during the pre-map check: $transcript" >&2
        return 1
    fi
    grep -Fq 'libsemantic.so.stripped' "$transcript"
    grep -Fq 'type = int (int, int)' "$transcript"
    grep -Fq 'EXTERNAL_DECLARATION' "$transcript"
    if grep -Fq 'No symbol "external_counter"' "$transcript"; then
        return 1
    fi
    grep -Fq 'SCOPED_GLOBAL' "$transcript"
    grep -Eq '[$][0-9]+ = 7' "$transcript"
    grep -Eq 'starts at address 0x[0-9a-f]+ <recovered_add>' "$transcript"
    grep -Eq 'RUNTIME_BIAS 0x[1-9a-f][0-9a-f]*' "$transcript"
    if [[ "$target" == "aarch64" ]]; then
        grep -Fq 'Breakpoint 2, recovered_add (left=<optimized out>, right=<optimized out>)' \
            "$transcript"
        grep -Fxq 'left = <optimized out>' "$transcript"
        grep -Fxq 'right = <optimized out>' "$transcript"
    elif [[ "$target" == "arm32" ]]; then
        grep -Fq 'Breakpoint 2, recovered_add (left=<optimized out>, right=<optimized out>)' \
            "$transcript"
        grep -Fxq 'left = <optimized out>' "$transcript"
        grep -Fxq 'right = <optimized out>' "$transcript"
    else
        grep -Fq 'Breakpoint 2, recovered_add (left=19, right=23)' "$transcript"
        grep -Fxq 'left = 19' "$transcript"
        grep -Fxq 'right = 23' "$transcript"
    fi
    grep -Eq '[$][0-9]+ = 0' "$transcript"
    grep -Eq '[$][0-9]+ = 42' "$transcript"
    grep -Fq 'exited normally' "$transcript"
    local runtime_function runtime_global
    runtime_function=$(awk '$1 == "RUNTIME_RECOVERED_ADD" { print $2; exit }' "$transcript")
    runtime_global=$(awk '$1 == "RUNTIME_FIXTURE_SINK" { print $2; exit }' "$transcript")
    if [[ -z "$runtime_function" || -z "$runtime_global" ]] ||
        (( runtime_function >= main_load_start && runtime_function < main_load_end )) ||
        (( runtime_global >= main_load_start && runtime_global < main_load_end )); then
        echo "shared symbol collided with the main executable PT_LOAD range: $transcript" >&2
        return 1
    fi
}

gdb_commands() {
    local target=$1 main_address=$2 text_link_address=$3 sidecar=$4
    local sysroot=${5:-} port=${6:-}
    cat <<EOF
set debuginfod enabled off
set auto-solib-add off
directory $fixture_dir/$target
file $fixture_dir/$target/semantic.shared-driver.stripped
EOF
    if [[ -n "$sysroot" ]]; then
        cat <<EOF
set sysroot $sysroot
set solib-search-path $fixture_dir/$target
target remote :$port
EOF
    else
        echo starti
    fi
    cat <<EOF
echo BEFORE_LIBRARY_MAP\\n
info sharedlibrary
add-symbol-file $sidecar -o 0
ptype recovered_add
echo EXTERNAL_DECLARATION\n
ptype external_counter
info line recovered_add
remove-symbol-file $sidecar
break *$main_address
continue
echo AFTER_LIBRARY_MAP\\n
info sharedlibrary
python out=gdb.execute('info sharedlibrary',to_string=True); line=next(x for x in out.splitlines() if 'libsemantic.so.stripped' in x); start=int(line.split()[0],16); bias=start-int('$text_link_address',16); print('RUNTIME_BIAS',hex(bias)); gdb.execute('add-symbol-file $sidecar -o '+hex(bias))
python print('RUNTIME_RECOVERED_ADD',hex(int(gdb.parse_and_eval('&recovered_add'))))
python print('RUNTIME_FIXTURE_SINK',hex(int(gdb.parse_and_eval('&fixture_sink'))))
echo SCOPED_GLOBAL\n
ptype scoped_counter
break recovered_add
continue
info args
print fixture_sink
print scoped_counter
next
print fixture_sink
continue
EOF
}

run_native() {
    local target=x86_64
    local sidecar="$fixture_dir/$target/libsemantic.so.ghidra-forge.dbg"
    local main_address text_link_address transcript command_file
    local main_load_start main_load_end
    main_address=$(symbol_address "$target" semantic.shared-driver.reference main)
    text_link_address=$(text_address "$target")
    read -r main_load_start main_load_end < <(main_load_bounds "$target")
    transcript="$result_dir/$target.txt"
    command_file="$result_dir/$target.gdb"
    gdb_commands "$target" "$main_address" "$text_link_address" "$sidecar" >"$command_file"
    timeout 30s gdb-multiarch -q -nx -batch -x "$command_file" 2>&1 | tee "$transcript"
    validate_transcript "$target" "$transcript" "$main_load_start" "$main_load_end"
}

run_emulated() {
    local target=$1 emulator=$2 sysroot=$3 port=$4
    local sidecar="$fixture_dir/$target/libsemantic.so.ghidra-forge.dbg"
    local main_address text_link_address transcript command_file
    local main_load_start main_load_end
    main_address=$(symbol_address "$target" semantic.shared-driver.reference main)
    text_link_address=$(text_address "$target")
    read -r main_load_start main_load_end < <(main_load_bounds "$target")
    transcript="$result_dir/$target.txt"
    command_file="$result_dir/$target.gdb"
    gdb_commands "$target" "$main_address" "$text_link_address" "$sidecar" \
        "$sysroot" "$port" >"$command_file"
    "$emulator" -L "$sysroot" -g "$port" \
        "$fixture_dir/$target/semantic.shared-driver.stripped" &
    active_emulator_pid=$!
    timeout 30s gdb-multiarch -q -nx -batch -x "$command_file" 2>&1 | tee "$transcript"
    wait "$active_emulator_pid"
    active_emulator_pid=""
    validate_transcript "$target" "$transcript" "$main_load_start" "$main_load_end"
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

echo "shared-object-gdb=PASS"
