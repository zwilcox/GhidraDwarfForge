#!/usr/bin/env bash
set -euo pipefail

repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture_dir="$repository_dir/build/fixtures"
result_dir="$repository_dir/build/test-results/qemu-gdb-oracle"
source_dir="$repository_dir/src/test/fixtures"
base_port=$((20000 + ($$ % 20000)))
active_emulator_pid=""
fixture_role=${FIXTURE_ROLE:-exec}
debug_artifact_suffix=${DEBUG_ARTIFACT_SUFFIX:-reference}
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

validate_transcript() {
    local transcript=$1
    grep -q "Breakpoint 1, recovered_add" "$transcript"
    grep -q "left = 19" "$transcript"
    grep -q "right = 23" "$transcript"
    grep -q '\$1 = 42' "$transcript"
    grep -q "exited normally" "$transcript"
}

run_emulated_case() {
    local target=$1
    local emulator=$2
    local sysroot=$3
    local port=$4
    local debug_artifact="$fixture_dir/$target/semantic.$fixture_role.$debug_artifact_suffix"
    local stripped="$fixture_dir/$target/semantic.$fixture_role.stripped"
    local transcript="$result_dir/$target.$fixture_role.$debug_artifact_suffix.gdb.txt"

    for required in "$debug_artifact" "$stripped" "$emulator" "$sysroot"; do
        if [[ ! -e "$required" ]]; then
            echo "missing test dependency: $required" >&2
            exit 1
        fi
    done

    "$emulator" -L "$sysroot" -g "$port" "$stripped" &
    active_emulator_pid=$!
    sleep 0.2
    if ! kill -0 "$active_emulator_pid" 2>/dev/null; then
        echo "emulator failed before GDB connected: $target" >&2
        wait "$active_emulator_pid"
    fi

    timeout 30s gdb-multiarch -q -batch \
        -ex "set debuginfod enabled off" \
        -ex "set auto-solib-add off" \
        -ex "set sysroot $sysroot" \
        -ex "set substitute-path /ghidra-dwarf-forge-fixture $source_dir" \
        -ex "file $stripped" \
        -ex "symbol-file $debug_artifact" \
        -ex "target remote :$port" \
        -ex "break recovered_add" \
        -ex "continue" \
        -ex "info args" \
        -ex "list recovered_add" \
        -ex "next" \
        -ex "print sum" \
        -ex "continue" 2>&1 | tee "$transcript"

    wait "$active_emulator_pid"
    active_emulator_pid=""

    validate_transcript "$transcript"
}

run_native_case() {
    local target=x86_64
    local debug_artifact="$fixture_dir/$target/semantic.$fixture_role.$debug_artifact_suffix"
    local stripped="$fixture_dir/$target/semantic.$fixture_role.stripped"
    local transcript="$result_dir/$target.$fixture_role.$debug_artifact_suffix.gdb.txt"
    if [[ ! -f "$debug_artifact" || ! -f "$stripped" ]]; then
        echo "missing test dependency: $debug_artifact or $stripped" >&2
        exit 1
    fi

    timeout 30s gdb-multiarch -q -batch \
        -ex "set debuginfod enabled off" \
        -ex "set auto-solib-add off" \
        -ex "set substitute-path /ghidra-dwarf-forge-fixture $source_dir" \
        -ex "file $stripped" \
        -ex "symbol-file $debug_artifact" \
        -ex "break recovered_add" \
        -ex "run" \
        -ex "info args" \
        -ex "list recovered_add" \
        -ex "next" \
        -ex "print sum" \
        -ex "continue" 2>&1 | tee "$transcript"
    validate_transcript "$transcript"
}

for target in "${targets[@]}"; do
    case "$target" in
        x86_64)
            run_native_case
            ;;
        aarch64)
            run_emulated_case aarch64 /usr/bin/qemu-aarch64-static \
                /usr/aarch64-linux-gnu "$base_port"
            ;;
        arm32)
            run_emulated_case arm32 /usr/bin/qemu-arm-static \
                /usr/arm-linux-gnueabihf "$((base_port + 3))"
            ;;
        mips32be)
            run_emulated_case mips32be /usr/bin/qemu-mips-static \
                /usr/mips-linux-gnu "$((base_port + 1))"
            ;;
        mips32le)
            run_emulated_case mips32le /usr/bin/qemu-mipsel-static \
                /usr/mipsel-linux-gnu "$((base_port + 2))"
            ;;
        *)
            echo "unknown target: $target" >&2
            exit 2
            ;;
    esac
done

echo "qemu-gdb-oracle=PASS"
