#!/usr/bin/env bash
set -euo pipefail

# Consume real exporter artifacts. Debuglink attachment mutates private test
# copies only; the product does not offer an attachment operation in this slice.
export LC_ALL=C
repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture_root="$repository_dir/build/fixtures"
result_root="$repository_dir/build/test-results/build-id-discovery"
targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then
    targets=(x86_64)
fi
mkdir -p "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
trap 'echo "automatic-association results: $result_dir"' EXIT

build_id() {
    readelf -n "$1" | sed -n 's/.*Build ID: //p'
}

symbol_address() {
    readelf -Ws "$1" | awk '$8 == "recovered_add" && !found { print "0x" $2; found = 1 }'
}

validate_diagnostics() {
    local log=$1 expected=${2:-}
    awk -v expected="$expected" '
        expected != "" && $0 == expected { matched++; next }
        tolower($0) ~ /warning:|error:|malformed|corrupt|could not find/ { print; bad = 1 }
        END { exit bad || (expected != "" && matched < 1) }
    ' "$log"
}

lookup() {
    local input=$1 debug_root=$2 debug_file=$3 source=$4 address=$5 log=$6
    local mode=${7:-present} runtime=${8:-0} explicit=${9:-0} expected_warning=${10:-}
    local symbol_command=()
    if [[ "$explicit" == 1 ]]; then
        symbol_command=(-ex "symbol-file \"$debug_file\"")
    fi
    FORGE_ASSOCIATION_MODE="$mode" FORGE_ASSOCIATION_ADDRESS="$address" \
        FORGE_ASSOCIATION_DEBUG_FILE="$debug_file" FORGE_ASSOCIATION_SOURCE="$source" \
        FORGE_ASSOCIATION_RUNTIME="$runtime" \
        timeout 45 gdb-multiarch -q -nx -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex 'set disable-randomization off' \
        -ex "set debug-file-directory $debug_root" \
        -ex "file \"$input\"" "${symbol_command[@]}" \
        -x "$repository_dir/src/test/integration/automatic-association-gdb.py" \
        > "$log" 2>&1
    validate_diagnostics "$log" "$expected_warning"
    grep -Fxq "automatic-association=$mode PASS" "$log"
    if [[ "$runtime" == 1 ]]; then
        grep -Fq 'exited normally' "$log"
    fi
}

for target in "${targets[@]}"; do
    case "$target" in
        x86_64) objcopy_tool=objcopy ;;
        aarch64) objcopy_tool=aarch64-linux-gnu-objcopy ;;
        arm32) objcopy_tool=arm-linux-gnueabihf-objcopy ;;
        mips32be) objcopy_tool=mips-linux-gnu-objcopy ;;
        mips32le) objcopy_tool=mipsel-linux-gnu-objcopy ;;
        *) echo "unknown fixture target: $target" >&2; exit 64 ;;
    esac
    fixture_dir="$fixture_root/$target"
    target_dir="$result_dir/$target"
    mkdir -p "$target_dir"
    manifest="$target_dir/originals.sha256"
    for role in exec pie exec.no-build-id; do
        for suffix in stripped ghidra-forge.dbg ghidra-forge.dbg.c; do
            original="$fixture_dir/semantic.$role.$suffix"
            test -s "$original"
            sha256sum "$original" >> "$manifest"
        done
    done

    for role in exec pie; do
        case_dir="$target_dir/$role"
        mkdir -p "$case_dir/build-id-root" "$case_dir/empty-debug-root" "$case_dir/debuglink"
        original="$fixture_dir/semantic.$role.stripped"
        sidecar="$fixture_dir/semantic.$role.ghidra-forge.dbg"
        source="$sidecar.c"
        cp "$source" "$case_dir/expected-source.c"
        address=$(symbol_address "$fixture_dir/semantic.$role.reference")
        identity=$(build_id "$original")
        test -n "$identity"
        test "$identity" = "$(build_id "$sidecar")"
        mismatch_role=pie
        if [[ "$role" == pie ]]; then
            mismatch_role=exec
        fi
        mismatch="$fixture_dir/semantic.$mismatch_role.ghidra-forge.dbg"
        test "$identity" != "$(build_id "$mismatch")"
        debug_directory="$case_dir/build-id-root/.build-id/${identity:0:2}"
        debug_file="$debug_directory/${identity:2}.debug"
        mkdir -p "$debug_directory"
        cp "$original" "$case_dir/original"
        cp "$mismatch" "$debug_file"
        lookup "$case_dir/original" "$case_dir/build-id-root" "$debug_file" \
            "$source" "$address" "$case_dir/mismatched-build-id.txt" absent 0 0 \
            "warning: File \"$debug_file\" has a different build-id, file skipped"
        cp "$sidecar" "$debug_file"
        runtime=0
        if [[ "$target:$role" == x86_64:exec ]]; then
            runtime=1
        fi
        lookup "$case_dir/original" "$case_dir/build-id-root" "$debug_file" \
            "$source" "$address" "$case_dir/matched-build-id.txt" present "$runtime"

        # An empty private global directory prevents a successful build-ID
        # lookup from masking a broken debuglink association.
        linked_input="$case_dir/debuglink/original"
        linked_debug="$case_dir/debuglink/forge.debug"
        cp "$original" "$linked_input"
        cp "$sidecar" "$linked_debug"
        "$objcopy_tool" "--add-gnu-debuglink=$linked_debug" "$linked_input"
        lookup "$linked_input" "$case_dir/empty-debug-root" "$linked_debug" \
            "$source" "$address" "$case_dir/matched-debuglink.txt" present "$runtime"
        sha256sum -c "$manifest" > "$case_dir/original-preservation.txt"
        echo "automatic-association-$target-$role=PASS"
    done

    # No build ID exists in either artifact, so CRC rejection cannot fall back
    # to a matching identity-based file anywhere in GDB's configured search.
    case_dir="$target_dir/no-build-id"
    mkdir -p "$case_dir/empty-debug-root" "$case_dir/debuglink"
    original="$fixture_dir/semantic.exec.no-build-id.stripped"
    sidecar="$fixture_dir/semantic.exec.no-build-id.ghidra-forge.dbg"
    source="$sidecar.c"
    cp "$source" "$case_dir/expected-source.c"
    address=$(symbol_address "$fixture_dir/semantic.exec.no-build-id.reference")
    test -z "$(build_id "$original")"
    test -z "$(build_id "$sidecar")"
    linked_input="$case_dir/debuglink/original"
    linked_debug="$case_dir/debuglink/forge.debug"
    cp "$original" "$linked_input"
    cp "$sidecar" "$linked_debug"
    "$objcopy_tool" "--add-gnu-debuglink=$linked_debug" "$linked_input"
    printf '\0' >> "$linked_debug"
    lookup "$linked_input" "$case_dir/empty-debug-root" "$linked_debug" \
        "$source" "$address" "$case_dir/crc-mismatch.txt" absent 0 0 \
        "warning: the debug information found in \"$linked_debug\" does not match \"$linked_input\" (CRC mismatch)."
    cp "$sidecar" "$linked_debug"
    lookup "$linked_input" "$case_dir/empty-debug-root" "$linked_debug" \
        "$source" "$address" "$case_dir/matched-debuglink.txt"
    runtime=0
    if [[ "$target" == x86_64 ]]; then
        runtime=1
    fi
    lookup "$original" "$case_dir/empty-debug-root" "$sidecar" "$source" \
        "$address" "$case_dir/no-build-id-explicit.txt" present "$runtime" 1
    sha256sum -c "$manifest" > "$target_dir/original-preservation.txt"
    echo "automatic-association-$target-no-build-id=PASS"
done
echo 'automatic-association=PASS'
