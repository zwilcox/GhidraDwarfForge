#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp> [target ...]" >&2
    echo "requires generated semantic.{exec,pie}.extended-sections fixtures" >&2
    exit 2
fi

export LC_ALL=C
repository_dir=$(realpath "$(dirname "$0")/../../..")
ghidra_dir=$(realpath "$1")
consumer=$(realpath "$2")
producer=$(realpath "$3")
shift 3
if [[ $# -eq 0 ]]; then
    targets=(x86_64 mips32be)
else
    targets=("$@")
fi

for tool in readelf llvm-dwarfdump dwarfdump gdb-multiarch sha256sum cmp; do
    command -v "$tool" >/dev/null
done
fixture_dir="$repository_dir/build/fixtures"
headless_results="$repository_dir/build/test-results/headless-symbol-export"
gdb_results="$repository_dir/build/test-results/qemu-gdb-symbols"
result_root="$repository_dir/build/test-results/extended-sections-export"
mkdir -p "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
echo "extended-sections-results=$result_dir"
active_case=""
stage=preparation
originals=()
for target in "${targets[@]}"; do
    for role in exec pie; do
        for suffix in reference stripped extended-sections; do
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
    for file in "$headless_results/$target.$role."*; do
        if [[ -f "$file" && -f "$active_case/export-started" &&
                "$file" -nt "$active_case/export-started" ]]; then
            cp -- "$file" "$active_case/"
        fi
    done
    if [[ -f "$active_case/gdb-started" &&
            "$gdb_results/$target.$role.txt" -nt "$active_case/gdb-started" ]]; then
        cp -- "$gdb_results/$target.$role.txt" "$active_case/gdb.txt"
    fi
    for file in "$output" "$output.c"; do
        if [[ -f "$file" && -f "$active_case/export-started" &&
                "$file" -nt "$active_case/export-started" ]]; then
            cp -- "$file" "$active_case/"
        fi
    done
}

finish() {
    local status=$?
    archive_case || status=1
    if ! sha256sum -c "$result_dir/originals.sha256" \
            >"$result_dir/input-preservation.txt" 2>&1; then
        cat "$result_dir/input-preservation.txt" >&2
        status=1
    fi
    echo "extended-sections-export results: $result_dir"
    exit "$status"
}
trap finish EXIT

require_empty() {
    if [[ -s "$1" ]]; then
        cat "$1" >&2
        echo "unexpected readelf diagnostic: $1" >&2
        return 1
    fi
}

validate_extended_header() {
    local artifact=$1 destination=$2
    local count_field index_field count index
    readelf --file-header "$artifact" >"$destination.header.txt" \
        2>"$destination.header.stderr"
    require_empty "$destination.header.stderr"
    count_field=$(awk -F':[[:space:]]*' '/Number of section headers:/ { print $2 }' \
        "$destination.header.txt")
    index_field=$(awk -F':[[:space:]]*' \
        '/Section header string table index:/ { print $2 }' "$destination.header.txt")
    if [[ ! "$count_field" =~ ^0[[:space:]]+\(([0-9]+)\)$ ]]; then
        echo "expected extended e_shnum encoding in $artifact: $count_field" >&2
        return 1
    fi
    count=${BASH_REMATCH[1]}
    if [[ ! "$index_field" =~ ^65535[[:space:]]+\(([0-9]+)\)$ ]]; then
        echo "expected SHN_XINDEX encoding in $artifact: $index_field" >&2
        return 1
    fi
    index=${BASH_REMATCH[1]}
    if ((count < 0xff00 || index < 0xff00 || index >= count)); then
        echo "extended section metadata is out of range in $artifact" >&2
        return 1
    fi
    printf 'section_count=%s\nsection_name_index=%s\n' "$count" "$index" \
        >"$destination.metadata.txt"
}

repeat_target=${targets[0]}
for target in "${targets[@]}"; do
    for role in exec pie; do
        case_dir="$result_dir/$target/$role"
        mkdir -p "$case_dir"
        input="$fixture_dir/$target/semantic.$role.extended-sections"
        output="$fixture_dir/$target/semantic.$role.ghidra-forge.dbg"
        cp -- "$input" "$case_dir/input.elf"
        validate_extended_header "$input" "$case_dir/input"
        readelf --notes "$input" >"$case_dir/input.notes.txt" \
            2>"$case_dir/input.notes.stderr"
        require_empty "$case_dir/input.notes.stderr"
        input_hash=$(sha256sum "$input" | cut -d' ' -f1)
        iterations=(first)
        if [[ "$target:$role" == "$repeat_target:exec" ]]; then
            iterations+=(second)
        fi

        for iteration in "${iterations[@]}"; do
            active_case="$case_dir/$iteration"
            mkdir -p "$active_case"
            stage=headless-export
            touch "$active_case/export-started"
            echo "extended-sections-export: $target $role $iteration import/export"
            FIXTURE_ROLE="$role" FIXTURE_INPUT_SUFFIX=extended-sections \
                "$repository_dir/src/test/integration/headless-symbol-export.sh" \
                "$ghidra_dir" "$consumer" "$producer" "$target" \
                >"$active_case/headless-console.txt" 2>&1

            stage=extended-metadata
            validate_extended_header "$output" "$active_case/sidecar"
            readelf --notes "$output" >"$active_case/sidecar.notes.txt" \
                2>"$active_case/sidecar.notes.stderr"
            require_empty "$active_case/sidecar.notes.stderr"
            grep 'Build ID:' "$case_dir/input.notes.txt" >"$active_case/input.build-id.txt"
            grep 'Build ID:' "$active_case/sidecar.notes.txt" >"$active_case/sidecar.build-id.txt"
            cmp "$active_case/input.build-id.txt" "$active_case/sidecar.build-id.txt"

            stage=gdb
            touch "$active_case/gdb-started"
            FIXTURE_ROLE="$role" FIXTURE_INPUT_SUFFIX=extended-sections \
                "$repository_dir/src/test/integration/qemu-gdb-symbols.sh" "$target" \
                >"$active_case/gdb-console.txt" 2>&1
            if grep -Eiq 'warning:|error:|malformed|corrupt|could not find' \
                    "$gdb_results/$target.$role.txt"; then
                echo "unexpected GDB diagnostic for $target $role $iteration" >&2
                exit 1
            fi
            test "$input_hash" = "$(sha256sum "$input" | cut -d' ' -f1)"
            sha256sum "$output" "$output.c" >"$active_case/artifacts.sha256"
            {
                echo "target=$target"
                echo "role=$role"
                echo "iteration=$iteration"
                echo "runtime_input=$input"
                echo "input_sha256=$input_hash"
                echo "extended_sections_export=PASS"
            } | tee "$active_case/result.txt"
            stage=complete
            archive_case
            active_case=""
        done
        if [[ ${#iterations[@]} == 2 ]]; then
            cmp "$case_dir/first/artifacts.sha256" "$case_dir/second/artifacts.sha256"
            echo "deterministic_rerun=PASS" >"$case_dir/determinism.txt"
        fi
    done
done

echo "extended-sections-export=PASS"
