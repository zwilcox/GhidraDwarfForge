#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <ghidra-dir> <libdwarf> <libdwarfp>" >&2
    exit 2
fi

export LC_ALL=C
repository_dir=$(realpath "$(dirname "$0")/../../..")
ghidra_dir=$(realpath "$1")
consumer=$(realpath "$2")
producer=$(realpath "$3")
fixture_dir="$repository_dir/build/fixtures/x86_64"
result_root="$repository_dir/build/test-results/large-headless-export"
mkdir -p "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
suffix="large-file.${result_dir##*/}"
input="$fixture_dir/semantic.exec.$suffix"
output="$fixture_dir/semantic.exec.ghidra-forge.dbg"
original="$fixture_dir/semantic.exec.stripped"
test -f "$original"
test ! -e "$input"

cleanup() {
    local status=$?
    rm -f -- "$input"
    # Generated large artifacts are validated in place, never uploaded to CI.
    # Keep compact transcripts, source and hashes for diagnosis instead.
    if [[ -f "$result_dir/export-started" && -f "$output" &&
            "$output" -nt "$result_dir/export-started" ]]; then
        stat -c 'sidecar_size=%s' "$output" >"$result_dir/sidecar-size.txt"
        rm -f -- "$output"
    fi
    sha256sum -c "$result_dir/original.sha256" \
        >"$result_dir/input-preservation.txt" 2>&1 || status=1
    echo "large-headless-export results: $result_dir"
    exit "$status"
}

sha256sum "$original" >"$result_dir/original.sha256"
trap cleanup EXIT
cp --sparse=always -- "$original" "$input"
truncate -s 2147487744 "$input"
sha256sum "$input" >"$result_dir/large-input.sha256"
stat -c 'input_size=%s' "$input" >"$result_dir/input-size.txt"

for iteration in first repeat; do
    touch "$result_dir/export-started"
    # Avoid unrelated loader probes: Ghidra 12's SOM detector allocates from
    # arbitrary bytes in this ELF and can exhaust its heap before ELF import.
    GHIDRA_FORCE_ELF_LOADER=1 FIXTURE_INPUT_SUFFIX="$suffix" FIXTURE_ROLE=exec \
        "$repository_dir/src/test/integration/headless-symbol-export.sh" \
        "$ghidra_dir" "$consumer" "$producer" x86_64 \
        >"$result_dir/$iteration.export.txt" 2>&1
    cp -- "$repository_dir/build/test-results/headless-symbol-export/x86_64.exec."* \
        "$result_dir/"
    test "$(stat -c %s "$output")" -gt 2147483647
    sha256sum "$output" "$output.c" >"$result_dir/$iteration.output.sha256"
    cp -- "$output.c" "$result_dir/$iteration.dbg.c"
    sha256sum -c "$result_dir/large-input.sha256" \
        >"$result_dir/$iteration.large-input-preservation.txt"
    if [[ "$iteration" == first ]]; then
        FIXTURE_INPUT_SUFFIX="$suffix" FIXTURE_ROLE=exec \
            "$repository_dir/src/test/integration/qemu-gdb-symbols.sh" x86_64 \
            >"$result_dir/gdb-harness.txt" 2>&1
        cp -- "$repository_dir/build/test-results/qemu-gdb-symbols/x86_64.exec.txt" \
            "$result_dir/gdb.txt"
    fi
done

cmp "$result_dir/first.output.sha256" "$result_dir/repeat.output.sha256"
printf 'large-headless-export=PASS\ninput-and-output-over-2GiB=PASS\n' \
    >"$result_dir/result.txt"
cat "$result_dir/result.txt"
