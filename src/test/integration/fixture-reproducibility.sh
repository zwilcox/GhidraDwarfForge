#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <x86_64|aarch64|arm32|mips32be|mips32le>" >&2
    exit 2
fi

target=$1
case "$target" in
    x86_64|aarch64|arm32|mips32be|mips32le) ;;
    *)
        echo "unsupported fixture target: $target" >&2
        exit 2
        ;;
esac

repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture_source_dir="$repository_dir/src/test/fixtures"
fixture_dir="$repository_dir/build/fixtures/$target"
result_dir="$repository_dir/build/test-results/fixture-metadata/$target"
temporary_root=$(mktemp -d -t ghidra-dwarf-forge-fixtures.XXXXXXXX)

cleanup() {
    case "$temporary_root" in
        /tmp/ghidra-dwarf-forge-fixtures.*)
            rm -rf -- "$temporary_root"
            ;;
        *)
            echo "refusing to remove unexpected temporary path: $temporary_root" >&2
            ;;
    esac
}
trap cleanup EXIT

expected_sources=(
    Makefile
    README.md
    minimal.c
    semantic.c
    shared_driver.c
    shared_semantic.c
)
mapfile -t actual_sources < <(
    cd "$fixture_source_dir"
    find . -maxdepth 1 -type f -printf '%P\n' | LC_ALL=C sort
)
if [[ "${actual_sources[*]}" != "${expected_sources[*]}" ]]; then
    echo "fixture source inventory contains an unreviewed file" >&2
    printf 'expected: %s\nactual: %s\n' "${expected_sources[*]}" "${actual_sources[*]}" >&2
    exit 1
fi

make -C "$fixture_source_dir" "$target" > "$temporary_root/current.log"
for build_name in first second; do
    build_dir="$temporary_root/$build_name"
    make -C "$fixture_source_dir" BUILD_DIR="$build_dir" "$target" \
        > "$temporary_root/$build_name.log"
    (
        cd "$build_dir/$target"
        find . -maxdepth 1 -type f -printf '%P\n' | LC_ALL=C sort
    ) > "$temporary_root/$build_name.files"
done

cmp "$temporary_root/first.files" "$temporary_root/second.files"
while IFS= read -r relative; do
    cmp "$temporary_root/first/$target/$relative" \
        "$temporary_root/second/$target/$relative"
    cmp "$temporary_root/first/$target/$relative" "$fixture_dir/$relative"
done < "$temporary_root/first.files"

mkdir -p "$result_dir/elf"
: > "$result_dir/SHA256SUMS"
while IFS= read -r relative; do
    sha256sum "$fixture_dir/$relative" |
        sed "s#  $fixture_dir/#  #" >> "$result_dir/SHA256SUMS"
done < "$temporary_root/first.files"

while IFS= read -r relative; do
    artifact="$fixture_dir/$relative"
    metadata="$result_dir/elf/$relative.txt"
    {
        echo "artifact=$relative"
        echo "sha256=$(sha256sum "$artifact" | cut -d' ' -f1)"
        readelf -h "$artifact"
        readelf -l "$artifact"
        readelf -S "$artifact"
        readelf -n "$artifact"
    } > "$metadata"
done < "$temporary_root/first.files"

partial="$fixture_dir/semantic.partial.stripped"
if readelf -S "$partial" | grep -q '[.]debug_'; then
    echo "partially stripped fixture still contains compiler DWARF: $partial" >&2
    exit 1
fi
readelf -Ws "$partial" | grep -Eq '[[:space:]]recovered_add$'

{
    echo "target=$target"
    echo "source_inventory=${expected_sources[*]}"
    echo "artifact_count=$(wc -l < "$temporary_root/first.files")"
    echo "byte_identical_rebuild=PASS"
    echo "partially_stripped_symbols=PASS"
    echo "redistributable_source_only=PASS"
} | tee "$result_dir/result.txt"
