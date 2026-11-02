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
    aarch64-abi.c
    aarch64-abi.h
    aarch64-vector.c
    aggregate-return-calls.c
    arm-aggregate-pcs.c
    arm-dynamic-pcs.c
    arm-hfa-controls.S
    arm-hfa-controls.c
    arm-hfa-lifetimes.c
    arm-mixed-body-driver.c
    arm-mixed-body.S
    arm-mixed-function-aliases.cpp
    arm-pcs-call-reference.c
    arm-pcs-profile.c
    arm-pcs-start.S
    arm-stack-aggregates.c
    arm-symbol-boundary.S
    arm-symbol-boundary.ld
    arm-thumb-after.c
    arm-thumb-caller.c
    arm-thumb-leaf.c
    arm-thumb-shared-driver.c
    bitfield-values.c
    call-memory-boundaries.c
    calling-convention.c
    composite-register-prefix.c
    composite-value-flow.c
    curated-thunk.c
    custom-call-storage.c
    defined-register-local.c
    direct-leaf-call.c
    direct-leaf-callee.c
    dynamic-composite-aggregate.c
    dynamic-composite-caller.c
    dynamic-composite-scalar.c
    dynamic-parameter-storage.c
    external-function-declarations.c
    formal-function-return.c
    fp_register_aliases.c
    function-pointer-conventions.c
    function-static-scopes.c
    function-type-flags.c
    function_entry_ranges.S
    function_entry_ranges.c
    i386-alias-entry.cpp
    i386-profile.c
    inspected-call-callees.c
    later-register-local.c
    lexical-shadow.c
    lexical-statics.c
    local-call-lifetimes.c
    local-definition-flow.c
    merged-local-mappings.c
    minimal.c
    mips-floating-call.c
    mips-truncated-space-start.S
    mips-truncated-space.c
    mips_layout_arguments.c
    mips_wide_arguments.c
    mixed-incoming-prefix.c
    mutable-stack-mappings.c
    nonzero_load_offset.c
    nonzero_load_offset.ld
    nonzero_load_offset_start.S
    object-parameter.cpp
    object-return.cpp
    opaque-register-effects.c
    outside-body-flow.c
    overloaded-signatures.cpp
    recovered-default-returns.c
    recovered-parameter-types.c
    register-copy.c
    register_prefix.c
    retained-function-aliases.cpp
    same-name-types.cpp
    second-register-copy.c
    semantic.c
    shared_driver.c
    shared_semantic.c
    stack-call-lifetimes.c
    stack-control-flow.c
    stack-first-use.c
    stack-local-definitions.c
    stack-local-effects.c
    stack-spill.c
    stack-value-transitions.c
    terminal-composite.c
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
