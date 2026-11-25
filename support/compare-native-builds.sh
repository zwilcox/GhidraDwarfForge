#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <linux|windows> <first-directory> <second-directory> <report>" >&2
    exit 64
fi

platform=$1
first_directory=$(realpath "$2")
second_directory=$(realpath "$3")
report=$(realpath -m "$4")

if [[ ! -d "$first_directory" || ! -d "$second_directory" ]]; then
    echo "both native build directories must exist" >&2
    exit 64
fi

temporary_parent=$(realpath -- "${TMPDIR:-/tmp}")
temporary=$(mktemp -d -p "$temporary_parent" ghidra-dwarf-forge-native-compare.XXXXXXXX)
cleanup() {
    case "$temporary" in
        "$temporary_parent"/ghidra-dwarf-forge-native-compare.*) rm -rf -- "$temporary" ;;
        *) echo "refusing to remove unexpected temporary path $temporary" >&2 ;;
    esac
}
trap cleanup EXIT

manifest_linux() {
    local directory=$1 output=$2 library
    find "$directory" -maxdepth 1 -type f -name 'libdwarf*.so*' -printf '%f\n' |
        sort > "$output.files"
    : > "$output"
    while IFS= read -r name; do
        library="$directory/$name"
        {
            echo "FILE $name"
            readelf -h "$library" |
                sed -n -E '/^[[:space:]]*(Class|Data|Type|Machine):/p'
            readelf -d "$library" |
                sed -n -E '/\((NEEDED|SONAME|RUNPATH)\)/p' |
                sed -E 's/0x[0-9a-f]+//g; s/^[[:space:]]+//; s/[[:space:]]+/ /g' |
                sed -E 's/^\(RUNPATH\).*$/\(RUNPATH\) normalized-build-path/' |
                sort
            nm -D --defined-only "$library" |
                awk '{ print $(NF-1), $NF }' | sort
        } >> "$output"
    done < "$output.files"
}

manifest_windows() {
    local directory=$1 output=$2 library
    find "$directory" -maxdepth 1 -type f -iname '*.dll' -printf '%f\n' |
        sort -f > "$output.files"
    : > "$output"
    while IFS= read -r name; do
        library="$directory/$name"
        {
            echo "FILE $name"
            objdump -f "$library" |
                sed -n -E 's/^.*file format[[:space:]]+/file format /p; /architecture:/p'
            objdump -p "$library" |
                sed -n -E 's/^[[:space:]]*DLL Name: /NEEDED /p' |
                sort -f
            nm -g --defined-only "$library" |
                awk '{ print $(NF-1), $NF }' | sort
        } >> "$output"
    done < "$output.files"
}

case "$platform" in
    linux)
        manifest_linux "$first_directory" "$temporary/first"
        manifest_linux "$second_directory" "$temporary/second"
        ;;
    windows)
        manifest_windows "$first_directory" "$temporary/first"
        manifest_windows "$second_directory" "$temporary/second"
        ;;
    *)
        echo "unsupported platform $platform" >&2
        exit 64
        ;;
esac

for inventory in "$temporary/first.files" "$temporary/second.files"; do
    for stem in libdwarf libdwarfp; do
        if [[ $platform == linux ]]; then
            pattern="^${stem}\.so(\.[0-9]+)*$"
        else
            pattern="^${stem}(-[0-9]+)?\.dll$"
        fi
        if ! grep -Eiq -- "$pattern" "$inventory"; then
            echo "$platform native ABI inventory is missing $stem" >&2
            exit 1
        fi
    done
done

mkdir -p "$(dirname "$report")"
{
    echo "native-abi-inventory=$platform"
    diff -u "$temporary/first.files" "$temporary/second.files"
    diff -u "$temporary/first" "$temporary/second"
    echo "first-build-sha256:"
    (cd "$first_directory" && find . -maxdepth 1 -type f \
        \( -name 'libdwarf*.so*' -o -iname '*.dll' \) -print0 |
        sort -z | xargs -0 sha256sum)
    echo "second-build-sha256:"
    (cd "$second_directory" && find . -maxdepth 1 -type f \
        \( -name 'libdwarf*.so*' -o -iname '*.dll' \) -print0 |
        sort -z | xargs -0 sha256sum)
    echo "native-abi-inventory=PASS"
} | tee "$report"
