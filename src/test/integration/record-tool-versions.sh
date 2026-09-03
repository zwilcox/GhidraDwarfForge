#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <x86_64|aarch64|arm32|mips32be|mips32le> <output-file>" >&2
    exit 2
fi

target=$1
output_file=$2
: "${GHIDRA_INSTALL_DIR:?GHIDRA_INSTALL_DIR is required}"
: "${GHIDRA_ARCHIVE:?GHIDRA_ARCHIVE is required}"
: "${GHIDRA_ARCHIVE_SHA256:?GHIDRA_ARCHIVE_SHA256 is required}"
: "${LIBDWARF_VERSION:?LIBDWARF_VERSION is required}"
: "${LIBDWARF_ARCHIVE_SHA256:?LIBDWARF_ARCHIVE_SHA256 is required}"
: "${LIBDWARF_SOURCE_COMMIT:?LIBDWARF_SOURCE_COMMIT is required}"

case "$target" in
    x86_64)
        compiler=gcc
        runtime=()
        ;;
    aarch64)
        compiler=aarch64-linux-gnu-gcc
        runtime=(qemu-aarch64-static)
        ;;
    arm32)
        compiler=arm-linux-gnueabihf-gcc
        runtime=(qemu-arm-static)
        ;;
    mips32be)
        compiler=mips-linux-gnu-gcc
        runtime=(qemu-mips-static)
        ;;
    mips32le)
        compiler=mipsel-linux-gnu-gcc
        runtime=(qemu-mipsel-static)
        ;;
    *)
        echo "unknown target: $target" >&2
        exit 2
        ;;
esac

mkdir -p "$(dirname "$output_file")"
properties="$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
if [[ ! -f "$properties" ]]; then
    echo "Ghidra application properties are missing: $properties" >&2
    exit 1
fi

{
    printf 'target=%s\n' "$target"
    printf 'ghidra_archive=%s\n' "$GHIDRA_ARCHIVE"
    printf 'ghidra_archive_sha256=%s\n' "$GHIDRA_ARCHIVE_SHA256"
    grep -E '^application\.(version|release\.name|build\.date)=' "$properties"
    printf 'libdwarf_release=%s\n' "$LIBDWARF_VERSION"
    printf 'libdwarf_source_commit=%s\n' "$LIBDWARF_SOURCE_COMMIT"
    printf 'libdwarf_archive_sha256=%s\n' "$LIBDWARF_ARCHIVE_SHA256"
    sha256sum native-integration/libdwarf.so.2.3.2 \
        native-integration/libdwarfp.so.2.3.2
    printf '\n[java]\n'
    java -version
    printf '\n[gradle]\n'
    ./gradlew --version
    printf '\n[compiler]\n'
    "$compiler" --version
    printf '\n[readelf]\n'
    readelf --version
    printf '\n[llvm-dwarfdump]\n'
    llvm-dwarfdump --version
    printf '\n[independent-dwarfdump]\n'
    dwarfdump -V
    printf '\n[gdb]\n'
    gdb-multiarch --version
    if [[ "${#runtime[@]}" -eq 0 ]]; then
        printf '\n[runtime]\nnative x86-64 runner\n'
    else
        printf '\n[qemu]\n'
        "${runtime[@]}" --version
    fi
} 2>&1 | tee "$output_file"
