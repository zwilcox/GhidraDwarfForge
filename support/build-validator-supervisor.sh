#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 3 ]]; then
    echo 'usage: build-validator-supervisor.sh linux|windows output-directory evidence-directory' >&2
    exit 64
fi
repository=$(realpath "$(dirname "$0")/..")
platform=$1
output=$(realpath "$2")
mkdir -p "$3"
evidence=$(realpath "$3")
case "$platform" in
    linux) binary=forge-validator-supervisor; extra=() ;;
    windows) binary=forge-validator-supervisor.exe; extra=(-municode -static-libgcc -Wl,--no-insert-timestamp) ;;
    *) echo 'unsupported supervisor host' >&2; exit 64 ;;
esac
source_file="$repository/native/supervisor/forge-supervisor-$platform.c"
[[ ! -e "$output/$binary" && ! -L "$output/$binary" ]] || { echo 'supervisor output already exists' >&2; exit 1; }
compiler=${CC:-gcc}
"$compiler" -std=c11 -O2 -Wall -Wextra -Werror "${extra[@]}" "$source_file" -o "$evidence/first-$binary"
"$compiler" -std=c11 -O2 -Wall -Wextra -Werror "${extra[@]}" "$source_file" -o "$evidence/second-$binary"
cmp "$evidence/first-$binary" "$evidence/second-$binary"
cp "$evidence/first-$binary" "$output/$binary"
cp "$source_file" "$evidence/"
{
    printf 'forge-validator-supervisor protocol=1 platform=%s\n' "$platform"
    printf 'source commit: '
    git -C "$repository" rev-parse HEAD
    printf 'compiler: '
    "$compiler" --version
    printf 'options: -std=c11 -O2 -Wall -Wextra -Werror '
    printf '%s ' "${extra[@]}"
    printf '\nsource SHA-256:\n'
    sha256sum "$source_file"
    printf 'binary SHA-256:\n'
    sha256sum "$output/$binary"
    printf 'two-build comparison: byte-identical\n'
    if [[ "$platform" == windows ]]; then
        objdump -p "$output/$binary" | sed -n 's/^[[:space:]]*DLL Name: /dependency: /p'
        pacman -Q mingw-w64-x86_64-gcc
        pacman -Qo /mingw64/include/windows.h /mingw64/lib/libmsvcrt.a
    else
        readelf -d "$output/$binary"
    fi
} > "$output/SUPERVISOR-BUILD-METADATA.txt"
cp "$output/SUPERVISOR-BUILD-METADATA.txt" "$evidence/"
printf 'validator-supervisor-build=PASS platform=%s\n' "$platform"
