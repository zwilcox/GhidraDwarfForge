#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo 'usage: gdb-companion-shared.sh <target> [normal|ambiguous] [normal|no-hostio]' >&2
    exit 64
fi
target=$1
mode=${2:-normal}
transport=${3:-normal}
[[ "$mode" == normal || "$mode" == ambiguous ]] || exit 64
[[ "$transport" == normal || "$transport" == no-hostio ]] || exit 64
repository=$(cd "$(dirname "$0")/../../.." && pwd)
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
case "$target" in
    x86_64) emulator=; sysroot=/ ;;
    aarch64) emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
    arm32) emulator=qemu-arm-static; sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf} ;;
    mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
    mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
    *) exit 64 ;;
esac
fixture="$repository/build/fixtures/$target"
root="$repository/build/test-results/gdb-companion-shared"
mkdir -p "$root"
result=$(mktemp -d "$root/$target.$mode.$transport.XXXXXXXX")
for file in "$fixture/semantic.loader-driver.stripped" "$fixture/semantic.loader-driver.reference" \
        "$fixture/libsemantic.so.stripped" "$fixture/libsemantic.so.ghidra-forge.dbg.gdb.py"; do
    test -s "$file"
done
if [[ -n "$emulator" ]]; then
    qemu_socket_start "$result/qemu" "$emulator" "$sysroot" \
        "$fixture/semantic.loader-driver.stripped" "$fixture/libsemantic.so.stripped" "$mode"
fi
FORGE_SHARED_FIXTURE="$fixture" FORGE_SHARED_RESULT="$result" FORGE_SHARED_MODE="$mode" \
    FORGE_SHARED_REMOTE="$qemu_socket_path" FORGE_SHARED_SYSROOT="$sysroot" \
    FORGE_SHARED_TRANSPORT="$transport" \
    timeout 90s "${FORGE_LOADER_GDB:-gdb-multiarch}" -nx -q -batch \
        -ex 'set python print-stack full' \
        -x "$repository/src/test/integration/gdb-companion-shared.py" >"$result/gdb.txt" 2>&1
if [[ -n "$emulator" ]]; then
    qemu_socket_wait
fi
grep -Fq 'FORGE_SHARED_COMPANION=PASS' "$result/gdb.txt"
if grep -Eq 'Python Exception|Traceback' "$result/gdb.txt"; then
    cat "$result/gdb.txt" >&2
    exit 1
fi
printf 'gdb-companion-shared=PASS %s\n' "$result"
