#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo 'usage: gdb-companion-remote.sh <target> [exec|pie|exec.no-sections] [normal|no-hostio]' >&2
    exit 64
fi
target=$1
role=${2:-pie}
discovery=${3:-normal}
[[ "$role" == exec || "$role" == pie || "$role" == exec.no-sections ]] || exit 64
[[ "$discovery" == normal || "$discovery" == no-hostio ]] || exit 64
repository=$(cd "$(dirname "$0")/../../.." && pwd)
case "$target" in
    x86_64) emulator=; sysroot=/ ;;
    aarch64) emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
    arm32) emulator=qemu-arm-static; sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf} ;;
    mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
    mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
    *) exit 64 ;;
esac
source "$repository/src/test/integration/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
result_root="$repository/build/test-results/gdb-companion-remote"
mkdir -p "$result_root"
result=$(mktemp -d "$result_root/$target.$role.$discovery.XXXXXXXX")
fixture="$repository/build/fixtures/$target/semantic.$role"
sidecar="$fixture.${FORGE_SYMBOL_SUFFIX:-ghidra-forge.dbg}"
reference="$fixture.reference"
if [[ "$role" == exec.no-sections ]]; then
    reference="$repository/build/fixtures/$target/semantic.exec.reference"
fi
for file in "$fixture.stripped" "$reference" "$sidecar" \
        "$sidecar.c" "$sidecar.gdb.py"; do
    test -s "$file"
done
if [[ -n "$emulator" ]]; then
    qemu_socket_start "$result/qemu" "$emulator" "$sysroot" "$fixture.stripped"
fi
FORGE_LOADER_FIXTURE="$fixture" FORGE_LOADER_RESULT="$result" \
    FORGE_LOADER_SIDECAR="$sidecar" FORGE_LOADER_REFERENCE="$reference" \
    FORGE_LOADER_ROLE="$role" FORGE_LOADER_TARGET="$target" \
    FORGE_LOADER_DISCOVERY="$discovery" \
    FORGE_LOADER_REMOTE="$qemu_socket_path" FORGE_LOADER_SYSROOT="$sysroot" \
    timeout 90s "${FORGE_LOADER_GDB:-gdb-multiarch}" -nx -q -batch \
        -ex 'set python print-stack full' \
        -x "$repository/src/test/integration/gdb-companion-remote.py" >"$result/gdb.txt" 2>&1
if [[ -n "$emulator" ]]; then
    qemu_socket_wait
fi
grep -Fq 'FORGE_REMOTE_COMPANION=PASS' "$result/gdb.txt"
if grep -Eq 'Python Exception|Traceback' "$result/gdb.txt"; then
    cat "$result/gdb.txt" >&2
    exit 1
fi
printf 'gdb-companion-remote=PASS %s\n' "$result"
