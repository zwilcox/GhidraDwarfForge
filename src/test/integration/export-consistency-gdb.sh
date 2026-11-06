#!/usr/bin/env bash
set -euo pipefail
target=$1
original=$(realpath "$2")
artifact=$(realpath "$3")
prefix=$(realpath -m "$4")
scripts=$(realpath "$(dirname "$0")")
source "$scripts/qemu-socket.sh"
trap qemu_socket_cleanup EXIT
commands=(-ex run)
if [[ "$target" == aarch64 ]]; then
    qemu_socket_start "$prefix.qemu" qemu-aarch64-static /usr/aarch64-linux-gnu "$original"
    commands=(-ex 'set sysroot /usr/aarch64-linux-gnu' -ex "target remote $qemu_socket_path" -ex continue)
elif [[ "$target" != x86_64 ]]; then
    exit 2
fi
timeout --kill-after=5 60 gdb-multiarch -q -nx -batch \
    -ex 'set pagination off' -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex "directory \"$scripts/../fixtures\"" \
    -ex 'set disable-randomization off' -ex "file \"$original\"" -ex "symbol-file \"$artifact\"" \
    -ex 'info functions recovered_add' -ex 'break recovered_add' "${commands[@]}" \
    -ex 'list recovered_add' -ex 'ptype recovered_add' -ex 'print left' -ex 'print right' \
    -ex next -ex step -ex continue > "$prefix.log" 2>&1
if [[ "$target" == aarch64 ]]; then qemu_socket_wait; fi
grep -q 'Breakpoint 1, recovered_add' "$prefix.log"
grep -q 'type = int (int, int, int, int)' "$prefix.log"
grep -q '\$1 = 19' "$prefix.log"
grep -q '\$2 = 23' "$prefix.log"
grep -q 'exited normally' "$prefix.log"
if grep -Eq 'No such file|No symbol|Error|error:' "$prefix.log"; then exit 1; fi
