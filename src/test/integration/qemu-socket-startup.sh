#!/usr/bin/env bash
set -euo pipefail

# Linux-only real QEMU/GDB startup plus bounded failure cleanup checks.
repository_dir=$(realpath "$(dirname "$0")/../../..")
source "$repository_dir/src/test/integration/qemu-socket.sh"
root="$repository_dir/build/test-results/qemu-socket-startup"
mkdir -p "$root"
work=$(mktemp -d "$root/run.XXXXXXXX")
trap qemu_socket_cleanup EXIT
echo "qemu-socket-startup-results=$work"

assert_cleaned() {
    local log=$1 pid socket
    pid=$(sed -n 's/^pid=//p' "$log.endpoint")
    socket=$(sed -n 's/^socket=//p' "$log.endpoint")
    [[ -n "$pid" && -n "$socket" ]]
    if kill -0 "$pid" 2>/dev/null || [[ -e "$(dirname "$socket")" ]]; then
        echo "QEMU child or private socket directory survived cleanup: $log" >&2
        exit 1
    fi
}

qemu_socket_start "$work/success" /usr/bin/qemu-x86_64-static / /bin/true
test "$(stat -c %a "$qemu_socket_directory")" = 700
timeout 15s gdb-multiarch -q -nx -batch \
    -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex 'file /bin/true' -ex "target remote $qemu_socket_path" -ex continue \
    > "$work/gdb.txt" 2> "$work/gdb.stderr"
test ! -s "$work/gdb.stderr"
grep -Fq 'exited normally' "$work/gdb.txt"
qemu_socket_wait
assert_cleaned "$work/success"

# An actual non-bind startup failure must be reported once, never retried.
if qemu_socket_start "$work/missing" /usr/bin/qemu-x86_64-static / \
        "$work/missing-executable" > "$work/missing.log" 2>&1; then
    echo 'missing executable unexpectedly started' >&2
    exit 1
fi
grep -Fq 'QEMU exited before its debugger socket was ready' "$work/missing.log"
grep -Fxq 'exit=1' "$work/missing.status"
test "$(wc -l < "$work/missing.endpoint")" = 2
assert_cleaned "$work/missing"

# A child that never opens a listener must time out and be reaped.
cat > "$work/no-listener" <<'EOF'
#!/usr/bin/env bash
exec sleep 30
EOF
chmod 755 "$work/no-listener"
if qemu_socket_start "$work/timeout" "$work/no-listener" / /bin/true \
        > "$work/timeout.log" 2>&1; then
    echo 'child without a listener unexpectedly became ready' >&2
    exit 1
fi
grep -Fq 'QEMU debugger socket startup timed out' "$work/timeout.log"
assert_cleaned "$work/timeout"

# Failure after the socket is ready still terminates the waiting emulator.
qemu_socket_start "$work/cleanup" /usr/bin/qemu-x86_64-static / /bin/true
qemu_socket_cleanup
assert_cleaned "$work/cleanup"
printf '%s\n' 'real-qemu-gdb=PASS' 'private-directory-mode=0700' \
    'non-bind-startup-failure=PASS' 'startup-timeout=PASS' 'ready-child-cleanup=PASS' \
    > "$work/result.txt"
echo qemu-socket-startup=PASS
