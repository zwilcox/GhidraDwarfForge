#!/usr/bin/env bash
# Source from Linux integration tests. QEMU 8.2.2 and GDB accept UNIX sockets;
# each child gets a short private path, with no shared TCP port to allocate.
qemu_socket_pid=
qemu_socket_directory=
qemu_socket_path=
qemu_socket_log=

qemu_socket_cleanup() {
    local cleanup_poll
    if [[ -n "$qemu_socket_pid" ]]; then
        if kill -0 "$qemu_socket_pid" 2>/dev/null; then
            kill "$qemu_socket_pid" 2>/dev/null || true
            for ((cleanup_poll = 0; cleanup_poll < 20; cleanup_poll++)); do
                if ! kill -0 "$qemu_socket_pid" 2>/dev/null; then break; fi
                sleep 0.05
            done
            kill -KILL "$qemu_socket_pid" 2>/dev/null || true
        fi
        wait "$qemu_socket_pid" 2>/dev/null || true
        qemu_socket_pid=
    fi
    if [[ -n "$qemu_socket_directory" ]]; then
        rm -f -- "$qemu_socket_path"
        rmdir -- "$qemu_socket_directory"
        qemu_socket_directory=
        qemu_socket_path=
    fi
}

qemu_socket_start() {
    local log=$1 emulator=$2 sysroot=$3 input=$4
    shift 4
    if [[ -n "$qemu_socket_pid" || -n "$qemu_socket_directory" ]]; then
        echo 'QEMU socket child is already active' >&2
        return 1
    fi
    qemu_socket_directory=$(mktemp -d /tmp/ghidra-forge-qemu.XXXXXXXX) || return 1
    qemu_socket_path="$qemu_socket_directory/gdb.socket"
    qemu_socket_log=$log
    "$emulator" -L "$sysroot" -g "$qemu_socket_path" "$input" "$@" \
        > "$log.stdout" 2> "$log.stderr" &
    qemu_socket_pid=$!
    if ! printf 'pid=%s\nsocket=%s\n' "$qemu_socket_pid" "$qemu_socket_path" \
            > "$log.endpoint"; then
        qemu_socket_cleanup
        return 1
    fi
    local startup_poll startup_status
    for ((startup_poll = 0; startup_poll < 100; startup_poll++)); do
        if ! kill -0 "$qemu_socket_pid" 2>/dev/null; then
            startup_status=0
            wait "$qemu_socket_pid" || startup_status=$?
            qemu_socket_pid=
            printf 'exit=%s\n' "$startup_status" > "$log.status"
            echo "QEMU exited before its debugger socket was ready (exit $startup_status): $log" >&2
            cat "$log.stderr" >&2
            qemu_socket_cleanup
            return 1
        fi
        # Looking at LISTEN state avoids consuming QEMU's single GDB connection.
        # The private directory makes this path unique to this launched child.
        if [[ -S "$qemu_socket_path" ]] && LC_ALL=C awk -v path="$qemu_socket_path" '
            $4 == "00010000" && $5 == "0001" && $8 == path { ready = 1 }
            END { exit !ready }
        ' /proc/net/unix; then
            return 0
        fi
        sleep 0.05
    done
    echo "QEMU debugger socket startup timed out: $log" >&2
    echo 'startup=timeout' > "$log.status"
    cat "$log.stderr" >&2
    qemu_socket_cleanup
    return 1
}

qemu_socket_wait() {
    local status=0 exit_poll
    for ((exit_poll = 0; exit_poll < 100; exit_poll++)); do
        if ! kill -0 "$qemu_socket_pid" 2>/dev/null; then break; fi
        sleep 0.05
    done
    if kill -0 "$qemu_socket_pid" 2>/dev/null; then
        echo "QEMU did not exit after GDB completed: $qemu_socket_log" >&2
        qemu_socket_cleanup
        return 1
    fi
    wait "$qemu_socket_pid" || status=$?
    qemu_socket_pid=
    printf 'exit=%s\n' "$status" > "$qemu_socket_log.status"
    if [[ -s "$qemu_socket_log.stderr" ]]; then
        cat "$qemu_socket_log.stderr" >&2
        status=1
    fi
    cat "$qemu_socket_log.stdout"
    qemu_socket_cleanup
    return "$status"
}
