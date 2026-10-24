#!/usr/bin/env python3
"""Run the real shared-object test while holding its historical TCP port."""

import errno
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile


def main():
    offsets = {"aarch64": 0, "arm32": 3, "mips32be": 1, "mips32le": 2}
    if len(sys.argv) != 2 or sys.argv[1] not in offsets:
        raise SystemExit("usage: shared-object-port-collision.py <emulated-target>")
    target = sys.argv[1]
    repository = Path(__file__).resolve().parents[3]
    root = repository / "build/test-results/shared-object-port-collision"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run.", dir=root))
    script = repository / "src/test/integration/shared-object-gdb.sh"
    print(f"shared-object-port-collision-results={work}", flush=True)
    # The shell reports its PID and waits; exec preserves the exact PID that the
    # former harness used to derive its TCP port. No GDB run is retried.
    child = None
    listener = None
    try:
        for _ in range(5):
            child = subprocess.Popen(
                ["bash", "-c", 'printf "%s\\n" "$$"; IFS= read -r ready; '
                    '[[ "$ready" == go ]] || exit 1; exec "$@"',
                    "collision-control", str(script), target],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, start_new_session=True)
            pid = int(child.stdout.readline().strip())
            if pid != child.pid:
                raise AssertionError("shell exec PID identity changed")
            port = 30000 + pid % 15000 + offsets[target]
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.bind(("0.0.0.0", port))
                listener.listen(1)
                break
            except OSError as error:
                listener.close()
                listener = None
                child.terminate()
                child.communicate(timeout=2)
                if error.errno != errno.EADDRINUSE:
                    raise
        else:
            raise AssertionError("could not reserve a controlled historical port")
        (work / "occupied-port.txt").write_text(f"pid={pid}\nport={port}\n")
        output, _ = child.communicate("go\n", timeout=90)
        (work / "shared-object.txt").write_text(output)
        print(output, end="")
        if child.returncode != 0 or "shared-object-gdb=PASS" not in output:
            raise AssertionError(f"shared-object test failed: exit {child.returncode}")
        if re.search(r"warning:|error:", output, re.IGNORECASE):
            raise AssertionError("shared-object collision control emitted a diagnostic")
        if "target remote /tmp/ghidra-forge-qemu." not in (
                repository / f"build/test-results/shared-object-gdb/{target}.gdb").read_text():
            raise AssertionError("real GDB did not use the private UNIX socket")
        (work / "result.txt").write_text("occupied-historical-tcp-port=PASS\n")
        print("shared-object-port-collision=PASS")
    finally:
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=3)
        if listener is not None:
            listener.close()


if __name__ == "__main__":
    main()
