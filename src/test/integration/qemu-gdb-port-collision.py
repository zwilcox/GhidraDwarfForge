#!/usr/bin/env python3
"""Run the real QEMU/GDB oracle while holding its historical TCP port."""

import errno
import hashlib
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile


def main():
    offsets = {"aarch64": 0, "arm32": 3, "mips32be": 1, "mips32le": 2}
    if len(sys.argv) != 2 or sys.argv[1] not in offsets:
        raise SystemExit("usage: qemu-gdb-port-collision.py <emulated-target>")
    target = sys.argv[1]
    repository = Path(__file__).resolve().parents[3]
    root = repository / "build/test-results/qemu-gdb-port-collision"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run.", dir=root))
    script = repository / "src/test/integration/qemu-gdb-oracle.sh"
    oracle_directory = work / "oracle"
    environment = dict(os.environ, FORGE_QEMU_ORACLE_RESULT_DIR=str(oracle_directory))
    role = os.environ.get("FIXTURE_ROLE", "exec")
    suffix = os.environ.get("DEBUG_ARTIFACT_SUFFIX", "reference")
    fixture = repository / "build/fixtures" / target
    inputs = [fixture / f"semantic.{role}.stripped", fixture / f"semantic.{role}.{suffix}"]
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    print(f"qemu-gdb-port-collision-results={work}", flush=True)
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
                stderr=subprocess.STDOUT, text=True, start_new_session=True, env=environment)
            pid = int(child.stdout.readline().strip())
            if pid != child.pid:
                raise AssertionError("shell exec PID identity changed")
            port = 20000 + pid % 20000 + offsets[target]
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
        (work / "qemu-gdb.txt").write_text(output)
        print(output, end="")
        if child.returncode != 0 or "qemu-gdb-oracle=PASS" not in output:
            raise AssertionError(f"qemu-gdb test failed: exit {child.returncode}")
        endpoint = oracle_directory / f"{target}.{role}.{suffix}.emulator"
        fields = dict(line.split("=", 1) for line in Path(str(endpoint) + ".endpoint").read_text().splitlines())
        socket_path = Path(fields["socket"])
        if not str(socket_path).startswith("/tmp/ghidra-forge-qemu.") or socket_path.parent.exists():
            raise AssertionError("private QEMU socket directory was not used and cleaned")
        if Path(str(endpoint) + ".status").read_text() != "exit=0\n":
            raise AssertionError("QEMU did not exit normally")
        listener.settimeout(0.1)
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            pass
        else:
            connection.close()
            raise AssertionError("GDB connected to the occupied TCP port")
        if hashes != {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}:
            raise AssertionError("oracle changed its executable or sidecar input")
        (work / "result.txt").write_text("occupied-historical-tcp-port=PASS\n")
        print("qemu-gdb-port-collision=PASS")
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
