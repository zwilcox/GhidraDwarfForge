#!/usr/bin/env python3
"""Attach to an owned live PIE image, then check invalidation across real exec."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]


def quoted(path):
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    original = args.input.resolve(strict=True)
    sidecar = args.sidecar.resolve(strict=True)
    source = Path(str(sidecar) + ".c")
    companion = Path(str(sidecar) + ".gdb.py")
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (original, sidecar, source, companion)}
    args.results.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run.", dir=args.results.resolve()))
    hook = directory / "lifecycle.so"
    compile_result = subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-Wall", "-Wextra", "-Werror",
        str(ROOT / "src/test/fixtures/gdb-loader-lifecycle.c"), "-o", str(hook)],
        capture_output=True, text=True, timeout=30)
    (directory / "compile.txt").write_text(compile_result.stdout + compile_result.stderr)
    compile_result.check_returncode()
    next_image = Path(shutil.which("true")).resolve(strict=True)
    environment = os.environ.copy()
    environment.update(LD_PRELOAD=str(hook), FORGE_LOADER_EXEC=str(next_image))
    child = subprocess.Popen([str(original)], env=environment, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            if not selector.select(10):
                raise AssertionError("owned target did not reach attach handshake")
            handshake = os.read(child.stdout.fileno(), 19)
        (directory / "handshake.txt").write_bytes(handshake)
        if handshake != b"FORGE_ATTACH_READY\n":
            raise AssertionError(f"bad attach handshake {handshake!r}")
        commands = f"""set pagination off
set confirm off
set debuginfod enabled off
set auto-solib-add off
file {quoted(original)}
attach {child.pid}
handle SIGSTOP nostop noprint nopass
source {companion}
forge-load
python
state = next(iter(gdb._forge_loader_registry_v1.loaded.values()))
assert state['bias'] != 0
assert {str(source)!r} in gdb.execute('info line recovered_add', to_string=True)
assert 'recovered_add' in gdb.execute('list recovered_add', to_string=True)
point = gdb.Breakpoint('recovered_add')
end
catch exec
continue
python
assert gdb.selected_frame().name() == 'recovered_add'
assert int(gdb.parse_and_eval('left')) == 19
assert int(gdb.parse_and_eval('right')) == 23
assert int(gdb.parse_and_eval('fixture_sink')) == 0
end
next
python
assert int(gdb.parse_and_eval('fixture_sink')) == 42
point.delete()
end
continue
python
assert gdb.current_progspace().filename == {str(next_image)!r}
assert not gdb._forge_loader_registry_v1.loaded, 'exec left registered symbols'
assert not any(obj.filename == {str(sidecar)!r} for obj in gdb.objfiles()), 'exec left sidecar objfile'
objects = list(gdb.objfiles())
try:
    gdb.execute('forge-load')
except gdb.error as error:
    assert 'mapping' in str(error) or 'mismatch' in str(error), str(error)
else:
    raise AssertionError('old companion loaded into replacement image')
assert list(gdb.objfiles()) == objects
print('FORGE_ATTACH_EXEC=PASS')
end
continue
"""
        script = directory / "commands.gdb"
        script.write_text(commands)
        result = subprocess.run(["gdb-multiarch", "-nx", "-q", "-batch", "-x", str(script)],
            cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
        (directory / "gdb.txt").write_text(result.stdout)
        if result.returncode and child.poll() is None:
            child.kill()
        stdout, stderr = child.communicate(timeout=10)
        (directory / "target.stdout").write_bytes(stdout)
        (directory / "target.stderr").write_bytes(stderr)
        if (result.returncode or child.returncode or "FORGE_ATTACH_EXEC=PASS" not in result.stdout or
                "Python Exception" in result.stdout or "Traceback" in result.stdout or stderr):
            raise AssertionError(f"attach/exec failed; inspect {directory}")
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)
    for path, digest in before.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise AssertionError(f"changed original/sidecar/source/companion: {path}")
    (directory / "result.json").write_text(json.dumps({"status": "PASS", "pid": child.pid,
        "replacementImage": str(next_image), "preserved": before}, indent=4) + "\n")
    print(f"gdb-companion-attach-exec=PASS {directory}")


if __name__ == "__main__":
    main()
