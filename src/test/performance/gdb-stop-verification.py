#!/usr/bin/env python3
"""Measure the strict loader's executable-byte check per step on Linux x86-64.

Run with Python 3, GNU as/ld/readelf, GDB with Python support, and qemu-x86_64.
The script builds a disposable 64 MiB executable and prints JSON for native and
emulated stepping. Each verified stop must read all 1,024 64 KiB chunks. Times
are medians over three trials and depend on the host and debugger transport.
"""
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time

LOADER = Path(__file__).resolve().parents[2] / "main/resources/ghidradwarfforge/gdb/loader.py"
SIZE = 64 * 1024 * 1024
TRIALS = 3

# Time real GDB stops and count inferior.read_memory calls in the production verifier.
GDB_SCRIPT = """
set confirm off
set pagination off
set auto-load off
set debuginfod enabled off
file image
{start}
python
import gdb, json, os, runpy, time
verify = runpy.run_path(os.environ["FORGE_LOADER"])["verify_memory"]
manifest = json.loads(os.environ["FORGE_PROBES"])
measurements = []
def verify_stop(event):
    reads = 0
    def read_memory(address, size):
        nonlocal reads
        reads += 1
        return gdb.selected_inferior().read_memory(address, size)
    started = time.perf_counter()
    verify(manifest, 0, read_memory)
    measurements.append((reads, time.perf_counter() - started))
def step():
    started = time.perf_counter()
    gdb.execute("stepi", to_string=True)
    return time.perf_counter() - started
baseline = [step() for _ in range({trials})]
gdb.events.stop.connect(verify_stop)
verified = [step() for _ in range({trials})]
gdb.events.stop.disconnect(verify_stop)
print("FORGE_BENCH=" + json.dumps([baseline, verified, measurements]))
end
quit
"""


def run_gdb(work, start, manifest):
    (work / "bench.gdb").write_text(GDB_SCRIPT.format(start=start, trials=TRIALS))
    result = subprocess.run(["gdb", "-nx", "-q", "-batch", "-x", "bench.gdb"], cwd=work,
        env={**os.environ, "FORGE_LOADER": str(LOADER), "FORGE_PROBES": json.dumps(manifest)},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=240)
    records = [line.removeprefix("FORGE_BENCH=") for line in result.stdout.splitlines()
               if line.startswith("FORGE_BENCH=")]
    if result.returncode or len(records) != 1:
        raise RuntimeError(result.stdout)
    baseline, verified, samples = json.loads(records[0])
    assert len(samples) == TRIALS and all(reads == SIZE // 65536 for reads, _ in samples), samples
    return {"trials": TRIALS, "bytesPerStop": SIZE, "readsPerStop": samples[0][0],
            "baselineStepSeconds": statistics.median(baseline), "verifiedStepSeconds": statistics.median(verified),
            "verificationSeconds": statistics.median(duration for _, duration in samples)}


def main():
    with tempfile.TemporaryDirectory(prefix="forge-gdb-stop-") as temporary:
        work = Path(temporary)
        assembly = f".text\n.globl _start\n_start:\n.fill {SIZE},1,0x90\n"
        subprocess.run(["as", "--64", "-o", "image.o"], cwd=work, text=True, input=assembly, check=True)
        subprocess.run(["ld", "-m", "elf_x86_64", "-Ttext=0x401000", "-e", "_start", "-o", "image", "image.o"],
            cwd=work, check=True)
        load = subprocess.check_output(["readelf", "-lW", "image"], cwd=work, text=True)
        segment, = [line.split() for line in load.splitlines() if line.lstrip().startswith("LOAD") and " E " in line]
        offset, address, size = (int(segment[i], 16) for i in (1, 2, 4))
        assert address == 0x401000 and size == SIZE
        with (work / "image").open("rb") as image:
            image.seek(offset)
            digest = hashlib.sha256(image.read(size)).hexdigest()
        manifest = {"address_bits": 64, "segments": [[offset, address, size, size]],
                    "checks": [{"size": size, "address": address, "sha256": digest}]}
        print("native " + json.dumps(run_gdb(work, "starti", manifest)), flush=True)
        with subprocess.Popen(["qemu-x86_64-static", "-g", "gdb.socket", "./image"], cwd=work) as emulator:
            try:
                deadline = time.monotonic() + 10
                while not (work / "gdb.socket").is_socket():
                    if emulator.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("QEMU debugger socket did not become ready")
                    time.sleep(0.02)
                print("qemu-unix " + json.dumps(run_gdb(work, "target remote ./gdb.socket", manifest)), flush=True)
            finally:
                if emulator.poll() is None:
                    emulator.kill()
                emulator.wait()


if __name__ == "__main__":
    main()
