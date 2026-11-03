"""GDB-side oracle for a real Forge companion on a QEMU user-mode target."""

import hashlib
import json
import os
from pathlib import Path
import subprocess

import gdb


def quoted(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


fixture = os.environ["FORGE_LOADER_FIXTURE"]
result = Path(os.environ["FORGE_LOADER_RESULT"])
original = Path(fixture + ".stripped")
sidecar = Path(fixture + ".ghidra-forge.dbg")
source = Path(str(sidecar) + ".c")
companion = Path(str(sidecar) + ".gdb.py")
before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in (original, sidecar, source, companion)}
with original.open("rb") as stream:
    header = stream.read(64)
assert header[:4] == b"\x7fELF"
bits = {1: 32, 2: 64}[header[4]]
order = {1: "little", 2: "big"}[header[5]]
entry = int.from_bytes(header[24:24 + bits // 8], order)
symbols = subprocess.check_output(["readelf", "-Ws", fixture + ".reference"], text=True)
function_link = {int(line.split()[1], 16) for line in symbols.splitlines()
    if len(line.split()) >= 8 and line.split()[7] == "recovered_add"}
assert len(function_link) == 1
function_link = function_link.pop()
discovery = os.environ["FORGE_LOADER_DISCOVERY"]
commands = ["set pagination off", "set confirm off", "set debuginfod enabled off",
    "set auto-solib-add off", "set sysroot " + os.environ["FORGE_LOADER_SYSROOT"],
    "file " + quoted(original)]
if discovery == "no-hostio":
    # Exercise a real remote connection without remote file access, rather than
    # substituting a fake mapping function in the production loader.
    commands.append("set remote hostio-open-packet off")
commands += ["target remote " + os.environ["FORGE_LOADER_REMOTE"], "source " + str(companion)]
for command in commands:
    gdb.execute(command)
exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))

# AT_ENTRY is the runtime main-program entry, independent of the loader's
# mapping algorithm and the dynamic linker's current PC. No architecture base
# or .text-address heuristic is used to supply this explicit override.
auxv = gdb.execute("info auxv", to_string=True)
(result / "auxv.txt").write_text(auxv)
entries = [int(line.split()[-1], 0) for line in auxv.splitlines() if "AT_ENTRY" in line.split()]
assert len(entries) == 1
bias = entries[0] - entry
assert gdb.lookup_type("void").pointer().sizeof * 8 == bits
objects = list(gdb.objfiles())
automatic = False
try:
    gdb.execute("forge-load")
except gdb.error as error:
    diagnostic = str(error)
    assert "mappings unavailable" in diagnostic, diagnostic
    assert list(gdb.objfiles()) == objects
    (result / "automatic-discovery.txt").write_text(diagnostic + "\n")
else:
    automatic = True
    state = next(iter(gdb._forge_loader_registry_v1.loaded.values()))
    assert state["bias"] == bias
    gdb.execute("forge-unload")
    assert list(gdb.objfiles()) == objects
    (result / "automatic-discovery.txt").write_text("automatic mapping discovery succeeded\n")
if discovery == "no-hostio":
    assert not automatic, "restricted transport unexpectedly provided process mappings"

try:
    gdb.execute("forge-load --bias " + hex(bias + 1))
except gdb.error as error:
    assert any(text in str(error) for text in ("mismatch", "contradicts", "unreadable")), str(error)
else:
    raise AssertionError("wrong explicit bias accepted")
assert list(gdb.objfiles()) == objects
gdb.execute("forge-load --bias " + hex(bias))
assert int(gdb.parse_and_eval("&recovered_add")) == function_link + bias
assert str(source) in gdb.execute("info line recovered_add", to_string=True)
assert "recovered_add" in gdb.execute("list recovered_add", to_string=True)
assert "struct fixture_state" in gdb.execute("ptype struct fixture_state", to_string=True)
loaded_objects = list(gdb.objfiles())
gdb.execute("forge-load --bias " + hex(bias))
assert list(gdb.objfiles()) == loaded_objects
point = gdb.Breakpoint("recovered_add")
gdb.execute("continue")
assert gdb.selected_frame().name() == "recovered_add"
assert int(gdb.parse_and_eval("left")) == 19
assert int(gdb.parse_and_eval("right")) == 23
assert int(gdb.parse_and_eval("fixture_sink")) == 0
assert int(gdb.parse_and_eval("scoped_counter")) == 7
gdb.execute("next")
# ARM's existing source oracle requires another statement transition before
# the global store; allow bounded stepping, while recording every observation.
observations = [int(gdb.parse_and_eval("fixture_sink"))]
if observations[-1] != 42:
    gdb.execute("next")
    observations.append(int(gdb.parse_and_eval("fixture_sink")))
assert observations[-1] == 42, observations
point.delete()
gdb.execute("continue")
assert exits == [0], exits
assert not gdb._forge_loader_registry_v1.loaded
assert not any(obj.filename == str(sidecar) for obj in gdb.objfiles())
for name, digest in before.items():
    assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest, name
(result / "result.json").write_text(json.dumps({"status": "PASS", "bits": bits,
    "order": order, "bias": bias, "entry": entry, "runtimeEntry": entries[0],
    "automaticDiscovery": automatic, "globalObservations": observations,
    "transportProfile": discovery,
    "preserved": before}, indent=4) + "\n")
print("FORGE_REMOTE_COMPANION=PASS")
