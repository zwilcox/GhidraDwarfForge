"""GDB-side real Forge library oracle using dlinfo evidence from the target."""

import hashlib
import json
import os
from pathlib import Path
import subprocess

import gdb


def quoted(path):
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def symbols(path):
    text = subprocess.check_output(["readelf", "-Ws", str(path)], text=True)
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[0].endswith(":") and fields[0][:-1].isdigit() and fields[6] != "UND":
            result[fields[7]] = int(fields[1], 16)
    return result


fixture = Path(os.environ["FORGE_SHARED_FIXTURE"])
result = Path(os.environ["FORGE_SHARED_RESULT"])
ambiguous = os.environ["FORGE_SHARED_MODE"] == "ambiguous"
restricted = os.environ["FORGE_SHARED_TRANSPORT"] == "no-hostio"
remote = os.environ["FORGE_SHARED_REMOTE"]
driver = fixture / "semantic.loader-driver.stripped"
original = fixture / "libsemantic.so.stripped"
sidecar = fixture / "libsemantic.so.ghidra-forge.dbg"
source = Path(str(sidecar) + ".c")
companion = Path(str(sidecar) + ".gdb.py")
before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in (driver, original, sidecar, source, companion)}
driver_symbols = symbols(fixture / "semantic.loader-driver.reference")
library_symbols = symbols(fixture / "libsemantic.so.reference")
with driver.open("rb") as stream:
    header = stream.read(64)
width = {1: 4, 2: 8}[header[4]]
order = {1: "little", 2: "big"}[header[5]]
entry = int.from_bytes(header[24:24 + width], order)
for command in ("set pagination off", "set confirm off", "set debuginfod enabled off",
        "set auto-solib-add off", "set disable-randomization off",
        "set sysroot " + os.environ["FORGE_SHARED_SYSROOT"],
        "set solib-search-path " + str(fixture), "file " + quoted(driver)):
    gdb.execute(command)
if restricted:
    assert remote, "restricted file transport is a remote test"
    gdb.execute("set remote hostio-open-packet off")
if remote:
    gdb.execute("target remote " + remote)
else:
    gdb.execute("set args " + quoted(original) + " " + ("ambiguous" if ambiguous else "normal"))
    gdb.execute("starti")
auxv = gdb.execute("info auxv", to_string=True)
(result / "auxv.txt").write_text(auxv)
runtime_entry, = [int(line.split()[-1], 0) for line in auxv.splitlines() if "AT_ENTRY" in line.split()]
driver_bias = runtime_entry - entry
gdb.execute("source " + str(companion))
exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))


def marker(name):
    return driver_bias + driver_symbols[name]


points = [gdb.Breakpoint("*" + hex(marker(name))) for name in
    ("fixture_after_load", "fixture_select_other", "fixture_after_unload")]
observations = []
for iteration in range(2):
    gdb.execute("continue")
    assert int(gdb.parse_and_eval("$pc")) == marker("fixture_after_load")
    inferior = gdb.selected_inferior()
    bias = int.from_bytes(bytes(inferior.read_memory(marker("fixture_loader_bias"), width)), order)
    other = int.from_bytes(bytes(inferior.read_memory(marker("fixture_loader_other_bias"), width)), order)
    assert bias != 0 and (not ambiguous or other != bias and other != 0)
    old_objects = list(gdb.objfiles())
    try:
        gdb.execute("forge-load")
    except gdb.error as error:
        diagnostic = str(error)
        assert ("mappings unavailable" in diagnostic or ambiguous and "ambiguous" in diagnostic), diagnostic
        assert list(gdb.objfiles()) == old_objects
        automatic = False
    else:
        assert not ambiguous and not restricted, "ambiguous/unavailable discovery silently selected a module"
        assert next(iter(gdb._forge_loader_registry_v1.loaded.values()))["bias"] == bias
        automatic = True
    gdb.execute("forge-load --bias " + hex(bias))
    rounds = [(bias, 19, 23)] + ([(other, -19, 42)] if ambiguous else [])
    for position, (selected_bias, left, right) in enumerate(rounds):
        if position:
            gdb.execute("continue")
            assert int(gdb.parse_and_eval("$pc")) == marker("fixture_select_other")
            gdb.execute("forge-load --bias " + hex(selected_bias))
        assert int(gdb.parse_and_eval("&recovered_add")) == library_symbols["recovered_add"] + selected_bias
        assert int(gdb.parse_and_eval("&fixture_sink")) == library_symbols["fixture_sink"] + selected_bias
        assert "recovered_add" in gdb.execute("list recovered_add", to_string=True)
        assert gdb.decode_line("recovered_add")[1][0].symtab.objfile.filename == str(sidecar)
        point = gdb.Breakpoint("recovered_add")
        gdb.execute("continue")
        assert gdb.selected_frame().name() == "recovered_add"
        assert int(gdb.parse_and_eval("left")) == left
        assert int(gdb.parse_and_eval("right")) == right
        assert int(gdb.parse_and_eval("fixture_sink")) == 0
        assert int(gdb.parse_and_eval("scoped_counter")) == 7
        gdb.execute("next")
        values = [int(gdb.parse_and_eval("fixture_sink"))]
        if values[-1] != left + right:
            gdb.execute("next")
            values.append(int(gdb.parse_and_eval("fixture_sink")))
        assert values[-1] == left + right, values
        point.delete()
        observations.append({"iteration": iteration, "bias": selected_bias,
            "left": left, "right": right, "values": values, "automatic": automatic})
    gdb.execute("continue")
    assert int(gdb.parse_and_eval("$pc")) == marker("fixture_after_unload")
    assert not gdb._forge_loader_registry_v1.loaded
    assert not any(obj.filename == str(sidecar) for obj in gdb.objfiles())
gdb.execute("continue")
assert exits == [0], exits
for path, digest in before.items():
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest, path
(result / "result.json").write_text(json.dumps({"status": "PASS", "bits": width * 8,
    "order": order, "ambiguous": ambiguous, "restrictedTransport": restricted,
    "observations": observations, "preserved": before}, indent=4) + "\n")
print("FORGE_SHARED_COMPANION=PASS")
