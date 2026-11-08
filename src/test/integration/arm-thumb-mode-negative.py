#!/usr/bin/env python3
"""Ensure the debugger oracle rejects corrupted instruction-mode metadata."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("case", type=Path)
args = parser.parse_args()
case = args.case.resolve(strict=True)
spec = importlib.util.spec_from_file_location("thumb_check", Path(__file__).with_name("arm-thumb-mode-check.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
labels = json.loads((case / "labels.json").read_text())
reference = json.loads((case / "compiler-calls.json").read_text())
assert reference["status"] == "PASS"
image = helper.elf(case / "thumb.dbg")
table = helper.section(image, ".symtab")
name = "__forge_arm_mode_%08x" % labels["thumb_add"]["code"]
index, = [index for index, symbol in enumerate(image["symbols"]) if symbol["name"] == name]
at = table["row"][4] + 16 * index
root = case / "mode-negative-controls"
root.mkdir(exist_ok=False)
script = root / "check.py"
script.write_text('''import json
from pathlib import Path
import gdb
labels = json.loads(Path(''' + repr(str(case / "labels.json")) + ''').read_text())
expected = json.loads(Path(''' + repr(str(case / "compiler-calls.json")) + ''').read_text())["static"]
actual = {}
for name in expected:
    row = labels[name]
    actual[name] = [{"address": item["addr"], "length": item["length"],
        "mnemonic": item["asm"].split()[0]} for item in
        gdb.selected_inferior().architecture().disassemble(row["code"], row["code"] + row["codeSize"] - 1)]
print("MODE_ORACLE=" + json.dumps({"matches": actual == expected, "actual": actual}))
''')
results = []
variants = ["positive", "clear-thumb-bit", "shift-thumb-entry"]
if labels["thumb_add"]["codeSize"] < labels["thumb_add"]["size"]:
    variants.append("cover-literal-pool")
for variant in variants:
    payload = bytearray(image["data"])
    if variant == "clear-thumb-bit":
        struct.pack_into("<I", payload, at + 4, labels["thumb_add"]["code"])
    elif variant == "shift-thumb-entry":
        struct.pack_into("<I", payload, at + 4, labels["thumb_add"]["raw"] + 4)
    elif variant == "cover-literal-pool":
        struct.pack_into("<I", payload, at + 8, labels["thumb_add"]["size"])
    artifact = root / (variant + ".dbg")
    artifact.write_bytes(payload)
    command = ["gdb-multiarch", "-q", "-nx", "-batch", "-ex", "set debuginfod enabled off",
        "-ex", "set auto-solib-add off", "-ex", "file " + str(case / "thumb.stripped"),
        "-ex", "symbol-file " + str(artifact), "-x", str(script)]
    (root / (variant + ".command.json")).write_text(json.dumps(command, indent=4) + "\n")
    run = subprocess.run(command, capture_output=True, timeout=30)
    (root / (variant + ".stdout")).write_bytes(run.stdout)
    (root / (variant + ".stderr")).write_bytes(run.stderr)
    assert run.returncode == 0 and not run.stderr, (variant, run.stderr)
    row, = [json.loads(line.split("MODE_ORACLE=", 1)[1]) for line in run.stdout.decode().splitlines()
        if line.startswith("MODE_ORACLE=")]
    extent_matches = struct.unpack_from("<I", payload, at + 8)[0] == labels["thumb_add"]["codeSize"]
    assert (row["matches"] and extent_matches) == (variant == "positive"), (variant, row)
    results.append({"variant": variant, "matchesCompilerInstructions": row["matches"],
        "matchesProvenExtent": extent_matches})
(root / "result.json").write_text(json.dumps({"status": "PASS", "cases": results}, indent=4) + "\n")
print("arm-thumb-mode-negative=PASS " + str(root))
