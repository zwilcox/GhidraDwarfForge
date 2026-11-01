#!/usr/bin/env python3
"""Verify exact must-analysis local intervals, including unavailable joins and body holes."""

import json
from pathlib import Path
import re
import struct
import subprocess
import sys


artifact, labels_path, target = sys.argv[1:]
labels = json.loads(Path(labels_path).read_text())


def command(*args):
    result = subprocess.run(args, text=True, capture_output=True, check=True, timeout=60)
    assert not result.stderr, result.stderr
    return result.stdout


records = []
for line in command("readelf", "--debug-dump=info", artifact).splitlines():
    header = re.match(r"^\s*<(\d+)><[0-9a-f]+>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?", line)
    if header:
        records.append({"depth": int(header[1]), "tag": header[2], "attrs": {}})
    elif records:
        attribute = re.match(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s+:\s*(.*)", line)
        if attribute:
            records[-1]["attrs"][attribute[1]] = attribute[2]


def name(record):
    return record["attrs"].get("DW_AT_name", "").rsplit(": ", 1)[-1]


offsets = {}
for index, record in enumerate(records):
    if record["tag"] != "DW_TAG_subprogram" or name(record) not in labels:
        continue
    function = name(record)
    assert function not in offsets
    parameters = []
    for child in records[index + 1:]:
        if child["depth"] <= record["depth"]:
            break
        if child["tag"] == "DW_TAG_variable":
            assert child["depth"] == record["depth"] + 1
            parameters.append(child)
    assert len(parameters) == 1 and name(parameters[0]) == "curated_held", parameters
    attrs = parameters[0]["attrs"]
    assert "DW_AT_type" in attrs
    if not labels[function]["available"]:
        assert "DW_AT_location" not in attrs, attrs
        offsets[function] = None
        continue
    location = re.fullmatch(r"(0x[0-9a-f]+) \(location list\)", attrs.get("DW_AT_location", ""))
    assert location, attrs
    offsets[function] = int(location[1], 16)
assert set(offsets) == set(labels), offsets
if all(offset is None for offset in offsets.values()):
    print(json.dumps({"local_definition_flow_locations": "PASS", "unavailable": sorted(offsets)}))
    sys.exit(0)
sections = command("readelf", "-SW", artifact)
section = re.findall(r"^\s*\[\s*\d+\]\s+\.debug_loclists\s+PROGBITS\s+"
    r"[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\b", sections, re.M)
assert len(section) == 1
offset, size = (int(value, 16) for value in section[0])
assert 12 <= size <= 64 * 1024 * 1024
with open(artifact, "rb") as stream:
    assert stream.read(6) == b"\x7fELF\x02\x01", "fixture must be ELF64 little-endian"
    stream.seek(offset)
    data = stream.read(size)
assert len(data) == size
length, version, width, segment, table = struct.unpack_from("<IHBBI", data)
assert (length, version, width, segment, table) == (size - 4, 5, 8, 0, 0)
register = {"x86_64": 10, "aarch64": 9}[target]
checked = {}
for function, start in offsets.items():
    if start is None:
        continue
    actual = []
    cursor = start
    while data[cursor] != 0:
        assert data[cursor] == 7, "expected an absolute DW_LLE_start_end"
        low, high = struct.unpack_from("<QQ", data, cursor + 1)
        cursor += 17
        length = data[cursor]
        assert length in (2, 3), "expected a direct register or register-relative memory expression"
        expression = data[cursor + 1:cursor + 1 + length]
        actual.append((low, high, expression.hex()))
        cursor += 1 + length
    record = labels[function]
    if record.get("allowStorageMigration"):
        coverage = []
        for low, high, encoded in actual:
            expression = bytes.fromhex(encoded)
            if expression[0] == 0x90:
                assert len(expression) == 2 and expression[1] <= (16 if target == "x86_64" else 31)
            else:
                assert expression[0] == 0x92 and expression[1] == (7 if target == "x86_64" else 31)
                assert len(expression) == 3 and expression[2] < 0x80
            if coverage and coverage[-1][1] == low:
                coverage[-1][1] = high
            else:
                coverage.append([low, high])
        assert coverage == record["available"], (function, coverage, record["available"])
        checked[function] = actual
        continue
    expected = [(low, high, bytes([0x90, record.get("dwarfRegister", register)]).hex())
        for low, high in record["available"]]
    assert actual == expected, (function, actual, expected)
    checked[function] = actual
print(json.dumps({"local_definition_flow_locations": "PASS", "functions": checked}, indent=4))
