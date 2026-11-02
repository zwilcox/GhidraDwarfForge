#!/usr/bin/env python3
"""Bind actual lane types and raw DWARF expressions to the SIMD runtime oracle."""
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

spec = importlib.util.spec_from_file_location(
    "abi", Path(__file__).with_name("aarch64-abi-locations.py")
)
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)
helper, leb = abi.helper, abi.leb


def main(case, failed=None):
    artifact = case / "abi.dbg"
    result = subprocess.run(
        ["readelf", "-SW", "--debug-dump=info", artifact],
        text=True,
        capture_output=True,
        check=True,
    )
    assert not result.stderr
    records = helper.parse_dies(result.stdout)
    nodes = {row["offset"]: row for row in records}
    (section,) = re.findall(
        r"^\s*\[\s*\d+\]\s+\.debug_loclists\s+PROGBITS\s+"
        r"[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\b",
        result.stdout,
        re.M,
    )
    offset, size = (int(value, 16) for value in section)
    data = artifact.read_bytes()[offset : offset + size]
    assert struct.unpack_from("<IHBBI", data) == (size - 4, 5, 8, 0, 0)
    symbols = json.loads((case / "metadata.json").read_text())["symbols"]
    assert failed is None or failed == "vector_stack"
    locations = {}
    failed_range = None

    def dtype(row):
        return nodes[int(re.search(r"<0x([0-9a-f]+)>", row["attributes"]["DW_AT_type"])[1], 16)]

    for index, row in enumerate(records):
        name = helper.text_value(row["attributes"].get("DW_AT_name", ""))
        if row["tag"] != "DW_TAG_subprogram" or name not in symbols:
            continue
        low = helper.number(row["attributes"]["DW_AT_low_pc"])
        high = low + helper.number(row["attributes"]["DW_AT_high_pc"])
        assert low == symbols[name] and name not in locations
        children = []
        for child in records[index + 1 :]:
            if child["depth"] <= row["depth"]:
                break
            children.append(child)
        if name == failed:
            assert all(child["tag"] is None for child in children)
            assert (
                not {"DW_AT_type", "DW_AT_decl_file", "DW_AT_decl_line"} & row["attributes"].keys()
            )
            failed_range = (low, high)
            continue
        assert helper.number(row["attributes"]["DW_AT_calling_convention"]) == 3
        (parameter,) = [
            child
            for child in children
            if child["tag"] == "DW_TAG_formal_parameter"
            and helper.text_value(child["attributes"].get("DW_AT_name", "")) == "value"
        ]
        assert parameter["attributes"]["DW_AT_type"] == row["attributes"]["DW_AT_type"]
        alias = dtype(parameter)
        assert alias["tag"] == "DW_TAG_typedef"
        array = dtype(alias)
        assert array["tag"] == "DW_TAG_array_type" and "DW_AT_GNU_vector" not in array["attributes"]
        element = dtype(array)
        assert (
            element["tag"] == "DW_TAG_base_type"
            and helper.number(element["attributes"]["DW_AT_byte_size"]) == 4
        )
        assert helper.number(element["attributes"]["DW_AT_encoding"]) == (
            4 if name == "vector_float" else 5
        )
        bounds = []
        for child in records[records.index(array) + 1 :]:
            if child["depth"] <= array["depth"]:
                break
            if child["tag"] == "DW_TAG_subrange_type":
                bounds.append(child)
        (child,) = bounds
        assert (
            helper.number(child["attributes"].get("DW_AT_count", "0")) == 4
            or helper.number(child["attributes"].get("DW_AT_upper_bound", "0")) == 3
        )
        text = parameter["attributes"]["DW_AT_location"]
        match = re.search(r"(0x[0-9a-f]+) \(location list\)$", text)
        expressions = []
        if match:
            cursor = int(match[1], 16)
            while data[cursor]:
                assert data[cursor] == 7
                start, end = struct.unpack_from("<QQ", data, cursor + 1)
                length, cursor = leb(data, cursor + 17)
                expressions.append((start, end, data[cursor : cursor + length]))
                cursor += length
        else:
            block = re.search(r"(\d+) byte block: ([0-9a-f ]+)\s+\(DW_OP_", text)
            assert block and name == "vector_stack_arg", (name, text)
            expression = bytes(int(value, 16) for value in block[2].split())
            assert len(expression) == int(block[1])
            expressions.append((low, high, expression))
        intervals = []
        for start, end, expression in expressions:
            op = expression[0]
            assert op in (0x90, 0x92), expression.hex()
            register, position = leb(expression, 1)
            displacement = 0
            if op == 0x92:
                displacement, position = leb(expression, position, signed=True)
                assert register == 31
            else:
                assert 64 <= register <= 95
            assert position == len(expression) and low <= start < end <= high
            assert (start - low) % 4 == (end - low) % 4 == 0
            assert not intervals or intervals[-1]["end"] <= start - low
            intervals.append(
                {
                    "start": start - low,
                    "end": end - low,
                    "register": register,
                    "kind": "memory" if op == 0x92 else "register",
                    "displacement": displacement,
                    "bytes": expression.hex(),
                }
            )
        assert intervals and intervals[0]["start"] == 0
        locations[name] = {"size": high - low, "intervals": intervals}
    assert set(locations) == set(symbols) - ({failed} if failed else set())
    if failed:
        assert failed_range
        cursor = 12
        while cursor < len(data):
            if data[cursor] == 0:
                cursor += 1
                continue
            assert data[cursor] == 7
            start, end = struct.unpack_from("<QQ", data, cursor + 1)
            assert end <= failed_range[0] or start >= failed_range[1]
            length, cursor = leb(data, cursor + 17)
            cursor += length
        assert cursor == len(data)
    (case / "vector-locations.json").write_text(json.dumps(locations, indent=4) + "\n")
    print("aarch64-vector-locations=PASS functions=" + str(len(locations)))


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) == 3 else None)
