#!/usr/bin/env python3
"""Compare Forge's address index with independently decoded subprogram coverage."""

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(*arguments):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=120)
    require(result.returncode == 0 and not result.stderr, str(arguments) + result.stderr)
    require(not re.search(r"\b(?:warning|error):", result.stdout, re.I), result.stdout)
    return result.stdout


def coverage(path):
    text = command("llvm-dwarfdump", "--debug-info", str(path))
    return coverage_text(text)


def coverage_text(text):
    units = re.findall(r"^0x([0-9a-f]+): Compile Unit:.*addr_size = 0x([0-9a-f]+)",
        text, re.M)
    require(len(units) == 1 and int(units[0][0], 16) == 0, "expected one CU at header offset zero")
    width = int(units[0][1], 16)
    intervals = []
    functions = 0
    blocks = re.split(r"(?m)(?=^0x[0-9a-f]+:\s+(?:DW_TAG_|NULL))", text)
    for block in blocks:
        if not re.match(r"^0x[0-9a-f]+:\s+DW_TAG_subprogram\b", block):
            continue
        declarations = re.findall(r"^\s+DW_AT_declaration\s+\(([^)]+)\)", block, re.M)
        require(len(declarations) <= 1, "duplicate declaration flag")
        if declarations:
            flag = declarations[0]
            require(flag in ("0x00", "0x01", "false", "true"), "invalid declaration flag")
            if flag in ("0x01", "true"):
                require(not re.search(r"^\s+DW_AT_(?:low_pc|high_pc|ranges|entry_pc|frame_base|location)\b",
                    block, re.M), "function declaration carries executable address/location")
                continue
        functions += 1
        low = re.findall(r"^\s+DW_AT_low_pc\s+\((0x[0-9a-f]+)\)", block, re.M)
        high = re.findall(r"^\s+DW_AT_high_pc\s+\((0x[0-9a-f]+)\)", block, re.M)
        ranges = re.findall(r"^\s*\[(0x[0-9a-f]+),\s*(0x[0-9a-f]+)\)", block, re.M)
        if re.search(r"^\s+DW_AT_ranges\s+\(", block, re.M):
            require(ranges and not low and not high, "ambiguous or undecoded function ranges")
            intervals.extend((int(start, 16), int(end, 16)) for start, end in ranges)
        else:
            require(len(low) == len(high) == 1 and not ranges, "missing function bounds")
            # LLVM resolves constant-class high_pc to the absolute exclusive end.
            intervals.append((int(low[0], 16), int(high[0], 16)))
    require(functions > 0 and width in (4, 8), "missing functions or unsupported target width")
    merged = []
    for start, end in sorted(intervals):
        require(0 <= start < end <= 1 << (width * 8), "invalid function interval")
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return width, functions, merged


def declaration_controls():
    definition = ("0x00000000: Compile Unit: addr_size = 0x08\n"
        "0x00000020: DW_TAG_subprogram\n"
        "  DW_AT_low_pc (0x1000)\n  DW_AT_high_pc (0x1010)\n")
    declaration = "0x00000040: DW_TAG_subprogram\n  DW_AT_declaration (0x01)\n"
    expected = (8, 1, [(0x1000, 0x1010)])
    require(coverage_text(definition + declaration) == expected, "addressless declaration changes coverage")
    invalid = [declaration + "  DW_AT_" + name + " (0x1000)\n"
        for name in ("low_pc", "high_pc", "ranges", "entry_pc", "frame_base", "location")]
    invalid += [declaration.replace("0x01", "0x00"), declaration.replace("  DW_AT_declaration (0x01)\n", "")]
    for candidate in invalid:
        try:
            coverage_text(definition + candidate)
        except ValueError:
            continue
        raise ValueError("invalid function declaration/definition was accepted")
    return len(invalid)


def payload(path):
    sections = command("readelf", "-SW", str(path))
    rows = re.findall(r"^\s*\[\s*\d+\]\s+\.debug_aranges\s+PROGBITS\s+"
        r"[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\b", sections, re.M)
    require(len(rows) == 1, "expected exactly one PROGBITS .debug_aranges")
    offset, length = (int(item, 16) for item in rows[0])
    require(0 < length <= 64 * 1024 * 1024, "invalid or oversized address index")
    with path.open("rb") as stream:
        header = stream.read(16)
        require(header[:4] == b"\x7fELF" and header[4] in (1, 2) and header[5] in (1, 2),
            "invalid ELF identity")
        stream.seek(offset)
        data = stream.read(length)
    require(len(data) == length, "truncated address index")
    return data, 4 if header[4] == 1 else 8, "<" if header[5] == 1 else ">"


def verify(data, width, order, expected):
    require(len(data) >= 12, "truncated header")
    length, version, unit, address_size, segment = struct.unpack_from(order + "IHI2B", data)
    require(length == len(data) - 4 and length < 0xfffffff0, "invalid DWARF32 unit length")
    require(version == 2 and unit == 0, "incorrect aranges version or CU header offset")
    require(address_size == width and segment == 0, "incorrect address/segment size")
    tuple_size = 2 * width
    start = ((12 + tuple_size - 1) // tuple_size) * tuple_size
    require(not any(data[12:start]), "nonzero alignment padding")
    require(len(data) >= start + tuple_size and (len(data) - start) % tuple_size == 0,
        "truncated or misaligned tuple sequence")
    fmt = order + ("II" if width == 4 else "QQ")
    entries = list(struct.iter_unpack(fmt, data[start:]))
    require(entries[-1] == (0, 0), "missing final terminator")
    actual = []
    for address, size in entries[:-1]:
        require(size > 0 and address + size <= 1 << (width * 8), "empty or overflowing range")
        require(not actual or address >= actual[-1][1], "unsorted or overlapping index tuples")
        if actual and address == actual[-1][1]:
            actual[-1] = (actual[-1][0], address + size)
        else:
            actual.append((address, address + size))
    require(actual == expected, "address index differs from exact subprogram union")


def negative_controls(data, width, order, expected):
    changes = []
    for offset, fmt, value in ((0, "I", len(data)), (4, "H", 5), (6, "I", 12),
            (10, "B", 8 if width == 4 else 4), (11, "B", 1), (12, "B", 1)):
        mutated = bytearray(data)
        struct.pack_into(order + fmt, mutated, offset, value)
        changes.append(bytes(mutated))
    changes.append(data[:-1])
    tuple_size = width * 2
    start = ((12 + tuple_size - 1) // tuple_size) * tuple_size
    for offset in (start, len(data) - tuple_size):
        mutated = bytearray(data)
        mutated[offset] ^= 1
        changes.append(bytes(mutated))
    # A validly encoded extra interval is still wrong if no function covers it.
    maximum = (1 << (width * 8)) - 1
    fmt = order + ("II" if width == 4 else "QQ")
    mutated = bytearray(data[:-tuple_size] + struct.pack(fmt, maximum, 1) + data[-tuple_size:])
    struct.pack_into(order + "I", mutated, 0, len(mutated) - 4)
    changes.append(bytes(mutated))
    for index, mutated in enumerate(changes):
        try:
            verify(mutated, width, order, expected)
        except ValueError:
            continue
        raise ValueError("invalid address-index control was accepted: " + str(index))
    return len(changes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--negative-controls", action="store_true")
    arguments = parser.parse_args()
    width, functions, expected = coverage(arguments.artifact)
    data, elf_width, order = payload(arguments.artifact)
    require(width == elf_width, "CU and ELF disagree on target width")
    verify(data, width, order, expected)
    rejected = negative_controls(data, width, order, expected) if arguments.negative_controls else 0
    declaration_rejected = declaration_controls() if arguments.negative_controls else 0
    print(json.dumps({"code_address_index": "PASS", "functions": functions,
        "ranges": expected, "address_bytes": width, "byte_order": order,
        "negative_controls_rejected": rejected,
        "declaration_controls_rejected": declaration_rejected}, indent=4))


if __name__ == "__main__":
    main()
