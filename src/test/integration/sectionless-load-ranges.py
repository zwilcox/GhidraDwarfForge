#!/usr/bin/env python3
"""Check synthesized load metadata and reject corrupted real location-list copies."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Elf:
    """Independent bounded parser for small integration fixtures, not a product reader."""

    def __init__(self, data):
        self.data = data
        require(52 <= len(data) <= 64 * 1024 * 1024, "fixture size outside test bounds")
        require(data[:4] == b"\x7fELF" and data[4] in (1, 2) and data[5] in (1, 2),
            "fixture must be ELF32/64 with a known byte order")
        self.wide = data[4] == 2
        self.order = "<" if data[5] == 1 else ">"
        self.word = "Q" if self.wide else "I"
        self.header_size = 64 if self.wide else 52
        require(len(data) >= self.header_size, "truncated ELF header")
        self.phoff = self.unpack(self.word, 32 if self.wide else 28)[0]
        self.shoff = self.unpack(self.word, 40 if self.wide else 32)[0]
        self.flags = self.unpack("I", 48 if self.wide else 36)[0]
        ehsize, self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx = \
            self.unpack("6H", 52 if self.wide else 40)
        require(ehsize == self.header_size, "unexpected fixture ELF header size")
        self.identity = (data[:16], self.unpack("HHI", 16),
            self.unpack(self.word, 24)[0], self.flags)

    def unpack(self, fmt, offset):
        size = struct.calcsize(self.order + fmt)
        require(0 <= offset <= len(self.data) - size, "truncated fixture metadata")
        return struct.unpack_from(self.order + fmt, self.data, offset)

    def loads(self):
        require(0 < self.phnum < 0xffff and
            self.phentsize >= (56 if self.wide else 32), "ordinary program headers required")
        result = {}
        for index in range(self.phnum):
            at = self.phoff + index * self.phentsize
            if self.wide:
                kind, flags, offset, address, _, filesz, memsz, _ = self.unpack("II6Q", at)
            else:
                kind, offset, address, _, filesz, memsz, flags, _ = self.unpack("8I", at)
            if kind == 1 and memsz:
                require(filesz <= memsz and offset <= len(self.data) - filesz and
                    address + memsz <= 1 << (64 if self.wide else 32), "invalid load extent")
                result[index] = {"offset": offset, "address": address, "filesz": filesz,
                    "memsz": memsz, "flags": flags}
        require(result and any(load["flags"] & 1 for load in result.values()),
            "fixture needs a nonempty executable PT_LOAD")
        return result

    def sections(self):
        require(self.shoff > 0 and 0 < self.shnum < 0xff00 and
            0 < self.shstrndx < self.shnum and
            self.shentsize >= (64 if self.wide else 40), "ordinary named sections required")
        fmt = "II4QII2Q" if self.wide else "10I"
        rows = [self.unpack(fmt, self.shoff + index * self.shentsize)
            for index in range(self.shnum)]
        names = self.payload(rows[self.shstrndx])
        result = {}
        for index, row in enumerate(rows):
            require(row[0] < len(names), "invalid section name offset")
            end = names.find(b"\0", row[0])
            require(end >= 0, "unterminated section name")
            name = names[row[0]:end].decode("ascii")
            require(name not in result, "duplicate section name: " + name)
            result[name] = (index, row)
        return result

    def payload(self, row):
        offset, size = row[4:6]
        require(offset <= len(self.data) - size, "truncated section payload")
        return self.data[offset:offset + size]


def check_load_metadata(original, sidecar):
    require((original.shoff, original.shnum, original.shstrndx) == (0, 0, 0),
        "original fixture must have no section table")
    require(original.identity == sidecar.identity, "target identity changed")
    require((sidecar.phoff, sidecar.phentsize, sidecar.phnum) == (0, 0, 0),
        "sidecar must not have a program-header table")
    require(sidecar.data[original.header_size:len(original.data)] ==
        original.data[original.header_size:], "original bytes after the ELF header changed")
    loads = original.loads()
    sections = sidecar.sections()
    actual = {name for name in sections if name.startswith(".forge.load.")}
    require(actual == {".forge.load." + str(index) for index in loads},
        "synthesized load section inventory does not match original PT_LOADs")
    for index, load in loads.items():
        row = sections[".forge.load." + str(index)][1]
        flags = 2 | (1 if load["flags"] & 2 else 0) | (4 if load["flags"] & 1 else 0)
        require(row[1:] == (8, flags, load["address"], load["offset"], load["memsz"],
            0, 0, 1, 0), "synthesized load section differs from original PT_LOAD " + str(index))
    return loads, sections


def location_entries(elf, row, loads):
    payload = elf.payload(row)
    width = 8 if elf.wide else 4
    require(len(payload) >= 12 and elf.unpack("I", row[4])[0] == len(payload) - 4 and
        elf.unpack("H", row[4] + 4)[0] == 5 and payload[6:8] == bytes([width, 0]) and
        elf.unpack("I", row[4] + 8)[0] == 0, "expected direct Forge DWARF5 location lists")
    cursor = 12
    entries = []
    lists = 0
    count = 0
    while cursor < len(payload):
        opcode = payload[cursor]
        cursor += 1
        if opcode == 0:
            require(count > 0, "empty location list")
            lists += 1
            count = 0
            continue
        require(opcode == 7, "unsupported fixture location-list opcode")
        absolute = row[4] + cursor
        low, high = elf.unpack(elf.word * 2, absolute)
        require(low < high and any(load["flags"] & 1 and load["address"] <= low and
            high <= load["address"] + load["memsz"] for load in loads.values()),
            "location interval outside original executable PT_LOAD")
        entries.append(absolute)
        count += 1
        cursor += 2 * width
        length = 0
        for shift in range(0, 70, 7):
            require(cursor < len(payload), "truncated expression length")
            byte = payload[cursor]
            cursor += 1
            length |= (byte & 127) << shift
            if byte < 128:
                break
        else:
            raise AssertionError("oversized expression length")
        require(length > 0 and length <= len(payload) - cursor, "truncated location expression")
        cursor += length
    require(entries and lists > 0 and count == 0, "missing final location-list terminator")
    return entries, lists


def run(command, log):
    result = subprocess.run([str(value) for value in command], capture_output=True, text=True)
    log.write_text(result.stdout + result.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("sidecar", type=Path)
    parser.add_argument("--tool", default=os.environ.get("DWARFDUMP", "dwarfdump"))
    args = parser.parse_args()
    original_path = args.original.resolve(strict=True)
    sidecar_path = args.sidecar.resolve(strict=True)
    require(original_path != sidecar_path, "original and sidecar must be distinct")
    require(max(original_path.stat().st_size, sidecar_path.stat().st_size) <= 64 * 1024 * 1024,
        "fixture exceeds test size bound")
    original = Elf(original_path.read_bytes())
    sidecar = Elf(sidecar_path.read_bytes())
    root = Path(__file__).resolve().parents[3]
    results = root / "build/test-results/sectionless-load-ranges"
    results.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run.", dir=results))
    print("sectionless-load-range-results=" + str(work), flush=True)
    loads, sections = check_load_metadata(original, sidecar)
    entries, lists = location_entries(sidecar, sections[".debug_loclists"][1], loads)
    helper = root / "src/test/integration/check-dwarfdump.py"

    def check(path, label):
        log = work / (label + ".dwarfdump.txt")
        result = run([sys.executable, helper, path, log, "--tool", args.tool,
            "--original", original_path], work / (label + ".runner.txt"))
        metadata = json.loads(log.with_name(log.name + ".check.json").read_text())
        return result.returncode, metadata, log.read_text()

    status, metadata, _ = check(sidecar_path, "positive")
    require(status == 0 and metadata["status"] == "PASS", "positive strict validator failed")
    llvm = run(["llvm-dwarfdump", "--verify", sidecar_path], work / "positive.llvm.txt")
    require(llvm.returncode == 0 and not llvm.stderr and "No errors." in llvm.stdout,
        "positive LLVM verification failed")

    # Corrupt a copy beyond every original mapping, not merely beyond one function.
    outside = max(load["address"] + load["memsz"] for load in loads.values()) + 0x10000
    require(outside + 0x10 < 1 << (64 if sidecar.wide else 32), "no room for negative address")
    corrupted = bytearray(sidecar.data)
    struct.pack_into(sidecar.order + sidecar.word * 2, corrupted, entries[0], outside, outside + 0x10)
    bad = work / "outside-load-location.dbg"
    bad.write_bytes(corrupted)
    status, negative_metadata, text = check(bad, "outside-load-location")
    diagnostic = re.compile(r"^\*\*\* DWARF CHECK: \.debug_loc\[lists\]: Address outside a "
        r"valid \.text range:.* final lowpc 0x([0-9a-f]+)\s+final hipc 0x([0-9a-f]+)", re.MULTILINE)
    endpoints = [(int(low, 16), int(high, 16)) for low, high in diagnostic.findall(text)]
    require(status != 0 and negative_metadata["status"] == "FAILED" and
        negative_metadata["exit_status"] == 0 and
        Path(negative_metadata["stderr_log"]).stat().st_size == 0 and
        negative_metadata["failure"] == "checker reported a diagnostic" and
        (outside, outside + 0x10) in endpoints, "strict checker missed corrupted location interval")

    inflated = bytearray(sidecar.data)
    section_index = sections[".forge.load." + str(next(iter(loads)))][0]
    size_offset = sidecar.shoff + section_index * sidecar.shentsize + (32 if sidecar.wide else 20)
    struct.pack_into(sidecar.order + sidecar.word, inflated, size_offset, outside + 0x100)
    (work / "inflated-load-section.dbg").write_bytes(inflated)
    try:
        check_load_metadata(original, Elf(inflated))
    except AssertionError as failure:
        require("differs from original PT_LOAD" in str(failure), "wrong metadata negative failure")
    else:
        raise AssertionError("independent map oracle accepted an inflated load section")

    hashes = {}
    for path, expected in ((original_path, original.data), (sidecar_path, sidecar.data)):
        require(path.read_bytes() == expected, "input changed: " + str(path))
        hashes[str(path)] = hashlib.sha256(expected).hexdigest()
    summary = {"loads": loads, "location_lists": lists, "location_intervals": len(entries),
        "outside_interval": [outside, outside + 0x10], "positive": metadata,
        "negative_location": negative_metadata, "inflated_metadata_rejected": True, "hashes": hashes}
    (work / "summary.json").write_text(json.dumps(summary, indent=4) + "\n")
    (work / "result.txt").write_text("sectionless-load-ranges=PASS\n")
    print("sectionless-load-ranges=PASS")


if __name__ == "__main__":
    main()
