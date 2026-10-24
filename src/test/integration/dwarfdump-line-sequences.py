#!/usr/bin/env python3
"""Exercise standalone checker line-sequence rules with source-built ELF copies."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(command, log):
    result = subprocess.run([str(value) for value in command], capture_output=True, text=True)
    log.write_text(result.stdout + result.stderr)
    return result


def section_layout(path, wanted):
    data = path.read_bytes()
    require(data[:4] == b"\x7fELF" and data[4] in (1, 2) and data[5] in (1, 2),
        "fixture must be ELF")
    order = "<" if data[5] == 1 else ">"
    elf64 = data[4] == 2
    word = "Q" if elf64 else "I"
    offset = struct.unpack_from(order + word, data, 40 if elf64 else 32)[0]
    size, count, names_index = struct.unpack_from(order + "HHH", data, 58 if elf64 else 46)
    require(0 < count < 0xff00 and 0 < names_index < count, "fixture requires ordinary section counts")
    payload_field = 24 if elf64 else 16
    names_offset, names_size = struct.unpack_from(order + word * 2, data,
        offset + names_index * size + payload_field)
    names = data[names_offset:names_offset + names_size]
    for index in range(count):
        header = offset + index * size
        name_offset = struct.unpack_from(order + "I", data, header)[0]
        name = names[name_offset:names.index(0, name_offset)].decode()
        if name == wanted:
            begin, length = struct.unpack_from(order + word * 2, data, header + payload_field)
            return data, begin, length, order
    raise AssertionError("missing fixture section " + wanted)


def section(path, wanted):
    data, begin, length, _ = section_layout(path, wanted)
    return data[begin:begin + length]


def check_range_corruptions(tool, fixture, work):
    data, begin, length, order = section_layout(fixture, ".debug_rnglists")
    payload = data[begin:begin + length]
    require(struct.unpack_from(order + "H", payload, 4)[0] == 5 and
        payload[6] in (4, 8) and payload[7] == 0 and
        struct.unpack_from(order + "I", payload, 8)[0] == 0,
        "range control requires Forge's DWARF5 direct start/end format")
    width = payload[6]
    word = "I" if width == 4 else "Q"
    lists = []
    cursor = 12
    while cursor < len(payload):
        entries = []
        while cursor < len(payload) and payload[cursor] != 0:
            require(payload[cursor] == 6, "unexpected Forge range entry")
            entries.append(cursor)
            cursor += 1 + 2 * width
        require(cursor < len(payload) and entries, "unterminated or empty fixture range list")
        lists.append(entries)
        cursor += 1
    require(len(lists) >= 2, "fixture must contain CU and discontiguous function range lists")
    results = {}
    for name, entries in zip(("bad-cu-range", "bad-function-range"), lists[:2]):
        copy = bytearray(data)
        outside = (1 << (width * 8 - 1)) - 0x1000
        struct.pack_into(order + word * 2, copy, begin + entries[0] + 1,
            outside, outside + 0x10)
        artifact = work / (name + ".dbg")
        artifact.write_bytes(copy)
        current = run([tool, "--no-follow-debuglink", "--check-all", "--check-summary",
            "--check-show", artifact], work / (name + ".check.txt"))
        llvm = run(["llvm-dwarfdump", "--verify", artifact], work / (name + ".llvm.txt"))
        require(llvm.returncode != 0 and
            "DIE address ranges are not contained in its parent's ranges" in llvm.stdout,
            "complementary LLVM check missed corrupted range")
        # Current libdwarf alone misses this semantic corruption. Retain its
        # transcript, but require LLVM's independent parent-range check as well.
        results[name] = {"dwarfdump_exit": current.returncode, "llvm_exit": llvm.returncode}
    return results


def uleb(value):
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        result.append(byte | (128 if value else 0))
        if not value:
            return bytes(result)


def address(value):
    return b"\x00\x09\x02" + struct.pack("<Q", value)


def sequence(start, end):
    require(end > start, "empty fixture instruction range")
    # Two equal-address rows are valid; this also catches an overly strict > rule.
    return address(start) + b"\x01\x01\x02" + uleb(end - start) + b"\x00\x01\x01"


def checker(tool, artifact, log, expected=None):
    result = run([tool, "--no-follow-debuglink", "--check-all", "--check-summary",
        "--check-show", artifact], log)
    require(result.returncode == 0, "unexpected checker process failure: " + str(log))
    require(not result.stderr, "unexpected checker stderr: " + str(log))
    counts = [int(value) for value in re.findall(
        r"^\*\* Summarize \*\*\s+\d+\s+(\d+)\s*$", result.stdout, re.MULTILINE)]
    require(len(counts) >= 2, "checker did not complete summaries: " + str(log))
    if expected is None:
        require(all(value == 0 for value in counts), "positive checker errors: " + str(log))
        require("*** DWARF CHECK:" not in result.stdout, "positive checker diagnostic")
    else:
        require(all(value > 0 for value in counts) and expected in result.stdout,
            "negative checker control was not detected: " + str(log))
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("patched", type=Path)
    parser.add_argument("--unpatched", type=Path)
    parser.add_argument("--forge-fixture", type=Path)
    arguments = parser.parse_args()
    tool = arguments.patched.resolve(strict=True)
    repository = Path(__file__).resolve().parents[3]
    root = repository / "build/test-results/dwarfdump-line-sequences"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run.", dir=root))
    print("dwarfdump-line-sequence-results=" + str(work), flush=True)
    source = work / "multi-function.c"
    source.write_text("__attribute__((noinline)) int first_function(int value) { return value + 1; }\n"
        "__attribute__((noinline)) int second_function(int value) { return value + 2; }\n"
        "int main(void) { return second_function(first_function(4)) != 7; }\n")
    original = work / "compiler.elf"
    command = ["gcc", "-g", "-gdwarf-5", "-O0", "-fno-pie", "-no-pie", "-nostdlib",
        "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-Wl,-e,main", source,
        "-o", original]
    require(run(command, work / "compiler.txt").returncode == 0, "fixture build failed")
    (work / "compiler-command.json").write_text(json.dumps([str(x) for x in command]) + "\n")
    run([tool, "--version"], work / "checker-version.txt")
    original_hash = hashlib.sha256(original.read_bytes()).hexdigest()
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    symbols = run(["readelf", "-Ws", original], work / "symbols.txt")
    require(symbols.returncode == 0 and not symbols.stderr, "fixture symbols unavailable")
    functions = {}
    for line in symbols.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[3] == "FUNC" and fields[7] in {
                "first_function", "second_function", "main"}:
            begin, size = int(fields[1], 16), int(fields[2])
            functions[fields[7]] = (begin, begin + size)
    require(len(functions) == 3, "missing fixture function bounds")
    first, middle, last = sorted(functions.values())
    require(first[1] <= middle[0] < middle[1] <= last[0], "unexpected function overlap")
    compiler_lines = section(original, ".debug_line")
    require(struct.unpack_from("<H", compiler_lines, 4)[0] == 5 and
        compiler_lines[6:8] == b"\x08\x00", "unexpected line table format")
    header_end = 12 + struct.unpack_from("<I", compiler_lines, 8)[0]
    require(compiler_lines[12:14] == b"\x01\x01", "fixture requires unit byte operations")
    header = compiler_lines[:header_end]
    programs = {
        "ascending-discontiguous": sequence(*first) + sequence(*last),
        # Descending between independent sequences is valid and required when
        # an entry-first body also has a lower-address fragment.
        "entry-first-discontiguous": sequence(*last) + sequence(*first),
        "missing-final-end": sequence(*first)[:-3],
        "backward-within-sequence": address(last[0]) + b"\x01" + sequence(*first),
        "outside-address": sequence(0x7ffff000, 0x7ffff010),
    }
    expected = {
        "missing-final-end": "final row is missing DW_LNE_end_sequence",
        "backward-within-sequence": "address decreases within a sequence",
        "outside-address": "outside a valid .text range",
    }
    summary = {"compiler": checker(tool, original, work / "compiler.check.txt")}
    for name, program in programs.items():
        payload = bytearray(header + program)
        struct.pack_into("<I", payload, 0, len(payload) - 4)
        line_file = work / (name + ".debug_line")
        line_file.write_bytes(payload)
        artifact = work / (name + ".elf")
        result = run(["objcopy", "--update-section", ".debug_line=" + str(line_file),
            original, artifact], work / (name + ".objcopy.txt"))
        require(result.returncode == 0 and not result.stderr, "fixture rewrite failed")
        summary[name] = checker(tool, artifact, work / (name + ".check.txt"), expected.get(name))
        if name not in expected:
            result = run(["llvm-dwarfdump", "--verify", artifact], work / (name + ".llvm.txt"))
            require(result.returncode == 0 and not result.stderr, "positive LLVM verification failed")
    if arguments.unpatched:
        summary["unpatched-compiler"] = checker(arguments.unpatched.resolve(strict=True),
            original, work / "unpatched-compiler.check.txt",
            "DW_LNE_end_sequence address does not exactly match high function addr")
    if arguments.forge_fixture:
        fixture = arguments.forge_fixture.resolve(strict=True)
        before = hashlib.sha256(fixture.read_bytes()).hexdigest()
        summary["real-forge"] = checker(tool, fixture, work / "real-forge.check.txt")
        summary.update(check_range_corruptions(tool, fixture, work))
        require(hashlib.sha256(fixture.read_bytes()).hexdigest() == before, "Forge fixture changed")
    require(hashlib.sha256(original.read_bytes()).hexdigest() == original_hash,
        "compiler original changed")
    require(hashlib.sha256(source.read_bytes()).hexdigest() == source_hash, "source changed")
    (work / "summary.json").write_text(json.dumps(summary, indent=4) + "\n")
    (work / "original.sha256").write_text(original_hash + "  " + str(original) + "\n")
    (work / "checker.sha256").write_text(hashlib.sha256(tool.read_bytes()).hexdigest() +
        "  " + str(tool) + "\n")
    (work / "result.txt").write_text("dwarfdump-line-sequences=PASS\n")
    print("dwarfdump-line-sequences=PASS")


if __name__ == "__main__":
    main()
