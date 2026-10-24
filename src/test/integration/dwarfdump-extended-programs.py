#!/usr/bin/env python3
"""Exercise validation-only PN_XNUM handling without modifying any supplied ELF."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Header:
    def __init__(self, data):
        require(data[:4] == b"\x7fELF" and data[4] in (1, 2) and data[5] in (1, 2),
            "fixture must be ELF32/64 with a known byte order")
        self.wide = data[4] == 2
        self.order = "<" if data[5] == 1 else ">"
        self.word = "Q" if self.wide else "I"
        self.phoff_field = 32 if self.wide else 28
        self.shinfo_field = 44 if self.wide else 28
        self.phsize_field = 54 if self.wide else 42
        self.phcount_field = self.phsize_field + 2
        self.phoff = struct.unpack_from(self.order + self.word, data, self.phoff_field)[0]
        self.shoff = struct.unpack_from(self.order + self.word, data, 40 if self.wide else 32)[0]
        self.phsize, self.phcount = struct.unpack_from(self.order + "HH", data, self.phsize_field)

    def put(self, data, fmt, offset, value):
        struct.pack_into(self.order + fmt, data, offset, value)


def fixture(wide, order):
    """Build an independent small DWARF5 ELF; no target instruction execution is claimed."""
    width = 8 if wide else 4
    word = "Q" if wide else "I"
    pack = lambda fmt, *values: struct.pack(order + fmt, *values)
    # Compile unit followed by a signed integer base type. All attributes use
    # direct standard forms; ELF and DWARF share the selected byte order.
    abbrev = bytes([1, 0x11, 1, 3, 8, 0x25, 8, 0x13, 5, 0x11, 1, 0x12, 6, 0, 0,
        2, 0x24, 0, 3, 8, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0, 0])
    body = pack("HBBI", 5, 1, width, 0) + b"\x01pn-xnum.c\0Forge validation fixture\0"
    body += pack("H" + word + "I", 2, 0x1000, 4) + b"\x02int\0\x04\x05\x00"
    info = pack("I", len(body)) + body
    names = b"\0.text\0.debug_abbrev\0.debug_info\0.shstrtab\0"
    header_size, section_size, program_size = (64, 64, 56) if wide else (52, 40, 32)
    data = bytearray(header_size)
    records = [(0,) * 10]
    for name, payload, kind, flags, address in (
            (b".text", b"\0" * 4, 1, 6, 0x1000),
            (b".debug_abbrev", abbrev, 1, 0, 0),
            (b".debug_info", info, 1, 0, 0),
            (b".shstrtab", names, 3, 0, 0)):
        records.append((names.index(name), kind, flags, address, len(data), len(payload),
            0, 0, 1, 0))
        data.extend(payload)
    data.extend(b"\0" * (-len(data) % 8))
    section_offset = len(data)
    for record in records:
        data.extend(pack("II4QII2Q" if wide else "10I", *record))
    program_offset = len(data)
    if wide:
        data.extend(pack("II6Q", 1, 5, header_size, 0x1000, 0x1000, 4, 4, 1))
    else:
        data.extend(pack("8I", 1, header_size, 0x1000, 0x1000, 4, 4, 5, 1))
    data[:16] = bytes([0x7f, 69, 76, 70, 2 if wide else 1, 1 if order == "<" else 2, 1]) + bytes(9)
    machine = (62 if order == "<" else 21) if wide else 8
    struct.pack_into(order + "HHI", data, 16, 2, machine, 1)
    struct.pack_into(order + word * 3 + "I6H", data, 24, 0x1000, program_offset,
        section_offset, 0, header_size, program_size, 1, section_size, len(records), 4)
    return data


def extended(data, count):
    header = Header(data)
    require(0 < header.phcount < 0xffff and header.phcount <= count,
        "original fixture needs ordinary program headers")
    result = bytearray(data)
    result.extend(bytes(-len(result) % 8))
    offset = len(result)
    result.extend(bytes(count * header.phsize))
    # Preserve all original records at the end of a genuine extended table.
    original_table = data[header.phoff:header.phoff + header.phcount * header.phsize]
    require(len(original_table) == header.phcount * header.phsize, "truncated original table")
    result[-len(original_table):] = original_table
    header.put(result, header.word, header.phoff_field, offset)
    header.put(result, "H", header.phcount_field, 0xffff)
    header.put(result, "I", header.shoff + header.shinfo_field, count)
    return result


def run(command, log):
    result = subprocess.run([str(value) for value in command], capture_output=True, text=True)
    log.write_text(result.stdout + result.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", type=Path)
    parser.add_argument("--previous-tool", type=Path)
    parser.add_argument("--hosted-root", type=Path,
        help="digest-verified extracted x86_64/aarch64 target artifacts")
    args = parser.parse_args()
    tool = args.tool.resolve(strict=True)
    root = Path(__file__).resolve().parents[3]
    results = root / "build/test-results/dwarfdump-extended-programs"
    results.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run.", dir=results))
    print("dwarfdump-extended-program-results=" + str(work), flush=True)
    helper = root / "src/test/integration/check-dwarfdump.py"
    summary = {"positives": [], "negatives": [], "hosted": {}}
    run([tool, "--version"], work / "version.txt")

    def positive(path, label, original=None):
        command = [sys.executable, helper, path, work / (label + ".check.txt"), "--tool", tool]
        if original:
            command += ["--original", original]
        result = run(command, work / (label + ".runner.txt"))
        require(result.returncode == 0, "positive strict validation failed: " + label)
        metadata = json.loads((work / (label + ".check.txt.check.json")).read_text())
        require(metadata["status"] == "PASS", "missing positive completion")
        summary["positives"].append(label)
        return metadata

    def negative(data, label):
        path = work / (label + ".elf")
        path.write_bytes(data)
        result = run([sys.executable, helper, path, work / (label + ".check.txt"),
            "--tool", tool], work / (label + ".runner.txt"))
        metadata = json.loads((work / (label + ".check.txt.check.json")).read_text())
        text = (work / (label + ".check.txt")).read_text()
        require(result.returncode != 0 and metadata["status"] == "FAILED" and
            metadata["exit_status"] == 0 and
            metadata["failure"] == "checker reported a diagnostic" and
            not (work / (label + ".check.txt.stderr")).read_bytes() and
            "DW_DLE_IMPROPER_SECTION_ZERO" in text, "wrong or missed malformed-header rejection: " + label)
        summary["negatives"].append(label)

    for wide in (False, True):
        for order in ("<", ">"):
            label = ("elf64" if wide else "elf32") + ("-le" if order == "<" else "-be")
            ordinary = fixture(wide, order)
            path = work / (label + ".ordinary.elf")
            path.write_bytes(ordinary)
            positive(path, label + ".ordinary")
            for count in (0xffff, 0x10000):
                path = work / (label + ".extended-" + str(count) + ".elf")
                path.write_bytes(extended(ordinary, count))
                positive(path, path.stem)
            valid = extended(ordinary, 0xffff)
            header = Header(valid)
            mutations = [
                ("zero-count", "I", header.shoff + header.shinfo_field, 0),
                ("small-count", "I", header.shoff + header.shinfo_field, 0xfffe),
                ("oversized-count", "I", header.shoff + header.shinfo_field, 0xffffffff),
                ("missing-table", header.word, header.phoff_field, 0),
                ("inside-header", header.word, header.phoff_field, 1),
                ("offset-overflow", header.word, header.phoff_field, (1 << (64 if wide else 32)) - 1),
                ("zero-entry-size", "H", header.phsize_field, 0),
                ("small-entry-size", "H", header.phsize_field, header.phsize - 1),
                ("small-elf-header", "H", 52 if wide else 40, 63 if wide else 51),
                ("overlapping-elf-header", "H", 52 if wide else 40, header.phoff + 1),
                ("nonzero-section-name", "I", header.shoff, 1),
                ("nonzero-section-flags", header.word, header.shoff + 8, 1),
                ("nonzero-section-address", header.word, header.shoff + (16 if wide else 12), 1),
            ]
            for name, fmt, offset, value in mutations:
                copy = bytearray(valid)
                header.put(copy, fmt, offset, value)
                negative(copy, label + "." + name)
            negative(valid[:-1], label + ".truncated-table")
            copy = bytearray(ordinary)
            header.put(copy, "I", header.shoff + header.shinfo_field, 0xffff)
            negative(copy, label + ".ordinary-nonzero-info")
            if args.previous_tool:
                path = work / (label + ".extended-65535.elf")
                previous = run([args.previous_tool.resolve(strict=True), "--no-follow-debuglink",
                    "-ka", "-ki", "-kd", path], work / (label + ".previous.txt"))
                require(previous.returncode == 0 and not previous.stderr and
                    "DW_DLE_IMPROPER_SECTION_ZERO" in previous.stdout,
                    "previous consumer did not reproduce PN_XNUM rejection")

    source = work / "compiler.c"
    source.write_text("int entry(void) { return 7; }\n")
    compiled = work / "compiler.elf"
    command = ["gcc", "-g", "-gdwarf-5", "-O0", "-fno-pie", "-no-pie", "-nostdlib",
        "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-Wl,-e,entry", source, "-o", compiled]
    require(run(command, work / "compiler-build.txt").returncode == 0, "compiler fixture build failed")
    (work / "compiler-command.json").write_text(json.dumps([str(x) for x in command]) + "\n")
    original_bytes = compiled.read_bytes()
    positive(compiled, "compiler-ordinary")
    copied = work / "compiler-extended.elf"
    copied.write_bytes(extended(original_bytes, 0xffff))
    positive(copied, "compiler-extended")
    llvm = run(["llvm-dwarfdump", "--verify", copied], work / "compiler-extended.llvm.txt")
    require(llvm.returncode == 0 and not llvm.stderr, "compiler extended LLVM verification failed")
    require(compiled.read_bytes() == original_bytes, "compiler original changed")

    if args.hosted_root:
        for target in ("x86_64", "aarch64"):
            directories = list((args.hosted_root / target).glob(
                "elf-layout-export/*/" + target + "/exec/extended-programs"))
            require(len(directories) == 1, "expected exactly one hosted extended-programs case")
            directory = directories[0]
            original = directory / "input.elf"
            artifact = directory / "first/semantic.exec.ghidra-forge.dbg"
            hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (original, artifact)}
            metadata = positive(artifact, "hosted-" + target, original)
            require(metadata["reported_errors"] > 0 and metadata["uncorroborated_errors"] == 0,
                "hosted input did not exercise exact inherited-frame corroboration")
            for path in (original, artifact):
                require(hashlib.sha256(path.read_bytes()).hexdigest() == hashes[str(path)],
                    "hosted supplied file changed")
            summary["hosted"][target] = {"hashes": hashes, "validation": metadata}
    (work / "summary.json").write_text(json.dumps(summary, indent=4) + "\n")
    (work / "result.txt").write_text("dwarfdump-extended-programs=PASS\n")
    print("dwarfdump-extended-programs=PASS")


if __name__ == "__main__":
    main()
