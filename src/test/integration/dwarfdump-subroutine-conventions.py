#!/usr/bin/env python3
"""Check the LLVM/GDB subroutine convention extension without executing target code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fixture(wide, order, attribute=0x36, form=0x0b, convention=3, bad_reference=False):
    """Independent ELF/DWARF5 metadata fixture, no producer library involved."""
    pack = lambda fmt, *values: struct.pack(order + fmt, *values)
    word, width = ("Q", 8) if wide else ("I", 4)
    # CU -> signed base type, subroutine type -> formal parameter.
    abbrev = bytes([1, 0x11, 1, 3, 8, 0x25, 8, 0x13, 5, 0, 0,
        2, 0x24, 0, 3, 8, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0,
        3, 0x15, 1, 3, 8, 0x49, 0x13, attribute, form, 0, 0,
        4, 0x05, 0, 3, 8, 0x49, 0x13, 0, 0, 0])
    body = pack("HBBI", 5, 1, width, 0)
    body += b"\x01pointer.c\0Forge independent validator fixture\0" + pack("H", 2)
    base = len(body) + 4
    body += b"\x02int\0\x04\x05"
    body += b"\x03callback\0" + pack("I", 0xffffff if bad_reference else base)
    body += b"nocall\0" if form == 8 else bytes([convention])
    body += b"\x04value\0" + pack("I", base) + b"\0\0"
    info = pack("I", len(body)) + body
    names = b"\0.text\0.debug_abbrev\0.debug_info\0.shstrtab\0"
    header_size, section_size = (64, 64) if wide else (52, 40)
    data = bytearray(header_size)
    records = [(0,) * 10]
    for name, payload, kind, flags, address in (
            (b".text", bytes(4), 1, 6, 0x1000),
            (b".debug_abbrev", abbrev, 1, 0, 0),
            (b".debug_info", info, 1, 0, 0),
            (b".shstrtab", names, 3, 0, 0)):
        records.append((names.index(name), kind, flags, address, len(data), len(payload),
            0, 0, 1, 0))
        data.extend(payload)
    data.extend(bytes(-len(data) % 8))
    section_offset = len(data)
    for record in records:
        data.extend(pack("II4QII2Q" if wide else "10I", *record))
    data[:16] = bytes([0x7f, 69, 76, 70, 2 if wide else 1, 1 if order == "<" else 2, 1]) + bytes(9)
    machine = (62 if order == "<" else 21) if wide else 8
    struct.pack_into(order + "HHI", data, 16, 2, machine, 1)
    struct.pack_into(order + word * 3 + "I6H", data, 24, 0, 0, section_offset, 0,
        header_size, 0, 0, section_size, len(records), 4)
    return data


def run(argv, log, env=None):
    result = subprocess.run([str(value) for value in argv], capture_output=True, env=env, timeout=60)
    log.write_bytes(result.stdout)
    log.with_suffix(log.suffix + ".stderr").write_bytes(result.stderr)
    require(result.returncode >= 0, "validator terminated by signal: " + str(log))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", type=Path)
    parser.add_argument("--llvm", default="llvm-dwarfdump")
    parser.add_argument("--previous-tool", type=Path)
    parser.add_argument("--output", type=Path, default=Path("build/test-results/dwarfdump-subroutine-conventions"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run.", dir=args.output.resolve()))
    rows = []
    try:
        for wide in (False, True):
            for order in ("<", ">"):
                target = ("64" if wide else "32") + ("le" if order == "<" else "be")
                cases = [
                    ("normal", {}, None),
                    ("nocall", {"convention": 3}, None),
                    ("llvm-win64", {"convention": 0xc1}, None),
                    ("bad-low-pc", {"attribute": 0x11}, "check the tag-attr combination"),
                    ("bad-return-address", {"attribute": 0x2a}, "check the tag-attr combination"),
                    ("bad-convention", {"convention": 0x3f}, "Unknown CC value 0x3f"),
                    ("bad-form", {"form": 8}, None),
                    ("bad-reference", {"bad_reference": True}, None),
                ]
                for label, options, expected in cases:
                    positive = not label.startswith("bad-")
                    if label == "normal":
                        options = {"convention": 1}
                    name = target + "-" + label
                    artifact = work / (name + ".elf")
                    artifact.write_bytes(fixture(wide, order, **options))
                    before = hashlib.sha256(artifact.read_bytes()).hexdigest()
                    log = work / (name + ".strict.txt")
                    result = run([sys.executable, HERE / "check-dwarfdump.py", artifact, log],
                        work / (name + ".driver.txt"), dict(os.environ, DWARFDUMP=str(args.tool.resolve())))
                    transcript = log.read_text()
                    llvm = run([args.llvm, "--verify", artifact], work / (name + ".llvm.txt"))
                    if positive:
                        require(result.returncode == 0 and llvm.returncode == 0,
                            "positive rejected: " + name)
                    else:
                        require(result.returncode != 0, "strict checker accepted: " + name)
                        if expected:
                            require(expected in transcript, "wrong rejection: " + name)
                        # LLVM misses the invalid convention form; strict libdwarf must reject it.
                        # Reference corruption must also fail the independent LLVM reader.
                        if label == "bad-reference":
                            require(llvm.returncode != 0, "LLVM accepted: " + name)
                    if args.previous_tool and positive:
                        old = work / (name + ".previous.txt")
                        previous = run([sys.executable, HERE / "check-dwarfdump.py", artifact, old],
                            work / (name + ".previous-driver.txt"),
                            dict(os.environ, DWARFDUMP=str(args.previous_tool.resolve())))
                        require(previous.returncode != 0 and "check the tag-attr combination" in old.read_text(),
                            "old validator mismatch not reproduced: " + name)
                    require(before == hashlib.sha256(artifact.read_bytes()).hexdigest(), "input changed")
                    rows.append({"case": name, "sha256": before, "strictExit": result.returncode,
                        "llvmExit": llvm.returncode, "expected": "PASS" if positive else "REJECT"})
        (work / "result.json").write_text(json.dumps({"status": "PASS", "cases": rows,
            "scope": "Independent metadata controls; no target execution or architecture support claim."}, indent=4) + "\n")
        print("subroutine-convention-validator=PASS cases=" + str(len(rows)) + " result=" + str(work))
    except BaseException as failure:
        (work / "failure.json").write_text(json.dumps({"status": "FAILED", "message": str(failure),
            "completed": rows}, indent=4) + "\n")
        raise


if __name__ == "__main__":
    main()
