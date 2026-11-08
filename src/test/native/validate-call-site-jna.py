#!/usr/bin/env python3
"""Independently check sections from CallSiteProducerSmoke; no runtime ABI claim."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess


PROFILES = {
    "x86_64": ("elf64-x86-64", 8),
    "aarch64": ("elf64-littleaarch64", 8),
    "arm32": ("elf32-littlearm", 4),
    "mips32be": ("elf32-tradbigmips", 4),
    "mips32le": ("elf32-tradlittlemips", 4),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=PROFILES)
    parser.add_argument("--sections", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output must be empty")
    commands = []

    def run(command):
        result = subprocess.run(command, text=True, capture_output=True, timeout=60)
        commands.append({"command": command, "returncode": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
        (output / "commands.json").write_text(json.dumps(commands, indent=4) + "\n")
        if result.returncode or result.stderr:
            raise RuntimeError(f"Validator diagnostic: {command}\n{result.stdout}\n{result.stderr}")
        return result.stdout

    envelope = output / "envelope.bin"
    envelope.write_bytes(b"\0")
    target, width = PROFILES[args.profile]
    object_path = output / "probe.o"
    command = ["llvm-objcopy", "-I", "binary", "-O", target]
    sections = sorted(args.sections.resolve().glob(".debug_*"))
    if not {".debug_info", ".debug_abbrev"}.issubset({p.name for p in sections}):
        raise RuntimeError("missing required JNA section output")
    for section in sections:
        command.extend(["--add-section", section.name + "=" + str(section)])
    command.extend([str(envelope), str(object_path)])
    run(command)
    run(["llvm-dwarfdump", "--verify", str(object_path)])
    abbreviations = run(["readelf", "--debug-dump=abbrev", str(object_path)])
    for attr, form in (("call_pc", "addr"), ("call_return_pc", "addr"),
                       ("call_origin", "ref4"), ("call_parameter", "ref4"),
                       ("call_value", "exprloc"), ("location", "exprloc")):
        if not re.search(rf"\bDW_AT_{attr}\s+DW_FORM_{form}\b", abbreviations):
            raise RuntimeError(f"incorrect form for {attr}")
    info = run(["readelf", "--debug-dump=info", str(object_path)])
    values = []
    for line in info.splitlines():
        match = re.search(r"DW_AT_call_value\s*:\s*(\d+) byte block:\s*([0-9a-f ]+)\s*\(", line)
        if match:
            value = bytes(int(byte, 16) for byte in match[2].split())
            assert len(value) == int(match[1]), line
            values.append(value)
    assert len(values) == 2 and values[0] == bytes.fromhex("a30150"), "missing original/generated copied expressions"
    evaluate = runpy.run_path(str(Path(__file__).resolve().parents[1] / "integration/check-call-values.py"))["evaluate"]
    mask = (1 << (width * 8)) - 1
    generated_checks = 0
    for first in (0, 1, 127, 128, 255, 0xffffffff, 0xffffffffffffffff):
        for second in (0, 1, 0xffffffff):
            first, second = first & mask, second & mask
            signed_byte = (first & 255) - (256 if first & 128 else 0)
            expected = (signed_byte + 1 if second == 0 else first + second) & mask
            assert evaluate(values[1], width, "big" if args.profile == "mips32be" else "little",
                            {5: first, 6: second}) == expected
            generated_checks += 1
    if not re.search(rf"Pointer Size:\s+{width}\b", info):
        raise RuntimeError("target address width mismatch")
    address = 0x100001000 if width == 8 else 0x401000
    for attr, value in (("call_pc", address + 4), ("call_return_pc", address + 8)):
        if not re.search(rf"DW_AT_{attr}\s*:\s*0x0*{value:x}\b", info):
            raise RuntimeError(f"incorrect {attr}; possible truncation or byte-order error")
    llvm = run(["llvm-dwarfdump", "--debug-info", str(object_path)])
    if not re.search(r"DW_AT_call_value\s+\(DW_OP_entry_value\(DW_OP_reg0", llvm):
        raise RuntimeError("mutating the Java input buffer corrupted the retained block")
    entries = list(re.finditer(r"^0x([0-9a-f]+):\s+(DW_TAG_\w+)", llvm, re.MULTILINE))
    dies = {int(entry.group(1), 16):
            (entry.group(2), llvm[entry.end():entries[i + 1].start() if i + 1 < len(entries) else len(llvm)])
            for i, entry in enumerate(entries)}
    for attribute, expected, tag in (("call_origin", "synthetic_callee", "DW_TAG_subprogram"),
                                     ("call_parameter", "synthetic_parameter", "DW_TAG_formal_parameter")):
        reference = re.search(rf"DW_AT_{attribute}\s+\(0x([0-9a-f]+)", llvm)
        target_die = dies.get(int(reference.group(1), 16)) if reference else None
        if (target_die is None or target_die[0] != tag or
                not re.search(rf'DW_AT_name\s+\("{expected}"\)', target_die[1])):
            raise RuntimeError(f"incorrect {attribute} DIE reference")
    report = {"profile": args.profile, "status": "PASS", "addressBytes": width,
              "blockCopyVerified": True, "referencesVerified": True, "sectionsSha256": {},
              "generatedExpressionChecks": generated_checks,
              "scope": "Producer/JNA/serialized forms only; not Ghidra extraction or GDB runtime"}
    for section in sections:
        with section.open("rb") as stream:
            report["sectionsSha256"][section.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    (output / "summary.json").write_text(json.dumps(report, indent=4) + "\n")
    print(f"call-site-jna-forms=PASS profile={args.profile} copied-buffer=true references=true")


if __name__ == "__main__":
    main()
