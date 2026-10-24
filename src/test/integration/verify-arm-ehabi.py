#!/usr/bin/env python3
"""Check compiler-provided ARM EHABI coverage for the static-scope fixture.

This is a fixture precondition, not a general EHABI decoder. GNU readelf decodes
the real index/extab; runtime GDB still proves the caller/return behavior.
"""

from bisect import bisect_right
from pathlib import Path
import re
import subprocess
import sys


def readelf(output_dir, name, *arguments):
    result = subprocess.run(["readelf", *arguments], capture_output=True, text=True)
    (output_dir / f"{name}.txt").write_text(result.stdout)
    (output_dir / f"{name}.stderr").write_text(result.stderr)
    if result.returncode or result.stderr or re.search(
            r"\b(?:warning|error):", result.stdout, re.IGNORECASE):
        raise AssertionError(f"readelf rejected ARM unwind input: {name}")
    return result.stdout


def verify(input_file, reference, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    sections = readelf(output_dir, "input-sections", "-SW", str(input_file))
    index = re.findall(
        r"^\s*\[\s*\d+\]\s+\.ARM\.exidx\s+ARM_EXIDX\s+"
        r"[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s", sections, re.MULTILINE)
    if len(index) != 1 or int(index[0], 16) == 0 or int(index[0], 16) % 8:
        raise AssertionError("missing or malformed ARM EHABI index")
    count = int(index[0], 16) // 8
    unwind = readelf(output_dir, "input-unwind", "--unwind", str(input_file))
    headers = list(re.finditer(r"^(0x[0-9a-fA-F]+)(?: <[^>]+>)?:.*$",
                              unwind, re.MULTILINE))
    starts = [int(header.group(1), 16) for header in headers]
    if len(starts) != count or any(a >= b for a, b in zip(starts, starts[1:])):
        raise AssertionError("malformed ARM EHABI entry count/order")
    decoded = []
    for position, header in enumerate(headers):
        end = headers[position + 1].start() if position + 1 < len(headers) else len(unwind)
        block = unwind[header.start():end]
        # The fixture compiler uses standard compact personalities. A cantunwind
        # startup/sentinel is valid, but must not cover any checked function.
        decoded.append("[cantunwind]" not in block and
                       re.search(r"Compact model index: [012]\b", block) is not None and
                       re.search(r"^\s+0x[0-9a-fA-F]+\s+.*\S", block, re.MULTILINE) is not None and
                       re.search(r"\b(?:reserved|unknown|corrupt|bad|refuse)\b", block,
                                 re.IGNORECASE) is None)
    symbols = readelf(output_dir, "reference-symbols", "-Ws", str(reference))
    expected = {"first_scope", "second_scope", "main"}
    functions = {}
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[3] == "FUNC" and fields[7] in expected:
            value = (int(fields[1], 16), int(fields[2]))
            if fields[7] in functions and functions[fields[7]] != value:
                raise AssertionError("ambiguous fixture function symbol")
            functions[fields[7]] = value
    if set(functions) != expected:
        raise AssertionError("missing fixture function bounds")
    evidence = []
    for name, (start, size) in sorted(functions.items()):
        if size <= 0:
            raise AssertionError(f"empty fixture function: {name}")
        cursor = start
        while cursor < start + size:
            entry = bisect_right(starts, cursor) - 1
            if entry < 0 or not decoded[entry]:
                raise AssertionError(f"missing decoded ARM EHABI coverage for {name}")
            limit = starts[entry + 1] if entry + 1 < len(starts) else start + size
            evidence.append(f"{name} {cursor:#x}..{min(limit, start + size):#x} "
                            f"index={starts[entry]:#x}")
            cursor = min(limit, start + size)
    (output_dir / "coverage.txt").write_text("\n".join(evidence) + "\n")
    print("arm-ehabi-fixture-coverage=PASS")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: verify-arm-ehabi.py <stripped-elf> <reference-elf> <result-dir>")
    verify(*(Path(argument) for argument in sys.argv[1:]))
