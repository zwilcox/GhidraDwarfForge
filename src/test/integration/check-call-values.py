#!/usr/bin/env python3
"""Independent bounded DWARF VM for actual-value encoder regression vectors."""
import argparse
import json
from pathlib import Path


def evaluate(code, address_bytes, byte_order, registers):
    position = 0
    stack = []
    mask = (1 << (address_bytes * 8)) - 1
    steps = 0

    def uleb():
        nonlocal position
        value, shift = 0, 0
        while True:
            assert position < len(code) and shift < 70, "invalid ULEB"
            byte = code[position]
            position += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
            shift += 7

    while position < len(code):
        steps += 1
        assert steps <= 4096, "expression did not terminate"
        operation = code[position]
        position += 1
        if operation == 0x10:
            stack.append(uleb() & mask)
        elif operation == 0xa3:
            size = uleb()
            end = position + size
            assert code[position] == 0x90 and end <= len(code), "expected entry register block"
            position += 1
            register = uleb()
            assert position == end
            stack.append(registers[register] & mask)
        elif operation in (0x28, 0x2f):
            displacement = int.from_bytes(code[position:position + 2], byte_order, signed=True)
            position += 2
            if operation == 0x2f or stack.pop() != 0:
                position += displacement
            assert 0 <= position <= len(code), "branch escapes expression"
        else:
            right, left = stack.pop(), stack.pop()
            operations = {
                0x22: lambda: left + right,
                0x1c: lambda: left - right,
                0x1e: lambda: left * right,
                0x1a: lambda: left & right,
                0x21: lambda: left | right,
                0x27: lambda: left ^ right,
                0x24: lambda: left << right,
                0x25: lambda: left >> right,
                0x29: lambda: int(left == right),
                0x2e: lambda: int(left != right),
            }
            assert operation in operations, f"unsupported opcode {operation:x}"
            stack.append(operations[operation]() & mask)
    assert len(stack) == 1, "expression must yield exactly one value"
    return stack[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vectors", type=Path)
    parser.add_argument("--min-count", type=int, default=7000)
    args = parser.parse_args()
    vectors = json.loads(args.vectors.read_text())
    assert len(vectors) >= args.min_count, "missing boundary/random profiles"
    for vector in vectors:
        registers = {int(key): int(value, 16) for key, value in vector["registers"].items()} if "registers" in vector else {
            5: int(vector["register5"], 16), 6: int(vector["register6"], 16)}
        result = evaluate(bytes.fromhex(vector["expression"]), vector["addressBytes"],
                          "little" if vector["order"] == "LITTLE_ENDIAN" else "big",
                          registers)
        assert result == int(vector["expected"], 16), (vector, hex(result))
    print(f"call-value-dwarf-vm=PASS vectors={len(vectors)}")


if __name__ == "__main__":
    main()
