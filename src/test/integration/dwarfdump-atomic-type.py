#!/usr/bin/env python3
"""Accept a compiler's DWARF 5 atomic type; reject a non-type at that reference target."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys


def atomic_tag_offset(data):
    assert data[:6] == b'\x7fELF\x02\x01', 'fixture must be ELF64 little-endian'
    table, = struct.unpack_from('<Q', data, 40)
    entry, count, names = struct.unpack_from('<HHH', data, 58)
    assert entry == 64 and 0 < names < count < 65535
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, table + i * entry) for i in range(count)]
    shstr = headers[names]
    strings = data[shstr[4]:shstr[4] + shstr[5]]
    sections = [h for h in headers if strings[h[0]:].split(b'\0', 1)[0] == b'.debug_abbrev']
    section, = sections
    pos, end = section[4], section[4] + section[5]

    def leb():
        nonlocal pos
        value, shift = 0, 0
        while pos < end and shift < 70:
            byte = data[pos]
            pos += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
            shift += 7
        raise AssertionError('truncated fixture abbreviation')

    found = []
    while pos < end:
        code = leb()
        if code == 0:
            continue
        tag_pos = pos
        tag = leb()
        if tag == 0x47:
            assert pos == tag_pos + 1
            found.append(tag_pos)
        assert pos < end
        pos += 1  # Children byte.
        while True:
            attribute, form = leb(), leb()
            if attribute == 0 and form == 0:
                break
            assert attribute and form
            if form == 0x21:  # DW_FORM_implicit_const: signed LEB has the same byte terminator.
                leb()
    offset, = found
    return offset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('checker', type=Path)
    parser.add_argument('--results', type=Path, default=Path('build/test-results/dwarfdump-atomic-type'))
    parser.add_argument('--unpatched', type=Path)
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    source = root / 'atomic.c'
    source.write_text('_Atomic(int) atomic_value = 7;\nint main(void) { return atomic_value - 7; }\n')
    reference, valid, invalid = [root / name for name in ('reference', 'valid', 'invalid-type-target')]
    commands = []

    def run(label, command, expected=0):
        command = list(map(str, command))
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (root / (label + '.stdout')).write_text(result.stdout)
        (root / (label + '.stderr')).write_text(result.stderr)
        commands.append({'label': label, 'command': command, 'exit': result.returncode})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert result.returncode == expected, (label, result.stderr)
        return result

    run('compile', ['cc', '-std=c11', '-O0', '-gdwarf-5', '-fno-pie', '-no-pie', source, '-o', reference])
    before = hashlib.sha256(reference.read_bytes()).hexdigest()
    shutil.copyfile(reference, valid)
    data = bytearray(reference.read_bytes())
    offset = atomic_tag_offset(data)
    data[offset] = 0x34  # DW_TAG_variable is not a permitted DW_AT_type target.
    invalid.write_bytes(data)
    assert sum(a != b for a, b in zip(reference.read_bytes(), data)) == 1
    run('llvm-reference', ['llvm-dwarfdump', '--verify', reference])
    wrapper = Path(__file__).with_name('check-dwarfdump.py')

    def check(label, checker, artifact, expected):
        return run(label, [sys.executable, '-B', wrapper, artifact, root / (label + '.check.log'),
            '--original', reference, '--tool', checker.resolve()], expected)

    if args.unpatched:
        check('old-checker', args.unpatched, valid, 1)
        text = (root / 'old-checker.check.log').read_text()
        assert 'does not point to Type info we got tag 0x47 DW_TAG_atomic_type' in text
    check('valid-atomic', args.checker, valid, 0)
    check('invalid-reference', args.checker, invalid, 1)
    text = (root / 'invalid-reference.check.log').read_text()
    assert 'does not point to Type info we got tag 0x34 DW_TAG_variable' in text
    assert hashlib.sha256(reference.read_bytes()).hexdigest() == before
    result = {'status': 'PASS_ATOMIC_TYPE_REFERENCE_CHECKS', 'referenceSha256': before,
        'validAtomic': True, 'invalidVariableReferenceRejected': True, 'mutatedBytes': 1,
        'oldCheckerReproduced': bool(args.unpatched), 'checker': str(args.checker.resolve()),
        'scope': 'compiler-generated Linux ELF64 little-endian DWARF 5; no producer or Ghidra involved'}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print('dwarfdump-atomic-type=PASS')


if __name__ == '__main__':
    main()
