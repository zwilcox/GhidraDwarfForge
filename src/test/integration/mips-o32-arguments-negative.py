#!/usr/bin/env python3
"""Require GDB to reject structurally valid O32 carrier and lifetime mutations."""
import ast
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('wide', HERE / 'mips-wide-arguments.py')
wide = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wide)


def main(base):
    base = base.resolve(strict=True)
    assert json.loads((base / 'result.json').read_text())['status'] in ('PASS', 'CONTROLS_PENDING')
    metadata = json.loads((base / 'metadata.json').read_text())
    assert metadata['abi'] == 'o32'
    protected = {str(path): wide.support.digest(path) for path in base.iterdir() if path.is_file()}
    root = Path(tempfile.mkdtemp(prefix='negative.', dir=base))
    image = (base / 'abi.dbg').read_bytes()
    endian = '>' if metadata['endian'] == 'be' else '<'
    assert image[:5] == b'\x7fELF\x01' and image[5] == (2 if endian == '>' else 1)
    assert struct.unpack_from(endian + 'H', image, 18)[0] == 8
    shoff = struct.unpack_from(endian + 'I', image, 32)[0]
    shsize, count, names_index = struct.unpack_from(endian + 'HHH', image, 46)
    assert shsize == 40 and 0 < names_index < count
    sections = [struct.unpack_from(endian + '10I', image, shoff + index * shsize) for index in range(count)]
    names_row = sections[names_index]
    names = image[names_row[4]:names_row[4] + names_row[5]]
    sections = {names[row[0]:].split(b'\0', 1)[0].decode(): row for row in sections}
    info = subprocess.check_output(['readelf', '--debug-dump=info', base / 'abi.dbg'], text=True)
    (root / 'baseline-info.log').write_text(info)
    dies = re.split(r'(?=^\s*<\d+><[0-9a-f]+>:)', info, flags=re.M)

    def parameter(function, name):
        owner, = [index for index, die in enumerate(dies) if 'DW_TAG_subprogram' in die and
            re.search(r'DW_AT_name\s*:.*\b' + function + r'\s*$', die, re.M)]
        candidates = []
        for die in dies[owner + 1:]:
            depth = re.match(r'\s*<(\d+)>', die)
            if depth and int(depth[1]) <= 1:
                break
            if 'DW_TAG_formal_parameter' in die and re.search(r'DW_AT_name\s*:.*\b' + name + r'\s*$', die, re.M):
                candidates.append(die)
        formal, = candidates
        location = re.search(r'DW_AT_location\s*:\s*(0x[0-9a-f]+) \(location list\)', formal)
        if location:
            offset = sections['.debug_loclists'][4] + int(location[1], 16)
            assert image[offset] == 7 and image[offset + 9] < 128
            return offset + 10, image[offset + 9], offset
        block = re.search(r'<([0-9a-f]+)>\s+DW_AT_location\s*:\s*(\d+) byte block:', formal)
        assert block
        offset = sections['.debug_info'][4] + int(block[1], 16)
        length = int(block[2])
        assert length < 128 and image[offset] == length
        return offset + 1, length, None

    words = parameter('wide_words', 'a')
    pair = parameter('wide_pair', 'value')
    mixed = parameter('wide_mixed', 'b')
    mutations = [
        ('word-carrier', 'wide_words', 'a', words, 5 if endian == '>' else 4, 7 if endian == '>' else 6),
        ('aggregate-carrier', 'wide_pair', 'value.first', pair, 6, 4),
        ('double-carrier', 'wide_mixed', 'b', mixed, 6 if endian == '>' else 7, 4 if endian == '>' else 5),
        ('late-gap', 'wide_words', 'a', words, None, None)]
    rows = []
    for label, function, expression, location, old, new in [("positive", None, None, None, None, None), *mutations]:
        case = root / label
        case.mkdir()
        for name in ('abi.input', 'abi.reference', 'abi.dbg.c', 'metadata.json', 'compiler-runtime-gdb.log'):
            shutil.copy2(base / name, case / name)
        if (base / 'abi.driver').exists():
            shutil.copy2(base / 'abi.driver', case / 'abi.driver')
        data = bytearray(image)
        expected_offset = 0
        if location:
            offset, length, entry = location
            if label == 'late-gap':
                start, end = struct.unpack_from(endian + 'II', data, entry + 1)
                expected_offset = end - start
                struct.pack_into(endian + 'I', data, entry + 5, end + 4)
            else:
                matches = [index for index in range(offset, offset + length - 1)
                    if data[index:index + 2] == bytes((0x90, old))]
                at, = matches
                data[at + 1] = new
        (case / 'abi.dbg').write_bytes(data)
        for name, command in (
                ('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline,loc', case / 'abi.dbg']),
                ('llvm', ['llvm-dwarfdump', '--verify', case / 'abi.dbg']),
                ('strict', [sys.executable, HERE / 'check-dwarfdump.py', case / 'abi.dbg',
                    case / 'strict.txt', '--original', case / 'abi.input'])):
            wide.support.run(command, case / (name + '.log'), timeout=60)
            wide.support.require_clean(case / (name + '.log'))
        process = subprocess.run(['bash', HERE / 'mips-wide-arguments-gdb.sh', case, 'forge'],
            capture_output=True, timeout=120)
        (case / 'driver.stdout').write_bytes(process.stdout)
        (case / 'driver.stderr').write_bytes(process.stderr)
        assert not process.stderr, process.stderr
        text = process.stdout.decode()
        if function:
            assert process.returncode == 1 and 'MIPS_WIDE_ARGUMENTS_FORGE_PASS' not in text
            failure, = re.findall(r'^AssertionError: (.*)$', text, re.M)
            actual = ast.literal_eval(failure)
            assert actual[:4] == ('forge', function, expected_offset, expression), actual
            assert not (case / 'forge-observations.json').exists()
        else:
            assert process.returncode == 0 and 'MIPS_WIDE_ARGUMENTS_FORGE_PASS' in text
        assert not re.search(r'(?im)^warning:', text), text
        rows.append({'case': label, 'status': 'REJECTED' if function else 'PASS',
            'function': function, 'offset': expected_offset, 'artifactSha256': wide.support.digest(case / 'abi.dbg')})
    assert protected == {path: wide.support.digest(Path(path)) for path in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'cases': rows, 'baselineUnchanged': True}, indent=4) + '\n')
    print('mips-o32-arguments-negative=PASS ' + str(root))


if __name__ == '__main__':
    main(Path(sys.argv[1]))
