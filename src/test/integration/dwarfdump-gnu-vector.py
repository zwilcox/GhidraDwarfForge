#!/usr/bin/env python3
"""Check GNU vector flag forms without relaxing invalid form/tag/reference checks."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('container_fixture', HERE / 'dwarfdump-extended-programs.py')
container = importlib.util.module_from_spec(spec)
spec.loader.exec_module(container)


def fixture(wide, order, version, mode):
    data = container.fixture(wide, order)
    word, width = ('Q', 8) if wide else ('I', 4)
    pack = lambda fmt, *values: struct.pack(order + fmt, *values)
    fmt = order + ('II4QII2Q' if wide else '10I')
    size = struct.calcsize(fmt)
    shoff = struct.unpack_from(order + word, data, 40 if wide else 32)[0]
    rows = [list(struct.unpack_from(fmt, data, shoff + index * size)) for index in range(5)]
    forms = {'flag': (0x0c, b'\x01'), 'flag-present': (0x19, b''),
        'bad-string': (8, b'vector\0'), 'bad-constant': (0x0b, b'\x01'),
        'bad-reference-form': (0x13, pack('I', 0)), 'bad-expression': (0x18, b'\x01\x30')}
    form, value = forms.get(mode, forms['flag-present'])
    tag = 0x2e if mode == 'bad-tag' else 1
    # CU -> int, vector array -> subrange. GNU vector ULEB128 is 0x87,0x42.
    abbrev = bytes([1, 0x11, 1, 3, 8, 0x25, 8, 0x13, 5, 0x11, 1, 0x12, 6, 0, 0,
        2, 0x24, 0, 3, 8, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0,
        3, tag, 1, 3, 8, 0x49, 0x13, 0x87, 0x42, form, 0, 0,
        4, 0x21, 0, 0x49, 0x13, 0x37, 0x0b, 0, 0, 0])
    body = pack('HBBI', 5, 1, width, 0) if version == 5 else pack('HIB', 4, 0, width)
    body += b'\x01gnu-vector.c\0Forge independent vector checker fixture\0'
    body += pack('H' + word + 'I', 2, 0x1000, 4)
    base = len(body) + 4
    body += b'\x02int\0\x04\x05'
    body += b'\x03vector4\0' + pack('I', 0xffffff if mode == 'bad-type' else base) + value
    body += b'\x04' + pack('I', base) + b'\x04\0\0'
    info = pack('I', len(body)) + body
    for index, payload in ((2, abbrev), (3, info)):
        rows[index][4:6] = [len(data), len(payload)]
        data.extend(payload)
    data.extend(bytes(-len(data) % 8))
    struct.pack_into(order + word, data, 40 if wide else 32, len(data))
    for row in rows:
        data.extend(struct.pack(fmt, *row))
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', type=Path)
    parser.add_argument('--previous-tool', type=Path)
    args = parser.parse_args()
    root = HERE.parents[2] / 'build/test-results/dwarfdump-gnu-vector'
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='run.', dir=root))
    results = []
    try:
        for wide in (False, True):
            for order in ('<', '>'):
                for version in (4, 5):
                    for mode in ('flag', 'flag-present', 'bad-string', 'bad-constant',
                            'bad-reference-form', 'bad-expression', 'bad-tag', 'bad-type'):
                        label = f"elf{64 if wide else 32}-{'le' if order == '<' else 'be'}-dwarf{version}-{mode}"
                        path = work / (label + '.elf')
                        path.write_bytes(fixture(wide, order, version, mode))
                        sha = hashlib.sha256(path.read_bytes()).hexdigest()
                        positive = not mode.startswith('bad-')
                        if positive:
                            for name, command in [('gnu', ['readelf', '-hSW', '--debug-dump=info,abbrev', path]),
                                    ('llvm', ['llvm-dwarfdump', '--verify', path])]:
                                run = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=30)
                                (work / (label + '.' + name + '.log')).write_text(run.stdout + run.stderr)
                                assert run.returncode == 0 and not run.stderr.strip(), (label, name, run.stderr)
                                assert 'warning:' not in run.stdout.lower() and 'error:' not in run.stdout.lower()
                        tools = [(False, args.tool)] + ([(True, args.previous_tool)] if args.previous_tool else [])
                        for previous, tool in tools:
                            log = work / (label + ('-previous' if previous else '') + '.log')
                            run = subprocess.run([sys.executable, HERE / 'check-dwarfdump.py', path, log,
                                '--tool', tool], capture_output=True, text=True, timeout=30)
                            Path(str(log) + '.runner').write_text(run.stdout + run.stderr)
                            accepted = positive and not previous
                            assert (run.returncode == 0) == accepted, (label, previous, run.stdout, run.stderr)
                            receipt = json.loads(Path(str(log) + '.check.json').read_text())
                            assert receipt['status'] == ('PASS' if accepted else 'FAILED'), receipt
                            transcript = log.read_text()
                            if positive and previous or mode in ('bad-string', 'bad-constant', 'bad-reference-form', 'bad-expression'):
                                assert 'DW_AT_GNU_vector' in transcript and 'check the attr-formclass combination' in transcript
                            elif mode == 'bad-tag':
                                assert 'DW_AT_GNU_vector' in transcript and 'check the tag-attr combination' in transcript
                            elif mode == 'bad-type':
                                assert 'DW_DLE_' in transcript or 'DWARF CHECK:' in transcript
                            assert hashlib.sha256(path.read_bytes()).hexdigest() == sha
                            results.append({'fixture': label, 'previous': previous, 'accepted': accepted,
                                'sha256': sha, 'check': str(log) + '.check.json'})
        (work / 'result.json').write_text(json.dumps({'status': 'PASS', 'cases': results,
            'scope': 'Independent metadata, ELF32/64 both byte orders, DWARF4/5; no runtime support claim.'}, indent=4) + '\n')
        print('dwarfdump-gnu-vector=PASS cases=' + str(len(results)) + ' ' + str(work))
    except BaseException as failure:
        (work / 'failure.json').write_text(json.dumps({'status': 'FAILED', 'error': repr(failure),
            'completed': results}, indent=4) + '\n')
        raise


if __name__ == '__main__':
    main()
