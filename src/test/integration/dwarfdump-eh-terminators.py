#!/usr/bin/env python3
"""Check GNU frame terminators independently of legacy IRIX debug-frame lengths."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('elf_fixture', source / 'dwarfdump-extended-programs.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def framed(wide, order, name, payload):
    data = fixtures.fixture(wide, order)
    word = 'Q' if wide else 'I'
    fmt = order + ('II4QII2Q' if wide else '10I')
    size = struct.calcsize(fmt)
    shoff = struct.unpack_from(order + word, data, 40 if wide else 32)[0]
    rows = [list(struct.unpack_from(fmt, data, shoff + index * size)) for index in range(5)]
    names = data[rows[4][4]:rows[4][4] + rows[4][5]]
    name_index = len(names)
    names += name.encode() + b'\0'
    rows[4][4:6] = [len(data), len(names)]
    data.extend(names)
    rows.append([name_index, 1, 0, 0, len(data), len(payload), 0, 0, 1, 0])
    data.extend(payload)
    data.extend(b'\0' * (-len(data) % 8))
    struct.pack_into(order + word, data, 40 if wide else 32, len(data))
    struct.pack_into(order + 'H', data, 60 if wide else 48, len(rows))
    for row in rows:
        data.extend(struct.pack(fmt, *row))
    return data


def entries(wide, order):
    pack = lambda fmt, *values: struct.pack(order + fmt, *values)
    # GNU CIE followed by an FDE covering the fixture's four text bytes.
    cie = pack('I', 0) + bytes([1, 0, 1, 0x7c, 31, 0x0d, 29, 0])
    cie = pack('I', len(cie)) + cie
    fde = pack('I' + ('QQ' if wide else 'II'), len(cie) + 4, 0x1000, 4)
    return cie + pack('I', len(fde)) + fde


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', type=Path)
    parser.add_argument('--previous-tool', type=Path)
    args = parser.parse_args()
    root = source.parents[2] / 'build/test-results/dwarfdump-eh-terminators'
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='run.', dir=root))
    summary = {'positives': [], 'negatives': [], 'previousReproductions': []}
    tools = [args.tool.resolve(strict=True)]
    if args.previous_tool:
        tools.append(args.previous_tool.resolve(strict=True))
    inputs = [*tools, Path(__file__).resolve(), source / 'dwarfdump-extended-programs.py',
        source / 'check-dwarfdump.py']
    for tool in tools:
        bundle = tool.parent.parent
        inputs.extend(path for path in (bundle / 'libexec/dwarfdump',
            bundle / 'BUILD-METADATA.txt', bundle / 'SHA256SUMS',
            bundle / 'share/dwarfdump/dwarfdump.conf') if path.is_file())
    protected = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}

    def check(label, data, positive, tool=tools[0]):
        path = work / (label + '.elf')
        path.write_bytes(data)
        log = work / (label + '.log')
        run = subprocess.run([sys.executable, source / 'check-dwarfdump.py', path, log,
            '--tool', tool], capture_output=True, text=True, timeout=30)
        (work / (label + '.runner.log')).write_text(run.stdout + run.stderr)
        metadata = json.loads(Path(str(log) + '.check.json').read_text())
        assert (run.returncode == 0 and metadata['status'] == 'PASS') == positive, (label, run.stdout, run.stderr)
        if not positive:
            assert metadata['status'] == 'FAILED' and 'DW_DLE_' in log.read_text(), label
        assert path.read_bytes() == data, label
        summary['positives' if positive else 'negatives'].append(label)

    for wide in (False, True):
        for order in ('<', '>'):
            label = ('elf64' if wide else 'elf32') + ('-le' if order == '<' else '-be')
            for kind, payload in [('empty', bytes(4)), ('padded', bytes(8)),
                    ('entries', entries(wide, order) + bytes(4)),
                    ('stop-before-unused-tail', bytes(4) + b'ignored-after-terminator')]:
                data = framed(wide, order, '.eh_frame', payload)
                check(label + '-' + kind, data, True)
                if args.previous_tool and wide and order == '>' and kind in ('empty', 'entries'):
                    check(label + '-' + kind + '-previous', data, False, tools[1])
                    summary['previousReproductions'].append(label + '-' + kind)
            for count in (1, 2, 3):
                check(label + '-short-' + str(count), framed(wide, order, '.eh_frame', bytes(count)), False)
                check(label + '-short-tail-' + str(count),
                    framed(wide, order, '.eh_frame', entries(wide, order) + bytes(count)), False)
            for kind, payload in [('nonzero', struct.pack(order + 'I', 8)),
                    ('extended', bytes([255]) * 4), ('truncated-entry', entries(wide, order)[:-1])]:
                check(label + '-' + kind, framed(wide, order, '.eh_frame', payload), False)
    # A four-byte prefix cannot introduce an IRIX eight-byte .debug_frame length.
    check('irix-short-debug-frame', framed(True, '>', '.debug_frame', bytes(4)), False)
    # Preserve the historical unmarked eight-byte IRIX .debug_frame format.
    cie = bytes([255]) * 8 + bytes([1, 0, 1, 0x7c, 31, 0x0d, 29, 0])
    cie = struct.pack('>Q', len(cie)) + cie
    fde = struct.pack('>QQQ', 0, 0x1000, 4)
    irix = framed(True, '>', '.debug_frame', cie + struct.pack('>Q', len(fde)) + fde)
    check('irix-valid-debug-frame', irix, True)
    if args.previous_tool:
        check('irix-valid-debug-frame-previous', irix, True, tools[1])
    assert protected == {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    summary['status'] = 'PASS'
    summary['tools'] = protected
    (work / 'result.json').write_text(json.dumps(summary, indent=4) + '\n')
    print('dwarfdump-eh-terminators=PASS', work)


if __name__ == '__main__':
    main()
