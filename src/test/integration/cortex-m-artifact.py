#!/usr/bin/env python3
"""Independent exact Cortex-M ELF/DWARF address checks against compiler fixture facts."""
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess

HERE = Path(__file__).resolve().parent
facts = runpy.run_path(str(HERE / 'dynamic-parameter-storage-check.py'))


def records(text):
    rows = []
    for line in text.splitlines():
        match = re.match(r'\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+ \((DW_TAG_\w+)\)', line)
        if match:
            rows.append({'depth': int(match[1]), 'tag': match[3], 'attrs': {}})
        elif rows:
            match = re.match(r'\s*<([0-9a-f]+)>\s+(DW_AT_\w+)\s*:\s*(.*)', line)
            if match:
                rows[-1]['attrs'][match[2]] = {'offset': int(match[1], 16), 'text': match[3]}
    return rows


def name(row):
    return row['attrs'].get('DW_AT_name', {}).get('text', '').rsplit(': ', 1)[-1].removeprefix('(string) ')


def number(attribute, form):
    match = re.fullmatch(r'\((?:' + form + r')\) (0x[0-9a-f]+|\d+)', attribute['text'])
    assert match, attribute
    return int(match[1], 0)


def inspect(case, sidecar, output):
    output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((case / 'curation.json').read_text())
    original, artifact = (facts['elf'](path) for path in (case / 'original.elf', sidecar))
    assert original['header'][:4] == artifact['header'][:4]
    assert original['header'][6] == artifact['header'][6] == 0x05000200
    assert artifact['header'][4] == artifact['header'][8] == artifact['header'][9] == 0
    for section in ('.vectors', '.text', '.data', '.bss', '.note.gnu.build-id', '.ARM.attributes'):
        old, new = original['sections'][section], artifact['sections'][section]
        assert old[0][1:] == new[0][1:] and old[1] == new[1], 'target section changed: ' + section
    text = subprocess.check_output(['readelf', '-W', '--debug-dump=info', sidecar], text=True)
    (output / 'info.txt').write_text(text)
    dies = records(text)
    functions = {name(row): row for row in dies if row['tag'] == 'DW_TAG_subprogram'}
    assert len(functions) == sum(row['tag'] == 'DW_TAG_subprogram' for row in dies) == 8
    assert functions.keys() == {row['name'] for row in manifest['functions']}
    mode_symbols = [row for row in artifact['symbols'] if row['info'] & 15 == 2]
    modes = {row['address'] & ~1: row for row in mode_symbols}
    assert len(modes) == len(mode_symbols) == 8
    for expected in manifest['functions']:
        row = functions[expected['name']]
        start = number(row['attrs']['DW_AT_low_pc'], 'addr')
        end = start + number(row['attrs']['DW_AT_high_pc'], 'data[1248]|udata')
        assert [start, end] == expected['ranges'][0], ('function body changed', expected, start, end)
        assert start == expected['entry'] and not start & 1 and not end & 1
        assert modes[start]['address'] == start | 1 and modes[start]['size'] == end - start
        assert all(end <= low or start >= high for low, high in manifest['literalPools'])
    globals_ = {name(row): row for row in dies if row['tag'] == 'DW_TAG_variable' and row['depth'] == 1}
    assert len(globals_) == sum(row['tag'] == 'DW_TAG_variable' and row['depth'] == 1 for row in dies)
    objects = {row['name']: row for row in manifest['objects']}
    objects['cortex_vectors'] = {'address': 0, 'size': 64}
    assert globals_.keys() == objects.keys()
    for symbol, expected in objects.items():
        location = globals_[symbol]['attrs']['DW_AT_location']
        match = re.fullmatch(r'\(exprloc\) 5 byte block: [0-9a-f ]+\s*\(DW_OP_addr: ([0-9a-f]+)\)', location['text'])
        assert match and int(match[1], 16) == expected['address'], ('data address changed', symbol, location)
    assert objects['cortex_odd_byte']['address'] & 1
    lines = subprocess.check_output(['readelf', '--debug-dump=decodedline', sidecar], text=True)
    (output / 'lines.txt').write_text(lines)
    rows = []
    boundaries = set()
    for line in (case / 'disassembly.log').read_text().splitlines():
        fields = line.split('\t')
        if len(fields) >= 3 and re.fullmatch(r'\s*[0-9a-f]+:', fields[0]) and \
                re.fullmatch(r'[0-9a-f]{4}(?: [0-9a-f]{4})?\s*', fields[1]):
            boundaries.add(int(fields[0].strip()[:-1], 16))
    assert boundaries
    for line in lines.splitlines():
        match = re.match(r'^firmware\.dbg\.c\s+(\d+|-)\s+0x([0-9a-f]+)', line)
        if not match or match[1] == '-':
            continue
        address = int(match[2], 16)
        assert not address & 1, 'tagged instruction row'
        assert address in boundaries, 'source row inside an instruction'
        assert any(low <= address < high for f in manifest['functions'] for low, high in f['ranges']), 'row outside function bodies'
        assert all(not low <= address < high for low, high in manifest['literalPools']), 'literal-pool source row'
        rows.append({'address': address, 'line': int(match[1])})
    assert rows and {f['entry'] for f in manifest['functions']} <= {r['address'] for r in rows}
    result = {'status': 'PASS', 'functions': len(functions), 'globals': len(globals_),
        'lineRows': len(rows), 'oddDataAddress': objects['cortex_odd_byte']['address']}
    (output / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    return artifact, dies, result


def line_addresses(data):
    """Offsets of actual DW_LNE_set_address operands, skipping declared opcode operands."""
    assert struct.unpack_from('<H', data, 4)[0] == 5 and data[6:8] == bytes((4, 0))
    assert struct.unpack_from('<I', data)[0] + 4 == len(data)
    position = 12 + struct.unpack_from('<I', data, 8)[0]
    base = data[17]
    lengths = data[18:18 + base - 1]

    def leb():
        nonlocal position
        value, shift = 0, 0
        while True:
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
            shift += 7
            assert shift < 64

    offsets = []
    while position < len(data):
        opcode = data[position]
        position += 1
        if opcode == 0:
            length = leb()
            assert length > 0 and position + length <= len(data)
            if data[position] == 2:
                assert length == 5
                offsets.append(position + 1)
            position += length
        elif opcode == 9:
            position += 2
        elif opcode < base:
            for _ in range(lengths[opcode - 1]):
                leb()
    assert position == len(data) and offsets
    return offsets
