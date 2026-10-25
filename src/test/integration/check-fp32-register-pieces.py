#!/usr/bin/env python3
"""Check explicit FP32 register pieces in target object-memory order."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

artifact, target = sys.argv[1:]
assert target in ('mips32be', 'mips32le')
spec = importlib.util.spec_from_file_location('facts', Path(__file__).with_name('dynamic-composite-storage-check.py'))
facts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(facts)
result = subprocess.run(['readelf', '--debug-dump=info', artifact],
    capture_output=True, text=True, check=True, timeout=60)
assert not result.stderr
records = facts.die_records(result.stdout)
by_offset = {row['offset']: row for row in records}
function, = [row for row in records if row['tag'] == 'DW_TAG_subprogram' and facts.facts.die_name(row) == 'fp_double']
parameters = [row for row in facts.children(records, records.index(function)) if row['tag'] == 'DW_TAG_formal_parameter']
assert len(parameters) == 2
observed = {}
for parameter, name, high, low in zip(parameters, ('first', 'second'), (45, 47), (44, 46)):
    assert facts.facts.die_name(parameter) == name
    ref = int(re.fullmatch(r'<0x([0-9a-f]+)>', parameter['attrs']['DW_AT_type'])[1], 16)
    dtype = by_offset[ref]
    assert dtype['tag'] == 'DW_TAG_base_type' and dtype['attrs']['DW_AT_byte_size'] == '8'
    assert 'float' in dtype['attrs']['DW_AT_encoding']
    data = re.fullmatch(r'10 byte block: ([0-9a-f ]+)\s+\(.*\)', parameter['attrs']['DW_AT_location'])
    assert data, parameter
    order = (high, low) if target == 'mips32be' else (low, high)
    # DW_OP_regx plus a 32-bit, zero-offset DW_OP_bit_piece for each carrier.
    expected = bytes(byte for register in order for byte in (0x90, register, 0x9d, 32, 0))
    assert bytes(int(byte, 16) for byte in data[1].split()) == expected
    observed[name] = {'registersInMemoryOrder': order, 'pieceBits': 32, 'pieceBitOffset': 0}
print(json.dumps({'status': 'FP32_REGISTER_PIECES_PASS', 'parameters': observed}, indent=4))
