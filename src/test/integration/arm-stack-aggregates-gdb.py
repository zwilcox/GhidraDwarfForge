"""Independent entry bytes and instruction-by-instruction typed aggregate observations."""
import gdb
import importlib.util
import json
import os
from pathlib import Path
import re
import struct

case = Path(os.environ['FORGE_PCS_CASE'])
variant = os.environ['FORGE_PCS_VARIANT']
profile = json.loads((case / 'profile.json').read_text())
order = profile['order']
endian = '<' if order == 'little' else '>'
expected = {
    'pair': {'first': 17, 'second': -23},
    'aligned': {'first': 0x1122334455667788, 'second': -23},
    'packed': {'first': 0x91, 'second': 0x23456789},
    'bytes': {'first': 0x91, 'second': 0xa2, 'third': 0xb3},
    'words': {'items[0]': 17, 'items[1]': -23, 'items[2]': 31},
    'mixed': {'first': 1.25, 'second': 0x1122334455667788},
    'floats': {'first': 1.25, 'second': 2.5, 'third': 4.75},
}
layouts = {'pair': ('ii', 8), 'aligned': ('Qi4x', 16), 'packed': ('BI', 5),
    'bytes': ('BBB', 3), 'words': ('iii', 12), 'mixed': ('f4xQ', 16), 'floats': ('fff', 12)}
result = {'status': 'STARTED', 'variant': variant, 'entry': [], 'observations': [],
    'mismatches': [], 'referenceWindows': [], 'referenceMismatches': []}
calibrate = variant == 'compiler' and os.environ.get('FORGE_STACK_REFERENCE_CALIBRATION') == '1'
spec = importlib.util.spec_from_file_location('reference', Path(__file__).with_name('arm-stack-aggregates-reference.py'))
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def integer(expression):
    return int(gdb.parse_and_eval(expression))


def memory(address, size):
    return gdb.selected_inferior().read_memory(address, size).tobytes() if size else b''


def register_bytes(index):
    return (integer('$r' + str(index)) & 0xffffffff).to_bytes(4, order)


def raw_entry(name, pcs, kind):
    stack = integer('$sp')
    if kind == 'floats':
        if pcs == 'vfp':
            leading = [struct.unpack(endian + 'd', gdb.parse_and_eval('$d' + str(i)).bytes)[0] for i in range(7)]
            offset = 0
        else:
            leading = [struct.unpack(endian + 'd', register_bytes(2*i) + register_bytes(2*i+1))[0] for i in range(2)]
            leading += list(struct.unpack(endian + 'ddddd', memory(stack, 40)))
            offset = 40
        assert leading == list(range(1, 8)), (name, leading)
        payload = memory(stack + offset, 12)
        tail = struct.unpack(endian + 'f', memory(stack + offset + 12, 4))[0]
        assert tail == -8.5
    else:
        assert [integer('$r' + str(i)) for i in range(3)] == [7, 11, 13]
        size = layouts[kind][1]
        if kind in ('aligned', 'mixed'):
            payload = memory(stack, size)
            offset = size
        else:
            payload = (register_bytes(3) + memory(stack, max(0, size - 4)))[:size]
            offset = max(0, ((size + 3) // 4 - 1) * 4)
        tail = struct.unpack(endian + 'i', memory(stack + offset, 4))[0]
        assert tail == -41, (name, tail, offset)
    fields = list(struct.unpack(endian + layouts[kind][0], payload))
    assert fields == list(expected[kind].values()), (name, fields)
    return {'name': name, 'stack': stack, 'bytes': payload.hex(), 'fields': fields, 'tail': tail}


try:
    gdb.execute('target remote ' + os.environ['FORGE_PCS_REMOTE'])
    vdso = re.search(r'AT_SYSINFO_EHDR.*?(0x[0-9a-f]+)', gdb.execute('info auxv', to_string=True))
    if vdso:
        result['vdsoAddress'] = int(vdso[1], 16)
        result['vdsoMemory'] = memory(result['vdsoAddress'], 4096).hex()
    for pcs in ('base', 'vfp'):
        for kind in expected:
            name = pcs + '_' + kind
            entry = integer('&' + name)
            observe = json.loads((case / 'labels.json').read_text())[name + '_observe'] if (case / 'labels.json').exists() else integer('&' + name + '_observe')
            stop = gdb.Breakpoint('*' + hex(entry))
            gdb.execute('continue')
            stop.delete()
            result['entry'].append(raw_entry(name, pcs, kind))
            return_pc = integer('$lr') & ~1
            return_type = gdb.parse_and_eval(name).type.target()
            wanted = {'value.' + field: value for field, value in expected[kind].items()}
            wanted.update(dict(zip('abcdefg' if kind == 'floats' else 'abc', range(1, 8) if kind == 'floats' else (7, 11, 13))))
            wanted['tail'] = -8.5 if kind == 'floats' else -41
            code = memory(entry, observe - entry)
            for step in range(200):
                pc = integer('$pc')
                row = {'name': name, 'offset': pc-entry, 'atObserve': pc == observe, 'fields': {}}
                proof = reference.window(name, pc-entry, order, code) if calibrate else None
                if proof:
                    raw = reference.carriers(proof, order,
                        lambda name: register_bytes(3) if name == 'r3' else gdb.parse_and_eval('$' + name).bytes,
                        memory, result['entry'][-1]['stack'])
                    for expression, value in raw.items():
                        assert value == wanted[expression], (name, pc-entry, expression, value, wanted[expression])
                    result['referenceWindows'].append({'name': name, 'offset': pc-entry,
                        'reason': proof['reason'], 'raw': raw})
                for expression, value in wanted.items():
                    mismatch = None
                    try:
                        actual = gdb.parse_and_eval(expression)
                        observed = float(actual) if isinstance(value, float) or kind == 'floats' and expression in 'abcdefg' else int(actual)
                        row['fields'][expression] = observed
                        if observed != value:
                            mismatch = {'name': name, 'offset': pc-entry, 'expression': expression, 'expected': value, 'actual': observed}
                    except (gdb.error, ValueError) as error:
                        row['fields'][expression] = {'error': str(error)}
                        mismatch = {'name': name, 'offset': pc-entry, 'expression': expression, 'expected': value, 'error': str(error)}
                    if mismatch:
                        if proof and expression in proof['fields']:
                            result['referenceMismatches'].append({**mismatch, 'reason': proof['reason'], 'raw': raw[expression]})
                        else:
                            result['mismatches'].append(mismatch)
                result['observations'].append(row)
                if pc == observe:
                    for field, value in expected[kind].items():
                        actual = gdb.parse_and_eval('seen_' + kind + '.' + field)
                        assert (float(actual) if isinstance(value, float) else int(actual)) == value
                    break
                gdb.execute('stepi', to_string=True)
            else:
                raise AssertionError('did not reach observation label: ' + name)
            stop = gdb.Breakpoint('*' + hex(return_pc))
            gdb.execute('continue')
            stop.delete()
            assert integer('$pc') == return_pc
            assert int(gdb.parse_and_eval('$r0').cast(return_type)) == 1
    gdb.execute('continue')
    assert integer('$_exitcode') == 0
    result['status'] = 'PASS' if not result['mismatches'] else 'REFERENCE_MISMATCH' if variant == 'compiler' else 'FORGE_MISMATCH'
    assert not result['mismatches'], str(len(result['mismatches'])) + ' typed observations disagree'
except BaseException as error:
    if result['status'] == 'STARTED':
        result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')
