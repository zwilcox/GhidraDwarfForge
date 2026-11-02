"""FR=1 O32 compiler values and the exporter's honest unsupported-pair omission."""
import json
import os
from pathlib import Path
import struct

import gdb

case = Path(os.environ['MIPS_FPR_CASE'])
variant = os.environ['MIPS_FPR_VARIANT']
assert variant in ('compiler', 'forge')
metadata = json.loads((case / 'metadata.json').read_text())
order = 'big' if metadata['endian'] == 'be' else 'little'
format_prefix = '>' if order == 'big' else '<'
labels = json.loads((case / 'labels.json').read_text())
result = {'status': 'RUNNING', 'variant': variant, 'rows': []}


def integer(name):
    return int(gdb.parse_and_eval(name))


def raw_fpr(name, size):
    value = gdb.newest_frame().read_register(name)
    assert value.type.sizeof == 8, (name, value.type)
    raw = bytes(value.bytes)
    assert len(raw) == 8
    bits = int.from_bytes(raw, order)
    # Single-precision values occupy the low 32 bits; unused upper bits are
    # deliberately not assigned a value by the oracle.
    encoded = (bits & ((1 << (size * 8)) - 1)).to_bytes(size, order)
    return struct.unpack(format_prefix + ('f' if size == 4 else 'd'), encoded)[0], raw.hex()


try:
    for command in ('set pagination off', 'set confirm off', 'set debuginfod enabled off',
            'set auto-solib-add off'):
        gdb.execute(command)
    gdb.execute('file ' + str(case / ('reference' if variant == 'compiler' else 'original')))
    if variant == 'forge':
        gdb.execute('symbol-file ' + str(case / 'floating.dbg'))
    # The ELF uses O32/MIPS32r2 code on an actual MIPS64r2 CPU. Its legacy
    # remote packet has 64-bit GPR/FPR slots, independent of ELF pointer width.
    gdb.execute('set architecture mips:isa64r2')
    gdb.execute('set mips mask-address on')
    gdb.execute('target remote ' + os.environ['MIPS_FPR_SOCKET'])
    for function, expected, size in [('fp_float', [19.25, -7.5], 4), ('fp_double', [21.5, -9.25], 8)]:
        assert integer('&' + function) == labels[function]
        gdb.Breakpoint('*' + function, temporary=True)
        gdb.execute('continue')
        for marker in (function, function + '_before', function + '_after'):
            address = labels[marker]
            if integer('$pc') != address:
                gdb.Breakpoint('*' + hex(address), temporary=True)
                gdb.execute('continue')
            assert integer('$pc') == address
            assert integer('$sr') & (1 << 26), 'the reference requires actual FR=1'
            assert gdb.selected_frame().name() == function
            row = {'function': function, 'marker': marker, 'pc': address,
                'statusRegister': integer('$sr'), 'values': [], 'rawRegisters': []}
            for parameter, register, literal in zip(('first', 'second'), ('f12', 'f14'), expected):
                value = gdb.parse_and_eval(parameter)
                assert value.type.strip_typedefs().code == gdb.TYPE_CODE_FLT and value.type.sizeof == size
                raw, encoded = raw_fpr(register, size)
                assert raw == literal, (marker, register, raw, literal)
                unavailable = variant == 'forge' and function == 'fp_double'
                if unavailable:
                    assert value.is_optimized_out, ('unproven Ghidra pair was exported', marker, parameter, str(value))
                    row['values'].append(None)
                else:
                    assert not value.is_optimized_out and float(value) == literal, (marker, parameter, str(value))
                    row['values'].append(float(value))
                row['rawRegisters'].append({'register': register, 'bytes': encoded, 'value': raw})
            result['rows'].append(row)
        for suffix, literal in zip(('first', 'second'), expected):
            assert float(gdb.parse_and_eval(function + '_' + suffix)) == literal
        listing = gdb.execute('list ' + function, to_string=True)
        assert function in listing
        result[function + 'Listing'] = listing
        if variant == 'forge':
            assert gdb.selected_frame().find_sal().symtab.filename.endswith('floating.dbg.c')
    # Bare metal deliberately has no Linux exit syscall. The real main return
    # is checked before the startup code's terminal loop.
    gdb.Breakpoint('*' + hex(labels['reference_done']), temporary=True)
    gdb.execute('continue')
    assert integer('$pc') == labels['reference_done'] and integer('$v0') == 0
    result['mainReturn'] = 0
    result['status'] = 'PASS'
    gdb.execute('detach')
except BaseException as error:
    result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')
