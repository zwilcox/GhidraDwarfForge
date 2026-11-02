"""Audited GCC pre-state defects, corroborated by live ABI carriers.

These windows apply only to the compiler reference. Every instruction that
preserves a substitute carrier is checked; changed code fails closed. ARM and
BE8 both encode the tested ARM instructions in little-endian byte order.
"""
import struct
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('prefix_contract', Path(__file__).with_name('arm_stack_aggregate_contract.py'))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


PREFIXES = {
    'pair': (0xe24dd008, 0xe92d4830, 0xe28db00c, 0xe1a0e000, 0xe1a0c001, 0xe58b3008),
    'packed': (0xe24dd008, 0xe92d4810, 0xe28db008, 0xe1a0e000, 0xe1a0c001, 0xe58b3008),
    'words': (0xe24dd008, 0xe92d4870, 0xe28db010, 0xe1a0e000, 0xe1a0c001, 0xe1a04002, 0xe58b3008),
    'bytes-little': (0xe92d4800, 0xe28db004, 0xe24dd008, 0xe1a0e003, 0xe50b3008),
    'bytes-big': (0xe92d4830, 0xe28db00c, 0xe24dd008, 0xe50b3010),
}
FLOAT_PREFIX = (
    0xe52db004, 0xed2d8b02, 0xe28db008, 0xec410b16, 0xec432b17,
    0xed9b4b01, 0xed9b5b03, 0xed9b1b05, 0xed9b2b07, 0xed9b3b09,
    0xeddb0a0e, 0xe3003000, 0xe3403000, 0xe1c305f0, 0xed837b16,
    0xed834b18, 0xed835b1a, 0xed831b1c, 0xed832b1e, 0xed833b20,
    0xe283c088, 0xe28b202c,
)


def window(function, offset, order, code, layout='exec', entry=None, global_address=None):
    """Return the exact affected fields and carrier kind, without reading DWARF."""
    if order not in ('little', 'big') or layout not in ('exec', 'pie') or offset < 0 or offset % 4:
        return None
    if function == 'base_floats' and 48 <= offset <= 84:
        if layout == 'pie':
            # The audited PIC load/add writes only r3, leaving the proven d7
            # copy intact. Check its literal target too, not just opcode masks.
            try:
                contract.validate_prefix(function, order, code, 100, global_address, layout, entry)
            except (AssertionError, TypeError):
                return None
            return {'kind': 'double', 'fields': ('b',),
                'reason': 'GCC keeps b in overwritten r2/r3 after its exact copy to d7'}
        words = list(FLOAT_PREFIX)
        if order == 'big':
            words[3:5] = (0xec401b16, 0xec423b17)
        if len(code) < len(words) * 4:
            return None
        for index, expected in enumerate(words):
            actual = int.from_bytes(code[index * 4:index * 4 + 4], 'little')
            # Only the relocated literal differs. Opcode and r3 destination
            # remain exact; neither MOVW nor MOVT writes the surviving d7.
            mask = 0xfff0f000 if index in (11, 12) else 0xffffffff
            if actual & mask != expected:
                return None
        return {'kind': 'double', 'fields': ('b',),
            'reason': 'GCC keeps b in overwritten r2/r3 after its exact copy to d7'}
    pcs, separator, kind = function.partition('_')
    if not separator or pcs not in ('base', 'vfp') or kind not in ('pair', 'packed', 'words', 'bytes'):
        return None
    prefix = PREFIXES[kind + '-' + order if kind == 'bytes' else kind]
    if layout == 'pie' and kind == 'bytes' and order == 'big':
        prefix = (0xe92d4830, 0xe28db00c, 0xe24dd008, 0xe1a0c003, 0xe50b3010)
    expected = b''.join(word.to_bytes(4, 'little') for word in prefix)
    if offset >= len(expected) or code[:len(expected)] != expected:
        return None
    fields = {'pair': ('value.first',), 'packed': ('value.first', 'value.second'),
        'words': ('value.items[0]',), 'bytes': ('value.first', 'value.second', 'value.third')}
    return {'kind': kind, 'fields': fields[kind],
        'reason': 'GCC names the aggregate stack home before the r3 store executes'}


def carriers(proof, order, register, memory, entry_sp):
    """Read current physical carriers, never a cached entry or expected value."""
    endian = '<' if order == 'little' else '>'
    if proof['kind'] == 'double':
        return {'b': struct.unpack(endian + 'd', register('d7'))[0]}
    kind = proof['kind']
    size, layout, names = {
        'pair': (8, 'ii', ('first', 'second')),
        'packed': (5, 'BI', ('first', 'second')),
        'words': (12, 'iii', ('items[0]', 'items[1]', 'items[2]')),
        'bytes': (3, 'BBB', ('first', 'second', 'third')),
    }[kind]
    payload = (register('r3') + (memory(entry_sp, size - 4) if size > 4 else b''))[:size]
    return dict(zip(('value.' + name for name in names), struct.unpack(endian + layout, payload)))
