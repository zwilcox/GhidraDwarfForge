"""Independent O32 four-byte slots and instruction-derived availability boundaries."""
import importlib.util
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location('wide_values', Path(__file__).with_name('mips-wide-arguments-oracle.py'))
values = importlib.util.module_from_spec(spec)
spec.loader.exec_module(values)
EXPECTED, RETURNS, signed = values.EXPECTED, values.RETURNS, values.signed


def entry_arguments(function, register, memory, endian, pointer_bytes, stack_pointer=None):
    assert pointer_bytes == 4 and endian in ('big', 'little')
    address = (register(29) if stack_pointer is None else stack_pointer) & 0xffffffff

    def scalar(slot, width=8, real=False):
        data = b''.join((register(4 + index) & 0xffffffff).to_bytes(4, endian)
            if index < 4 else memory(address + index * 4, 4)
            for index in range(slot, slot + width // 4))
        assert len(data) == width
        return struct.unpack(('>' if endian == 'big' else '<') + ('d' if width == 8 else 'f'), data)[0] \
            if real else int.from_bytes(data, endian, signed=True)

    if function == 'wide_words':
        return {name: scalar(index * 2) for index, name in enumerate(EXPECTED[function])}
    if function in ('wide_pair', 'wide_large'):
        # Slot zero carries the hidden result pointer; eight-byte alignment skips slot one.
        return {name: scalar(2 + index * 2) for index, name in enumerate(EXPECTED[function])}
    if function == 'wide_mixed':
        return {'a': scalar(0), 'b': scalar(2, real=True), 'c': scalar(4, 4),
            'd': scalar(5, 4, True), 'e.first': scalar(6), 'e.second': scalar(8),
            'f': scalar(10), 'g': scalar(12, real=True), 'h': scalar(14), 'tail': scalar(16, 4)}
    raise ValueError(function)


def contract(function, code, endian, home_offset=None):
    """Accept only the audited straight-line MIPS32r2 fixture instruction vocabulary."""
    assert function in EXPECTED and code and len(code) % 4 == 0
    words = [int.from_bytes(code[index:index + 4], endian) for index in range(0, len(code), 4)]
    assert words[-2] == 0x03e00008, 'missing delayed return'
    writes, stores, homes = {}, [], {}
    for index, word in enumerate(words):
        opcode, rs, rt, rd, subop = word >> 26, word >> 21 & 31, word >> 16 & 31, word >> 11 & 31, word & 63
        destination = None
        if word == 0 or word == 0x03e00008 and index == len(words) - 2:
            pass
        elif opcode == 0 and subop in (3, 33, 37, 43):
            destination = rd
        elif opcode in (9, 15, 35):
            destination = rt
        elif opcode in (43, 57, 61):
            stores.append((index * 4 + 4, rs, rt, signed(word, 16), opcode))
        elif opcode in (49, 53):
            pass
        elif opcode == 17 and (rs == 4 or rs in (16, 17) and subop in (0, 33)):
            pass
        else:
            raise AssertionError((function, index * 4, hex(word), 'unaudited instruction'))
        assert destination != 29, 'unexpected stack adjustment'
        if destination is not None:
            writes.setdefault(destination, index * 4 + 4)
    clobbers, last_piece = {}, {}
    carriers = {'a': (4, 5), 'b': (6, 7)} if function in ('wide_words', 'wide_mixed') else {}
    for name, registers in carriers.items():
        boundaries = [writes.get(number, len(code)) for number in registers]
        clobbers[name], last_piece[name] = min(boundaries), max(boundaries)
    if function in ('wide_pair', 'wide_large'):
        assert home_offset == 8
        complete = []
        for register, offset in ((6, 8), (7, 12)):
            matches = [pc for pc, base, value, displacement, opcode in stores
                if (base, value, displacement, opcode) == (29, register, offset, 43)]
            assert len(matches) == 1 and matches[0] <= len(code) - 8
            assert writes.get(register, len(code)) >= matches[0]
            complete.append(matches[0])
        homes['value.first'] = {'complete': max(complete)}
        assert all(register not in writes for register in (6, 7)), 'aggregate argument register clobbered'
    elif function == 'wide_mixed':
        assert home_offset == 24
    else:
        assert home_offset is None
    assert not any(base == 29 and offset >= 16 for _, base, _, offset, _ in stores), 'incoming stack value overwritten'
    return {'size': len(code), 'clobbers': clobbers, 'lastPiece': last_piece, 'homes': homes,
        'firstStore': min(row[0] for row in stores), 'returnOffset': len(code) - 8, 'endian': endian}


def unavailable(function, expression, offset, proof, mode):
    if mode == 'forge' and function in ('wide_pair', 'wide_large'):
        # The shared mixed-storage analysis deliberately stops at its first possible
        # memory write. This is a documented omission, not a claim of a live clobber.
        return offset >= proof['firstStore']
    return offset >= proof['clobbers'].get(expression, proof['size'])


def reference_window(function, expression, offset, proof):
    if offset < 0 or offset % 4 or offset >= proof['size']:
        return None
    home = proof['homes'].get(expression)
    if home and offset < home['complete']:
        return 'compiler names aggregate home before both word stores execute'
    if proof['endian'] == 'big' and proof['clobbers'].get(expression, proof['size']) <= offset < proof['lastPiece'].get(expression, 0):
        return 'compiler retains a register pair after its first word is overwritten'
    return None
