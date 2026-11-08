"""Source-known values and independently decoded MIPS N32/N64 fixture contracts."""
import struct

EXPECTED = {
    'wide_words': dict(zip('abcdefghij', (11, 22, 33, 44, 55, 66, 77, 88, 909, -1010))),
    'wide_pair': {'value.first': 101, 'value.second': -202},
    'wide_large': {'value.first': 303, 'value.second': -404, 'value.third': 505},
    'wide_mixed': {'a': 17, 'b': 1.25, 'c': -19, 'd': -2.5, 'e.first': 101,
        'e.second': -202, 'f': 23, 'g': 3.75, 'h': 29, 'tail': -31}}
RETURNS = {'wide_words': 295, 'wide_pair': {'first': 101, 'second': -202},
    'wide_large': {'first': 303, 'second': -404, 'third': 505}, 'wide_mixed': -82}
AGGREGATES = {'wide_pair': ('value', (4, 5)), 'wide_large': ('value', (5, 6, 7)),
    'wide_mixed': ('e', (8, 9))}


def signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def entry_arguments(function, register, memory, endian, pointer_bytes):
    """register yields integer bit patterns; memory yields target-order bytes."""
    def word(number):
        return signed(register(number), 64)

    def real(number, width):
        bits = register(32 + number) & ((1 << (width * 8)) - 1)
        return struct.unpack('<f' if width == 4 else '<d', bits.to_bytes(width, 'little'))[0]

    address = register(29) & ((1 << (pointer_bytes * 8)) - 1)
    def stack(offset, width):
        return int.from_bytes(memory(address + offset, width), endian, signed=True)

    if function == 'wide_words':
        return dict(zip('abcdefghij', [word(i) for i in range(4, 12)] + [stack(0, 8), stack(8, 8)]))
    if function in ('wide_pair', 'wide_large'):
        return dict(zip(EXPECTED[function], [word(i) for i in AGGREGATES[function][1]]))
    if function == 'wide_mixed':
        return {'a': word(4), 'b': real(13, 8), 'c': signed(register(6), 32), 'd': real(15, 4),
            'e.first': word(8), 'e.second': word(9), 'f': word(10), 'g': real(19, 8),
            'h': stack(0, 8), 'tail': stack(12 if endian == 'big' else 8, 4)}
    raise ValueError(function)


def contract(function, code, endian, home_offset=None):
    """Fail closed on missing clobbers, altered homes, or an unrecognized epilogue."""
    assert code and len(code) % 4 == 0
    words = [int.from_bytes(code[i:i + 4], endian) for i in range(0, len(code), 4)]
    assert words[-2] == 0x03e00008, (function, 'not an audited delayed return')
    clobbers = {}
    for name, opcode in ({'a': 0x0085202d} if function == 'wide_words' else
            {'c': 0x00c4302d, 'd': 0x46007be1} if function == 'wide_mixed' else {}).items():
        offsets = [index * 4 + 4 for index, word in enumerate(words) if word == opcode]
        assert len(offsets) == 1, (function, name, offsets)
        clobbers[name] = offsets[0]
    adjusts = [(index * 4, signed(word, 16)) for index, word in enumerate(words)
        if word >> 26 in (9, 25) and (word >> 21) & 31 == 29 and (word >> 16) & 31 == 29]
    frame = 0
    if function != 'wide_words':
        assert len(adjusts) == 2 and adjusts[0][0] == 0 and adjusts[0][1] < 0
        frame = -adjusts[0][1]
        assert adjusts[1] == (len(code) - 4, frame), (function, adjusts)
    else:
        assert not adjusts and words[-1] == 0
    homes = {}
    if home_offset is not None:
        parameter, registers = AGGREGATES[function]
        for field, number in enumerate(registers):
            offset = frame + home_offset + field * 8
            assert 0 <= offset <= frame - 8
            opcode = (63 << 26) | (29 << 21) | (number << 16) | offset
            matches = [index * 4 + 4 for index, word in enumerate(words) if word == opcode]
            assert len(matches) == 1 and matches[0] < len(code) - 8, (function, number, matches)
            key = parameter + '.' + ('first', 'second', 'third')[field]
            homes[key] = {'complete': matches[0], 'entryOffset': home_offset + field * 8,
                'register': number}
    return {'size': len(code), 'clobbers': clobbers, 'homes': homes, 'frame': frame,
        'returnOffset': len(code) - 8}


def reference_window(function, expression, offset, proof):
    if offset < 0 or offset % 4 or offset >= proof['size']:
        return None
    home = proof['homes'].get(expression)
    if home is not None and 0 <= offset < home['complete']:
        return 'compiler names aggregate home before its store executes'
    if function == 'wide_mixed' and expression in ('h', 'tail') and offset == proof['returnOffset']:
        return 'compiler switches to restored stack pointer before delayed adjustment executes'
    return None
