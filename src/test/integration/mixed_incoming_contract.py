"""Independent instruction and storage contract for the ARM split-pair fixture."""
import struct


def expected_code(pie, entry, global_address):
    if pie:
        address_words = [0xe59f3018, 0xe08f3003]
    else:
        low, high = global_address & 0xffff, global_address >> 16
        address_words = [0xe3003000 | (low & 0xfff) | ((low & 0xf000) << 4),
            0xe3403000 | (high & 0xfff) | ((high & 0xf000) << 4)]
    words = [0xe24dd008, 0xe58d3004, *address_words, 0xe59d2004, 0xe5832000,
        0xe59d2008, 0xe5832004, 0xe28dd008, 0xe12fff1e]
    if pie:
        words.append((global_address - entry - 20) & 0xffffffff)
    return struct.pack('<' + 'I' * len(words), *words)


def validate_code(code, pie, entry, global_address):
    assert code == expected_code(pie, entry, global_address), 'mixed incoming instruction/address bytes changed'


def location_rows(entry):
    register = lambda number: f'DW_OP_regx: {number} (r{number})'
    stack = lambda offset: f'DW_OP_bregx: 13 (r13) {offset}'
    piece = '; DW_OP_bit_piece: size: 32 offset: 0 '
    return [(entry + begin, entry + end, '(' + low + piece + '; ' + stack(high) + piece + ')')
        for begin, end, low, high in ((0, 4, register(3), 0), (4, 12, register(3), 8),
            (12, 20, stack(4), 8), (20, 24, register(2), 8))]
