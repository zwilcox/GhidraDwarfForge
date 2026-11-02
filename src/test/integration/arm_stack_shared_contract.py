"""Audited LE ARM DSO prefixes and independently bound GOT relocations."""
import struct

PREFIXES = {
    'pair': 'e24dd008 e92d4830 e28db00c e1a0e000 e1a0c001 e58b3008 e59b4010 e59f308c e08f3003 e59f1088 e7931001 e5810000 e581c004 e5812008 e59f1078 e7931001 e1a05001 e28b1008 e8910003 e8850003 e59f1064 e7933001 e5834000',
    'aligned': 'e92d48f0 e28db014 e1a0e000 e1a0c001 e1a05002 e59b6014 e59f409c e08f4004 e59f3098 e7943003 e5830000 e5831004 e5832008 e59f3088 e7943003 e1a07003 e99b000f e887000f e59f3078 e7943003 e5836000',
    'packed': 'e24dd008 e92d4830 e28db00c e1a0c000 e1a00003 e58b3008 e59b5010 e59fe090 e08fe00e e59f308c e79e4003 e584c000 e5841004 e5842008 e59f307c e79e4003 e5840000 e5db300c e5c43004 e59f306c e79e3003 e5835000',
    'bytes': 'e92d4830 e28db00c e24dd008 e50b3010 e59be004 e59f3094 e08f3003 e59fc090 e793c00c e58c0000 e58c1004 e58c2008 e59fc080 e793c00c e15b51b0 e55b400e e1cc50b0 e5cc4002 e59fc06c e793300c e583e000',
    'words': 'e24dd008 e92d4870 e28db010 e1a0e000 e1a0c001 e1a04002 e58b3008 e59b5014 e59f309c e08f3003 e59f2098 e7932002 e5820000 e5821004 e5824008 e59f2088 e7932002 e1a06002 e28b2008 e8920007 e8860007 e59f2074 e7933002 e5835000',
    'mixed': 'e92d48f0 e28db014 e1a0e000 e1a0c001 e1a05002 e59b6014 e59f40a4 e08f4004 e59f30a0 e7943003 e5830000 e5831004 e5832008 e59f3090 e7943003 e1a07003 e99b000f e887000f e59f3080 e7943003 e5836000',
    'base_floats': 'e52db004 ed2d8b02 e28db008 ec410b16 ec432b17 ed9b4b01 ed9b5b03 ed9b1b05 ed9b2b07 ed9b3b09 eddb0a0e e59fc164 e08fc00c e59f3160 e79c3003 e1c300f0 ed837b02 ed834b04 ed835b06 ed831b08 ed832b0a ed833b0c e59f3140 e79c3003 e28b202c e8920007 e8830007 e59f3130 e79c3003 edc30a00',
    'vfp_floats': 'e52db004 ed2d8b02 e28db008 eddb7a04 e59fc160 e08fc00c e59f315c e79c3003 ed830b00 ed831b02 ed832b04 ed833b06 ed834b08 ed835b0a ed836b0c e59f313c e79c3003 e99b0007 e8830007 e59f3130 e79c3003 edc37a00',
}


def prefix(function):
    pcs, kind = function.split('_')
    assert pcs in ('base', 'vfp')
    return b''.join(int(word, 16).to_bytes(4, 'little')
        for word in PREFIXES[function if kind == 'floats' else kind].split())


def pool_offset(function):
    pcs, kind = function.split('_')
    assert pcs in ('base', 'vfp')
    return {'pair': 176, 'aligned': 188, 'packed': 180, 'bytes': 176,
        'words': 196, 'mixed': 196, 'floats': 408 if pcs == 'base' else 376}[kind]


def validate_prefix(function, code, observe, entry, got, symbols, memory):
    expected = prefix(function)
    assert code[:observe] == expected and observe == len(expected), (function, 'changed shared prefix')
    pool = pool_offset(function)
    assert len(code) == pool + 16, (function, 'changed shared pool bounds')
    loads = [(offset, int.from_bytes(code[offset:offset + 4], 'little')) for offset in range(0, observe, 4)
        if int.from_bytes(code[offset:offset + 4], 'little') & 0xffff0000 == 0xe59f0000]
    assert [offset + 8 + (word & 4095) for offset, word in loads] == list(range(pool, pool + 16, 4))
    values = struct.unpack_from('<4I', code, pool)
    assert (entry + loads[0][0] + 12 + values[0]) & 0xffffffff == got, (function, 'wrong shared GOT base')
    kind = function.split('_')[1]
    targets = ('seen_doubles', 'seen_floats', 'seen_float_tail') if kind == 'floats' else ('seen_leading', 'seen_' + kind, 'seen_tail')
    slots = []
    for offset, name in zip(values[1:], targets):
        slot = got + offset
        assert offset >= 12 and offset % 4 == 0
        assert int.from_bytes(memory(slot, 4), 'little') == symbols[name], (function, name, 'wrong shared GOT target')
        slots.append({'slot': slot, 'symbol': name, 'address': symbols[name]})
    return slots


def expects_gap(function, order, offset, expression, layout='shared'):
    assert order == 'little' and layout == 'shared' and offset >= 0 and offset % 4 == 0
    assert function.split('_')[0] in ('base', 'vfp')
    kind = function.split('_')[1]
    assert kind in ('pair', 'aligned', 'packed', 'bytes', 'words', 'mixed', 'floats')
    # Unknown global stores retire the mixed register/stack backup. The
    # three-byte object's r3 copy was already overwritten by the GOT base.
    boundary = {'pair': 48, 'packed': 48, 'bytes': 40, 'words': 52}.get(kind)
    return expression.startswith('value.') and boundary is not None and offset >= boundary
