"""Source-owned ARM prefix contract, independent of Forge locations/diagnostics.

The natural functions store to globals before returning. A register-derived
address has no proven relation to the entry stack in the shared affine analysis.
It must therefore retire stack backups. This contract requires an explicit gap
where the last complete object proof is lost; it does not say the runtime bytes
must actually have changed. The separate full-availability probe is retained.
"""


PREFIXES = {
    'pair': 'e24dd008 e92d4830 e28db00c e1a0e000 e1a0c001 e58b3008 e59b5010 W3 T3 e5830000 e5831004 e5832008 e283400c e28b1008 e8910003 e8840003 e5835014',
    'aligned': 'e92d48f0 e28db014 e1a04000 e1a0e001 e1a06002 e59b7014 W12 T12 e58c0000 e58c1004 e58c2008 e28c5018 e99b000f e885000f e58c7014',
    'packed-little': 'e24dd008 e92d4810 e28db008 e1a0e000 e1a0c001 e58b3008 e59b4010 W3 T3 e5830000 e5831004 e5832008 e28b1008 e8910003 e5830028 e5c3102c e5834014',
    'packed-big': 'e24dd008 e92d4810 e28db008 e1a0e000 e1a0c001 e58b3008 e59b4010 W3 T3 e5830000 e5831004 e5832008 e28b1008 e8910003 e5830028 e1a01c21 e5c3102c e5834014',
    'bytes-little': 'e92d4800 e28db004 e24dd008 e1a0e003 e50b3008 e59b3004 W12 T12 e58c0000 e58c1004 e58c2008 e1cce3b0 e1a0e82e e5cce032 e58c3014',
    'bytes-big': 'e92d4830 e28db00c e24dd008 e50b3010 e59b4004 W12 T12 e58c0000 e58c1004 e58c2008 e1a05423 e5cc5032 e1a05823 e5cc5031 e1a0ec23 e5cce030 e58c4014',
    'words': 'e24dd008 e92d4870 e28db010 e1a0e000 e1a0c001 e1a04002 e58b3008 e59b6014 W3 T3 e5830000 e5831004 e5832008 e2835034 e28b2008 e8920007 e8850007 e5836014',
    'mixed': 'e92d48f0 e28db014 e1a04000 e1a0e001 e1a06002 e59b7014 W12 T12 e58c0000 e58c1004 e58c2008 e28c5040 e99b000f e885000f e58c7014',
    'base-floats-little': 'e52db004 ed2d8b02 e28db008 ec410b16 ec432b17 ed9b4b01 ed9b5b03 ed9b1b05 ed9b2b07 ed9b3b09 eddb0a0e W3 T3 e1c305f0 ed837b16 ed834b18 ed835b1a ed831b1c ed832b1e ed833b20 e283c088 e28b202c e8920007 e88c0007 edc30a25',
    'base-floats-big': 'e52db004 ed2d8b02 e28db008 ec401b16 ec423b17 ed9b4b01 ed9b5b03 ed9b1b05 ed9b2b07 ed9b3b09 eddb0a0e W3 T3 e1c305f0 ed837b16 ed834b18 ed835b1a ed831b1c ed832b1e ed833b20 e283c088 e28b202c e8920007 e88c0007 edc30a25',
    'vfp-floats': 'e52db004 ed2d8b02 e28db008 eddb7a04 W3 T3 ed830b14 ed831b16 ed832b18 ed833b1a ed834b1c ed835b1e ed836b20 e283c088 e99b0007 e88c0007 edc37a25',
}
KINDS = ('pair', 'aligned', 'packed', 'bytes', 'words', 'mixed', 'floats')
FUNCTIONS = tuple(pcs + '_' + kind for pcs in ('base', 'vfp') for kind in KINDS)
PIE_BYTES_BIG = 'e92d4830 e28db00c e24dd008 e1a0c003 e50b3010 e59b4004 W3 T3 e5830000 e5831004 e5832008 e283e030 e1a0542c e5c35032 e1a0582c e5c35031 e1a0cc2c e5c3c030 e5834014'


def literal_offset(function, order):
    assert function in FUNCTIONS and order in ('little', 'big')
    pcs, kind = function.split('_')
    return {'pair': 152, 'aligned': 164, 'packed': 160 if order == 'little' else 164,
        'bytes': 152 if order == 'little' else 168, 'words': 172, 'mixed': 172,
        'floats': 388 if pcs == 'base' else 356}[kind]


def prefix(function, order, global_address, layout='exec'):
    assert function in FUNCTIONS and order in ('little', 'big')
    assert layout in ('exec', 'pie')
    assert 0 <= global_address <= 0xffffffff
    pcs, kind = function.split('_')
    key = (pcs + '-floats' + ('-' + order if pcs == 'base' else '')) if kind == 'floats' else (
        kind + '-' + order if kind in ('packed', 'bytes') else kind)
    items = PIE_BYTES_BIG if layout == 'pie' and key == 'bytes-big' else PREFIXES[key]
    words = []
    for index, item in enumerate(items.split()):
        if item[0] in ('W', 'T'):
            register = int(item[1:])
            if layout == 'pie':
                immediate = literal_offset(function, order) - index * 4 - 8
                assert 0 <= immediate <= 4095
                word = ((0xe59f0000 | register << 12 | immediate) if item[0] == 'W'
                    else (0xe08f0000 | register << 12 | register))
            else:
                immediate = global_address & 0xffff if item[0] == 'W' else global_address >> 16
                word = (0xe3000000 if item[0] == 'W' else 0xe3400000) | register << 12
                word |= (immediate & 0xf000) << 4 | immediate & 0xfff
        else:
            word = int(item, 16)
        words.append(word)
    return b''.join(word.to_bytes(4, 'little') for word in words)


def validate_prefix(function, order, code, observe_offset, global_address, layout='exec', entry=None):
    expected = prefix(function, order, global_address, layout)
    assert observe_offset == len(expected), (function, 'changed observation boundary')
    assert code[:observe_offset] == expected, (function, 'changed instruction prefix')
    if layout == 'pie':
        assert entry is not None and 0 <= entry <= 0xffffffff and entry % 4 == 0
        pool = literal_offset(function, order)
        assert pool >= observe_offset and pool + 4 == len(code), (function, 'changed literal pool boundary')
        loads = [offset for offset in range(0, observe_offset, 4)
            if int.from_bytes(expected[offset:offset + 4], 'little') & 0xffff0000 == 0xe59f0000]
        load, = loads
        literal = int.from_bytes(code[pool:pool + 4], order)
        assert (entry + load + 12 + literal) & 0xffffffff == global_address, (function, 'wrong PIC global address')


def gap_start(function, order, layout='exec'):
    assert function in FUNCTIONS and order in ('little', 'big')
    assert layout in ('exec', 'pie')
    kind = function.split('_')[1]
    # pair/packed: STR r0,[r3] at +36 destroys the affine stack proof.
    # words: the same store is at +40 after an extra preserved scalar copy.
    # LE bytes: an unknown store already retired the backup, then LSR lr,#16
    # at +48 destroys the last complete 3-byte register copy. BE8 keeps r3.
    # BE8 PIE saves r3 in ip, then overwrites r3 with the PIC address.
    # Its LSR ip,#24 at +64 destroys the final whole-object copy.
    if layout == 'pie' and order == 'big' and kind == 'bytes':
        return 68
    return {'pair': 40, 'packed': 40, 'words': 44,
        'bytes': 52 if order == 'little' else None}.get(kind)


def expects_gap(function, order, offset, expression, layout='exec'):
    assert offset >= 0 and offset % 4 == 0
    gap = gap_start(function, order, layout)
    return expression.startswith('value.') and gap is not None and offset >= gap
