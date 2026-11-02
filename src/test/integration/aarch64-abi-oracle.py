"""Independent AAPCS64 fixture facts and explicitly bounded compiler-reference windows.

Reference: Arm ABI 2025Q4, daa7a94ca55973736c0e434a67a6e4bbcd35d7fa.
These rules consume actual target bytes, never Forge locations or diagnostics.
"""
import struct


# GCC's exact ten-instruction HFA packing prefix: initialize x0/x1, copy each
# incoming s0..s3 through w2 into x0/x1. No instruction writes an FP register.
# GCC 13/14 DWARF prematurely names the partially assembled integer pieces.
HFA_PACKING_PREFIX = bytes.fromhex(
    '000080d2010080d20200261e407c40b32200261e407c60b3'
    '4200261e417c40b36200261e417c60b3')


def reference_window(function, offset, code):
    """Recognize only audited pre-state windows; changed instructions fail closed."""
    if function == 'abi_hfa' and 0 < offset < len(HFA_PACKING_PREFIX) and offset % 4 == 0:
        if code[:len(HFA_PACKING_PREFIX)] == HFA_PACKING_PREFIX:
            return 'GCC HFA pieces named before integer packing completes'
    if function == 'abi_large_stack' and offset == 0 and code[:4] == bytes.fromhex('e80340f9'):
        return 'GCC names x8 before the incoming pointer load executes'
    if function == 'abi_pair_chain' and offset == 0 and code[:4] == bytes.fromhex('e71b40f9'):
        return 'GCC names x7 before the incoming stack+48 pointer load executes'
    return None


def entry_arguments(function, register, memory):
    """Decode baseline LP64 arguments independently of either symbol file."""
    def word(index):
        return struct.unpack('<q', register('x' + str(index)))[0]

    def real(index):
        return struct.unpack('<d', register('d' + str(index)))[0]

    def pointer(name):
        return int.from_bytes(register(name), 'little')

    def fields(values):
        return dict(zip(('value.first', 'value.second', 'value.third', 'value.fourth'), values))

    if function in ('abi_narrow_stack', 'abi_aligned_stack', 'abi_pair_stack', 'abi_pair_chain', 'abi_pair_variadic'):
        count = 7 if function.startswith('abi_pair_') else 8
        result = dict(zip('abcdefgh', [word(i) for i in range(count)]))
        address = pointer('sp')
        if function == 'abi_narrow_stack':
            result.update(low=struct.unpack('<b', memory(address, 1))[0],
                high=struct.unpack('<H', memory(address + 8, 2))[0],
                middle=struct.unpack('<i', memory(address + 16, 4))[0],
                wide=struct.unpack('<q', memory(address + 24, 8))[0])
        elif function == 'abi_aligned_stack':
            result.update(lead=struct.unpack('<b', memory(address, 1))[0],
                wide=int.from_bytes(memory(address + 16, 16), 'little', signed=True),
                tail=struct.unpack('<b', memory(address + 32, 1))[0])
        else:
            result.update(fields(struct.unpack('<qq', memory(address, 16))))
            result['tail'] = struct.unpack('<q', memory(address + 16, 8))[0]
            if function == 'abi_pair_chain':
                result['wide'] = int.from_bytes(memory(address + 32, 16), 'little', signed=True)
                object_address = int.from_bytes(memory(address + 48, 8), 'little')
                result.update(zip(('object.first', 'object.second', 'object.third'),
                    struct.unpack('<qqq', memory(object_address, 24))))
                result['floating'] = real(0)
        return result
    if function == 'abi_aligned_register':
        return {'first': word(0), 'wide': int.from_bytes(register('x2') + register('x3'),
            'little', signed=True), 'tail': word(4)}
    if function == 'abi_words':
        return dict(zip('abcdefghij', [word(i) for i in range(8)] +
            list(struct.unpack('<qq', memory(pointer('sp'), 16)))))
    if function == 'abi_floats':
        return dict(zip('abcdefghij', [real(i) for i in range(8)] +
            list(struct.unpack('<dd', memory(pointer('sp'), 16)))))
    if function == 'abi_pair':
        return fields([word(0), word(1)])
    if function in ('abi_large', 'abi_large_spill', 'abi_large_spill_alias'):
        return fields(struct.unpack('<qqq', memory(pointer('x0'), 24)))
    if function == 'abi_large_stack':
        address = int.from_bytes(memory(pointer('sp'), 8), 'little')
        return {**dict(zip('abcdefgh', [word(i) for i in range(8)])),
            **fields(struct.unpack('<qqq', memory(address, 24)))}
    if function == 'abi_hfa':
        return fields([struct.unpack('<f', register('s' + str(i)))[0] for i in range(4)])
    if function == 'abi_hfa_exhausted':
        address = pointer('sp')
        return {**dict(zip('abcdefg', [real(i) for i in range(7)])),
            **fields(struct.unpack('<ffff', memory(address, 16))),
            'tail': struct.unpack('<d', memory(address + 16, 8))[0]}
    raise ValueError('unrecognized ABI fixture function: ' + function)


def return_value(function, register, memory, hidden_buffer):
    fields = ('first', 'second', 'third', 'fourth')
    if function in ('abi_words', 'abi_large_stack', 'abi_narrow_stack', 'abi_pair_stack', 'abi_pair_chain', 'abi_pair_variadic'):
        return struct.unpack('<q', register('x0'))[0]
    if function in ('abi_aligned_stack', 'abi_aligned_register'):
        return int.from_bytes(register('x0') + register('x1'), 'little', signed=True)
    if function in ('abi_floats', 'abi_hfa_exhausted'):
        return struct.unpack('<d', register('d0'))[0]
    if function == 'abi_pair':
        return dict(zip(fields, [struct.unpack('<q', register('x' + str(i)))[0] for i in range(2)]))
    if function in ('abi_large', 'abi_large_spill', 'abi_large_spill_alias'):
        return dict(zip(fields, struct.unpack('<qqq', memory(hidden_buffer, 24))))
    if function == 'abi_hfa':
        return dict(zip(fields, [struct.unpack('<f', register('s' + str(i)))[0] for i in range(4)]))
    raise ValueError('unrecognized ABI fixture return: ' + function)
