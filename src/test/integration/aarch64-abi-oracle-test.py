#!/usr/bin/env python3
"""Keep the independent ABI oracle exact and its reference exceptions bounded."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('oracle', Path(__file__).with_name('aarch64-abi-oracle.py'))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class AbiOracleTest(unittest.TestCase):
    def test_reference_windows_require_every_instruction_byte(self):
        prefix = oracle.HFA_PACKING_PREFIX
        self.assertEqual(len(prefix), 40)
        for offset in range(4, 40, 4):
            self.assertIsNotNone(oracle.reference_window('abi_hfa', offset, prefix))
        for offset in [-4, 0, 1, 3, 39, 40, 44]:
            self.assertIsNone(oracle.reference_window('abi_hfa', offset, prefix))
        for index in range(len(prefix)):
            changed = bytearray(prefix)
            changed[index] ^= 1
            self.assertIsNone(oracle.reference_window('abi_hfa', 4, changed))
        self.assertIsNone(oracle.reference_window('abi_pair', 4, prefix))
        self.assertIsNone(oracle.reference_window('abi_hfa', 4, prefix[:-1]))
        load = bytes.fromhex('e80340f9')
        self.assertIsNotNone(oracle.reference_window('abi_large_stack', 0, load))
        self.assertIsNone(oracle.reference_window('abi_large_stack', 4, load))
        for index in range(4):
            changed = bytearray(load)
            changed[index] ^= 1
            self.assertIsNone(oracle.reference_window('abi_large_stack', 0, changed))

    def test_raw_words_and_indirect_stack_do_not_round_or_confuse_pointer_with_object(self):
        values = [2**62 + 11, -(2**62) + 13, 17, -19, 23, -29, 31, -37]
        registers = {'x' + str(i): struct.pack('<q', value) for i, value in enumerate(values)}
        registers['sp'] = struct.pack('<Q', 0x1000)
        stack = struct.pack('<qq', 2**60 + 1, -(2**60) + 3)
        words = oracle.entry_arguments('abi_words', registers.__getitem__, lambda address, size: stack)
        self.assertEqual(list(words.values()), values + [2**60 + 1, -(2**60) + 3])
        object_values = [2**62 + 5, -(2**62) + 7, 41]
        blocks = {0x1000: struct.pack('<Q', 0x2000), 0x2000: struct.pack('<qqq', *object_values)}
        reads = []

        def memory(address, size):
            reads.append((address, size))
            data = blocks[address]
            self.assertEqual(len(data), size)
            return data

        observed = oracle.entry_arguments('abi_large_stack', registers.__getitem__, memory)
        self.assertEqual([observed['value.' + field] for field in ['first', 'second', 'third']], object_values)
        self.assertEqual(reads, [(0x1000, 8), (0x2000, 24)])

    def test_hfa_return_is_four_independent_float_registers(self):
        values = [1.25, -2.5, 3.75, 4.5]
        registers = {'s' + str(i): struct.pack('<f', value) for i, value in enumerate(values)}

        def memory(address, size):
            self.fail('HFA registers must not be treated as a memory pointer')

        arguments = oracle.entry_arguments('abi_hfa', registers.__getitem__, memory)
        returned = oracle.return_value('abi_hfa', registers.__getitem__, memory, None)
        self.assertEqual(list(arguments.values()), values)
        self.assertEqual(list(returned.values()), values)
        with self.assertRaises(ValueError):
            oracle.entry_arguments('unvalidated', registers.__getitem__, memory)


if __name__ == '__main__':
    unittest.main()
