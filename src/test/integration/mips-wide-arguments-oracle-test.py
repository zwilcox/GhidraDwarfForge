#!/usr/bin/env python3
"""Mutation and raw-byte controls for the independent N32/N64 reference oracle."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('oracle', Path(__file__).with_name('mips-wide-arguments-oracle.py'))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class WideOracleTest(unittest.TestCase):
    def test_raw_register_slots_width_sign_and_byte_order(self):
        for endian in ('big', 'little'):
            for pointer_bytes in (4, 8):
                for function, expected in oracle.EXPECTED.items():
                    with self.subTest(endian=endian, pointer_bytes=pointer_bytes, function=function):
                        registers = {29: 0xfeedface00001000 if pointer_bytes == 4 else 0x100001000}
                        address = registers[29] & ((1 << (pointer_bytes * 8)) - 1)
                        blocks = {}
                        if function == 'wide_words':
                            registers.update(zip(range(4, 12), list(expected.values())[:8]))
                            blocks[address] = (909).to_bytes(8, endian, signed=True)
                            blocks[address + 8] = (-1010).to_bytes(8, endian, signed=True)
                        elif function in ('wide_pair', 'wide_large'):
                            registers.update(zip(oracle.AGGREGATES[function][1], expected.values()))
                        else:
                            registers.update({4: 17, 6: 0xdeadbeefffffffed, 8: 101, 9: -202, 10: 23})
                            for number, fmt, value in [(45, '<d', 1.25), (47, '<f', -2.5), (51, '<d', 3.75)]:
                                registers[number] = int.from_bytes(struct.pack(fmt, value), 'little')
                            registers[47] |= 0xdeadbeef << 32
                            blocks[address] = (29).to_bytes(8, endian, signed=True)
                            blocks[address + (12 if endian == 'big' else 8)] = (-31).to_bytes(4, endian, signed=True)
                        reads = []

                        def memory(where, size):
                            reads.append((where, size))
                            value = blocks[where]
                            self.assertEqual(len(value), size)
                            return value

                        self.assertEqual(oracle.entry_arguments(function, registers.__getitem__, memory,
                            endian, pointer_bytes), expected)
                        self.assertEqual(len(reads), 2 if function in ('wide_words', 'wide_mixed') else 0)
        # High scalar bits are integer bits, never a rounded floating conversion.
        values = [2**62 + index if index % 2 == 0 else -(2**62) + index for index in range(8)]
        registers = dict(zip(range(4, 12), values)) | {29: 0x1000}
        observed = oracle.entry_arguments('wide_words', registers.__getitem__, lambda address, size: bytes(size), 'big', 8)
        self.assertEqual(list(observed.values())[:8], values)
        with self.assertRaises(ValueError):
            oracle.entry_arguments('unknown', registers.__getitem__, lambda address, size: bytes(size), 'big', 8)

    def test_home_windows_end_after_each_store_and_require_audited_epilogue(self):
        # Independently specified straight-line prologue, stores and delayed return.
        words = [0x27bdffe0, 0xffa40000, 0xffa50008, 0x00801025, 0x03e00008, 0x27bd0020]
        for endian in ('big', 'little'):
            code = b''.join(word.to_bytes(4, endian) for word in words)
            proof = oracle.contract('wide_pair', code, endian, -32)
            self.assertEqual(proof['homes']['value.first']['complete'], 8)
            self.assertEqual(proof['homes']['value.second']['complete'], 12)
            for field, end in [('first', 8), ('second', 12)]:
                for offset in range(-4, len(code) + 4):
                    expected = offset in range(0, end, 4)
                    self.assertEqual(oracle.reference_window('wide_pair', 'value.' + field, offset, proof) is not None,
                        expected, (endian, field, offset))
            self.assertIsNone(oracle.reference_window('wide_pair', 'unrelated', 0, proof))
            for index, replacement in [(0, 0x27bdffd0), (1, 0xffa60000), (2, 0xffa50010),
                    (3, 0xffa40000), (4, 0x03e00009), (5, 0x27bd0010)]:
                changed = words.copy()
                changed[index] = replacement
                with self.assertRaises(AssertionError, msg=str((index, replacement))):
                    oracle.contract('wide_pair', b''.join(word.to_bytes(4, endian) for word in changed), endian, -32)
            for wrong_home in (-40, -24, 0):
                with self.assertRaises(AssertionError):
                    oracle.contract('wide_pair', code, endian, wrong_home)
            with self.assertRaises(AssertionError):
                oracle.contract('wide_pair', code[:-1], endian, -32)

    def test_clobbers_and_delayed_stack_exception_have_exact_boundaries(self):
        words = [0x27bdfff0, 0xffa80000, 0xffa90008, 0x00c4302d, 0x46007be1,
            0x00801025, 0x03e00008, 0x27bd0010]
        for endian in ('big', 'little'):
            code = b''.join(word.to_bytes(4, endian) for word in words)
            proof = oracle.contract('wide_mixed', code, endian, -16)
            self.assertEqual(proof['clobbers'], {'c': 16, 'd': 20})
            for expression in ('h', 'tail', 'a', 'c'):
                for offset in range(-4, 37):
                    self.assertEqual(oracle.reference_window('wide_mixed', expression, offset, proof) is not None,
                        expression in ('h', 'tail') and offset == 24)
            for index in (3, 4):
                changed = words.copy()
                changed[index] = 0
                with self.assertRaises(AssertionError):
                    oracle.contract('wide_mixed', b''.join(word.to_bytes(4, endian) for word in changed), endian, -16)
            for duplicate in (0x00c4302d, 0x46007be1):
                changed = words.copy()
                changed[5] = duplicate
                with self.assertRaises(AssertionError):
                    oracle.contract('wide_mixed', b''.join(word.to_bytes(4, endian) for word in changed), endian, -16)


if __name__ == '__main__':
    unittest.main()
