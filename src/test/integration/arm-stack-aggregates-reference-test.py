#!/usr/bin/env python3
"""Reject instruction drift, wider exceptions and stale raw carriers."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('reference', Path(__file__).with_name('arm-stack-aggregates-reference.py'))
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


class ReferenceTest(unittest.TestCase):
    def test_split_windows_require_every_byte_and_exact_prestate(self):
        for order in ('little', 'big'):
            for kind in ('pair', 'packed', 'words', 'bytes'):
                prefix = reference.PREFIXES[kind + '-' + order if kind == 'bytes' else kind]
                code = b''.join(word.to_bytes(4, 'little') for word in prefix)
                for pcs in ('base', 'vfp'):
                    name = pcs + '_' + kind
                    for offset in range(0, len(code), 4):
                        self.assertIsNotNone(reference.window(name, offset, order, code))
                    for offset in (-4, 1, len(code), len(code) + 4):
                        self.assertIsNone(reference.window(name, offset, order, code))
                    self.assertIsNone(reference.window(name, 0, order, code[:-1]))
                    for index in range(len(code)):
                        corrupted = bytearray(code)
                        corrupted[index] ^= 1
                        self.assertIsNone(reference.window(name, 0, order, corrupted))
                self.assertIsNone(reference.window('other_' + kind, 0, order, code))

    def test_double_window_preserves_only_relocation_bits(self):
        for order in ('little', 'big'):
            words = list(reference.FLOAT_PREFIX)
            if order == 'big':
                words[3:5] = (0xec401b16, 0xec423b17)
            code = b''.join(word.to_bytes(4, 'little') for word in words)
            for offset in range(48, 88, 4):
                self.assertIsNotNone(reference.window('base_floats', offset, order, code))
            for offset in (-4, 0, 44, 49, 88):
                self.assertIsNone(reference.window('base_floats', offset, order, code))
            self.assertIsNone(reference.window('vfp_floats', 48, order, code))
            for index in range(len(words)):
                for bit in range(32):
                    corrupted = list(words)
                    corrupted[index] ^= 1 << bit
                    changed = b''.join(word.to_bytes(4, 'little') for word in corrupted)
                    found = reference.window('base_floats', 48, order, changed)
                    literal = index in (11, 12) and not (0xfff0f000 & (1 << bit))
                    self.assertEqual(found is not None, literal, (index, bit))

    def test_carriers_read_current_registers_and_entry_relative_stack(self):
        for order, endian in (('little', '<'), ('big', '>')):
            for kind, layout, values in (('pair', 'ii', (19, -31)),
                    ('packed', 'BI', (0x81, 0x12345678)), ('words', 'iii', (19, -31, 47)),
                    ('bytes', 'BBB', (0x82, 0x93, 0xa4))):
                payload = struct.pack(endian + layout, *values)
                calls = []

                def register(name):
                    calls.append(name)
                    self.assertEqual(name, 'r3')
                    return payload[:4].ljust(4, b'\x00')

                def memory(address, size):
                    calls.append((address, size))
                    self.assertEqual(address, 0x12340)
                    self.assertEqual(size, len(payload) - 4)
                    return payload[4:]

                result = reference.carriers({'kind': kind}, order, register, memory, 0x12340)
                self.assertEqual(tuple(result.values()), values)
                self.assertIn('r3', calls)
            result = reference.carriers({'kind': 'double'}, order,
                lambda name: struct.pack(endian + 'd', -13.25) if name == 'd7' else b'',
                lambda *_: self.fail('double must read d7'), 0)
            self.assertEqual(result, {'b': -13.25})


if __name__ == '__main__':
    unittest.main()
