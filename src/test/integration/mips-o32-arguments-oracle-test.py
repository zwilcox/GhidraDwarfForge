#!/usr/bin/env python3
"""O32 oracle controls: paired-word order, stack offsets, and exact instruction boundaries."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('oracle', Path(__file__).with_name('mips-o32-arguments-oracle.py'))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class O32OracleTest(unittest.TestCase):
    def test_independent_word_slots(self):
        for endian in ('big', 'little'):
            for function, expected in oracle.EXPECTED.items():
                with self.subTest(endian=endian, function=function):
                    slots = [b'\xa5' * 4 for _ in range(20)]
                    if function == 'wide_words':
                        layout = [(name, 2 * index, 8) for index, name in enumerate(expected)]
                    elif function in ('wide_pair', 'wide_large'):
                        layout = [(name, 2 + 2 * index, 8) for index, name in enumerate(expected)]
                    else:
                        layout = [('a', 0, 8), ('b', 2, 8), ('c', 4, 4), ('d', 5, 4),
                            ('e.first', 6, 8), ('e.second', 8, 8), ('f', 10, 8), ('g', 12, 8),
                            ('h', 14, 8), ('tail', 16, 4)]
                    for name, slot, width in layout:
                        value = expected[name]
                        data = struct.pack(('>' if endian == 'big' else '<') + ('d' if width == 8 else 'f'), value) \
                            if isinstance(value, float) else value.to_bytes(width, endian, signed=True)
                        for index in range(width // 4):
                            slots[slot + index] = data[index * 4:index * 4 + 4]
                    registers = {4 + index: int.from_bytes(slots[index], endian) for index in range(4)}
                    registers[29] = 0x1000
                    reads = []

                    def memory(address, width):
                        self.assertEqual(width, 4)
                        self.assertEqual((address - 0x1000) % 4, 0)
                        reads.append(address)
                        return slots[(address - 0x1000) // 4]

                    self.assertEqual(oracle.entry_arguments(function, registers.__getitem__, memory, endian, 4), expected)
                    self.assertTrue(all(address >= 0x1010 for address in reads))
                    for name, slot, width in layout:
                        if slot < 4:
                            changed = registers | {4 + slot: registers[4 + slot] ^ 1}
                            observed = oracle.entry_arguments(function, changed.__getitem__, memory, endian, 4)
                        else:
                            saved = slots[slot]
                            slots[slot] = (int.from_bytes(saved, endian) ^ 1).to_bytes(4, endian)
                            observed = oracle.entry_arguments(function, registers.__getitem__, memory, endian, 4)
                            slots[slot] = saved
                        self.assertNotEqual(observed[name], expected[name])
                    # The captured entry stack remains the reference after the physical SP changes.
                    registers[29] += 32
                    self.assertEqual(oracle.entry_arguments(function, registers.__getitem__, memory,
                        endian, 4, stack_pointer=0x1000), expected)
                    with self.assertRaises(AssertionError):
                        oracle.entry_arguments(function, registers.__getitem__, memory, endian, 8)

    def test_aggregate_home_and_store_boundary(self):
        words = [0x00801025, 0xafa60008, 0xafa7000c, 0x03e00008, 0x00000000]
        for endian in ('big', 'little'):
            code = b''.join(word.to_bytes(4, endian) for word in words)
            proof = oracle.contract('wide_pair', code, endian, 8)
            self.assertEqual(proof['firstStore'], 8)
            self.assertEqual(proof['homes'], {'value.first': {'complete': 12}})
            for offset in range(-4, 25):
                self.assertEqual(oracle.reference_window('wide_pair', 'value.first', offset, proof) is not None,
                    offset in (0, 4, 8))
            for offset in range(0, 20, 4):
                self.assertEqual(oracle.unavailable('wide_pair', 'value.second', offset, proof, 'forge'), offset >= 8)
                self.assertFalse(oracle.unavailable('wide_pair', 'value.second', offset, proof, 'compiler'))
            for index, replacement in ((0, 0x27bdfff0), (1, 0xafa50008), (2, 0xafa70010),
                    (3, 0x03e00009), (4, 0x00803025)):
                changed = words.copy()
                changed[index] = replacement
                with self.assertRaises(AssertionError):
                    oracle.contract('wide_pair', b''.join(word.to_bytes(4, endian) for word in changed), endian, 8)
            with self.assertRaises(AssertionError):
                oracle.contract('wide_pair', code, endian, 4)

    def test_partial_register_clobber_window_is_big_endian_only(self):
        words = [0x00a73821, 0x00e5282b, 0x00862021, 0x00803025, 0xac820000, 0x03e00008, 0]
        for endian in ('big', 'little'):
            proof = oracle.contract('wide_words', b''.join(word.to_bytes(4, endian) for word in words), endian)
            self.assertEqual(proof['clobbers'], {'a': 8, 'b': 4})
            self.assertEqual(proof['lastPiece'], {'a': 12, 'b': 16})
            for name, begin, end in (('a', 8, 12), ('b', 4, 16)):
                for offset in range(-4, 33):
                    self.assertEqual(oracle.reference_window('wide_words', name, offset, proof) is not None,
                        endian == 'big' and begin <= offset < end and offset % 4 == 0)
            with self.assertRaises(AssertionError):
                oracle.contract('wide_words', b''.join(word.to_bytes(4, endian) for word in [0x10000000, *words]), endian)


if __name__ == '__main__':
    unittest.main()
