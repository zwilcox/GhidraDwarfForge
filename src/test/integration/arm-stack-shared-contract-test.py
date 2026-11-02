#!/usr/bin/env python3
"""Shared prefix, relocation and compiler-window mutation controls."""
import importlib.util
from pathlib import Path
import struct
import unittest
import arm_stack_shared_contract as contract

spec = importlib.util.spec_from_file_location('reference', Path(__file__).with_name('arm-stack-aggregates-reference.py'))
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def sample(function, bias=0):
    code = contract.prefix(function)
    load = next(offset for offset in range(0, len(code), 4)
        if int.from_bytes(code[offset:offset + 4], 'little') & 0xffff0000 == 0xe59f0000)
    kind = function.split('_')[1]
    names = ('seen_doubles', 'seen_floats', 'seen_float_tail') if kind == 'floats' else ('seen_leading', 'seen_' + kind, 'seen_tail')
    entry, got = 0x800 + bias, 0x3000 + bias
    symbols = {name: 0x3100 + index * 16 + bias for index, name in enumerate(names)}
    offsets = (12, 16, 20)
    slots = {got + offset: symbols[name] for offset, name in zip(offsets, names)}
    code = code.ljust(contract.pool_offset(function), b'\x00') + struct.pack('<4I', (got - entry - load - 12) & 0xffffffff, *offsets)

    def memory(address, size):
        assert address in slots and size == 4
        return slots[address].to_bytes(4, 'little')

    return code, entry, got, symbols, slots, memory


class SharedTest(unittest.TestCase):
    def test_every_instruction_and_pool_byte_is_checked(self):
        for pcs in ('base', 'vfp'):
            for kind in ('pair', 'aligned', 'packed', 'bytes', 'words', 'mixed', 'floats'):
                function = pcs + '_' + kind
                for bias in (0, 0x40000000):
                    code, entry, got, symbols, slots, memory = sample(function, bias)
                    observe = len(contract.prefix(function))
                    self.assertEqual(len(contract.validate_prefix(function, code, observe, entry, got, symbols, memory)), 3)
                    for index in (*range(observe), *range(len(code) - 16, len(code))):
                        changed = bytearray(code)
                        changed[index] ^= 1
                        with self.assertRaises(AssertionError):
                            contract.validate_prefix(function, changed, observe, entry, got, symbols, memory)
                    for boundary in (observe - 4, observe + 4):
                        with self.assertRaises(AssertionError):
                            contract.validate_prefix(function, code, boundary, entry, got, symbols, memory)
                    with self.assertRaises(AssertionError):
                        contract.validate_prefix(function, code[:-1], observe, entry, got, symbols, memory)

    def test_each_live_got_target_and_load_bias_is_checked(self):
        code, entry, got, symbols, slots, memory = sample('base_pair', 0x40000000)
        observe = len(contract.prefix('base_pair'))
        for slot in slots:
            slots[slot] ^= 4
            with self.assertRaises(AssertionError):
                contract.validate_prefix('base_pair', code, observe, entry, got, symbols, memory)
            slots[slot] ^= 4
        for wrong_entry, wrong_got in ((entry + 4, got), (entry, got + 4)):
            with self.assertRaises(AssertionError):
                contract.validate_prefix('base_pair', code, observe, wrong_entry, wrong_got, symbols, memory)

    def test_compiler_double_window_is_bounded_and_checks_surviving_instructions(self):
        code, *_ = sample('base_floats')
        for offset in range(56, 100, 4):
            proof = reference.window('base_floats', offset, 'little', code, 'shared')
            self.assertEqual(proof['fields'], ('b',))
        for offset in (52, 57, 100):
            self.assertIsNone(reference.window('base_floats', offset, 'little', code, 'shared'))
        for index in range(len(contract.prefix('base_floats'))):
            changed = bytearray(code)
            changed[index] ^= 1
            self.assertIsNone(reference.window('base_floats', 56, 'little', changed, 'shared'))
        self.assertIsNone(reference.window('base_floats', 56, 'big', code, 'shared'))

    def test_gaps_follow_the_relevant_store_and_only_affect_objects(self):
        for kind, boundary in (('pair', 48), ('packed', 48), ('bytes', 40), ('words', 52)):
            for pcs in ('base', 'vfp'):
                name = pcs + '_' + kind
                self.assertFalse(contract.expects_gap(name, 'little', boundary - 4, 'value.first'))
                self.assertTrue(contract.expects_gap(name, 'little', boundary, 'value.first'))
                self.assertFalse(contract.expects_gap(name, 'little', boundary, 'a'))
                with self.assertRaises(AssertionError):
                    contract.expects_gap(name, 'big', boundary, 'value.first')


if __name__ == '__main__':
    unittest.main()
