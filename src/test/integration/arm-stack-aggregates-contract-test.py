#!/usr/bin/env python3
"""Keep the prefix/gap contract independent, exact and closed to code drift."""
import unittest
import arm_stack_aggregate_contract as contract


class ContractTest(unittest.TestCase):
    def test_pic_instructions_pool_and_relocated_target_are_exact(self):
        for order in ('little', 'big'):
            for function in contract.FUNCTIONS:
                for entry, target in ((0x10c, 0x2050), (0x4000010c, 0x40002050),
                        (0xfffff000, 0x100), (0x1000, 0x80)):
                    prefix = contract.prefix(function, order, target, 'pie')
                    pool = contract.literal_offset(function, order)
                    load, = [offset for offset in range(0, len(prefix), 4)
                        if int.from_bytes(prefix[offset:offset + 4], 'little') & 0xffff0000 == 0xe59f0000]
                    literal = (target - entry - load - 12) & 0xffffffff
                    code = prefix.ljust(pool, b'\x00') + literal.to_bytes(4, order)
                    contract.validate_prefix(function, order, code, len(prefix), target, 'pie', entry)
                    for index in (*range(len(prefix)), *range(pool, pool + 4)):
                        changed = bytearray(code)
                        changed[index] ^= 1
                        with self.assertRaises(AssertionError):
                            contract.validate_prefix(function, order, changed, len(prefix), target, 'pie', entry)
                    for changed in (code[:-1], code + b'\x00'):
                        with self.assertRaises(AssertionError):
                            contract.validate_prefix(function, order, changed, len(prefix), target, 'pie', entry)
                    with self.assertRaises(AssertionError):
                        contract.validate_prefix(function, order, code, len(prefix), target ^ 4, 'pie', entry)
                    with self.assertRaises(AssertionError):
                        contract.validate_prefix(function, order, code, len(prefix), target, 'pie', entry ^ 4)

    def test_be8_pic_partial_object_has_its_own_loss_boundary(self):
        for pcs in ('base', 'vfp'):
            function = pcs + '_bytes'
            code = contract.prefix(function, 'big', 0x2050, 'pie')
            self.assertEqual(len(code), 76)
            self.assertEqual(int.from_bytes(code[64:68], 'little'), 0xe1a0cc2c)
            self.assertFalse(contract.expects_gap(function, 'big', 64, 'value.first', 'pie'))
            self.assertTrue(contract.expects_gap(function, 'big', 68, 'value.first', 'pie'))
            self.assertFalse(contract.expects_gap(function, 'big', 68, 'a', 'pie'))
            self.assertIsNone(contract.gap_start(function, 'big', 'exec'))

    def test_every_instruction_byte_and_boundary_is_checked(self):
        for order in ('little', 'big'):
            for function in contract.FUNCTIONS:
                code = contract.prefix(function, order, 0x12345678)
                contract.validate_prefix(function, order, code, len(code), 0x12345678)
                for index in range(len(code)):
                    changed = bytearray(code)
                    changed[index] ^= 1
                    with self.assertRaises(AssertionError):
                        contract.validate_prefix(function, order, changed, len(code), 0x12345678)
                for boundary in (len(code) - 4, len(code) + 4):
                    with self.assertRaises(AssertionError):
                        contract.validate_prefix(function, order, code, boundary, 0x12345678)
                with self.assertRaises(AssertionError):
                    contract.validate_prefix(function, order, code, len(code), 0x12345679)

    def test_literal_relocations_are_decoded_not_masked(self):
        # A MOVW/MOVT pair for r3 must independently encode all 32 bits.
        code = contract.prefix('base_pair', 'little', 0x12345678)
        self.assertEqual(int.from_bytes(code[28:32], 'little'), 0xe3053678)
        self.assertEqual(int.from_bytes(code[32:36], 'little'), 0xe3413234)
        for address in (0, 0xffff, 0x10000, 0xffffffff):
            code = contract.prefix('base_pair', 'big', address)
            words = [int.from_bytes(code[i:i + 4], 'little') for i in (28, 32)]
            immediate = [(word & 0xfff) | (word >> 4 & 0xf000) for word in words]
            self.assertEqual(immediate[0] | immediate[1] << 16, address)

    def test_gaps_start_after_exact_loss_and_only_affect_object_fields(self):
        for order in ('little', 'big'):
            for function in contract.FUNCTIONS:
                boundary = contract.gap_start(function, order)
                for offset in range(0, len(contract.prefix(function, order, 0x10000)) + 1, 4):
                    self.assertEqual(contract.expects_gap(function, order, offset, 'value.first'),
                        boundary is not None and offset >= boundary)
                    for expression in ('a', 'b', 'tail'):
                        self.assertFalse(contract.expects_gap(function, order, offset, expression))
        self.assertEqual(contract.gap_start('base_bytes', 'little'), 52)
        self.assertIsNone(contract.gap_start('base_bytes', 'big'))
        with self.assertRaises(AssertionError):
            contract.expects_gap('unvalidated', 'little', 40, 'value.first')


if __name__ == '__main__':
    unittest.main()
