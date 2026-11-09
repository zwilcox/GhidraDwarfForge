#!/usr/bin/env python3
"""Pure diagnostic controls; no producer, Ghidra, debugger or artifact writes."""
from pathlib import Path
import runpy
import unittest


check = runpy.run_path(str(Path(__file__).with_name('mips-fpr-system.py')))['check_diagnostics']


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.labels = {'_start': 0x100000, 'main': 0x100100,
                       'fp_float': 0x100200, 'fp_double': 0x100300}
        self.original = ['original diagnostic ' + str(index) for index in range(8)]
        self.calls = [
            'Call-site metadata at ELF address 0x100000: ELF or program is outside the selected ordinary unwind ABIs',
            'Call-site metadata at ELF address 0x100100: ELF or program is outside the selected ordinary unwind ABIs',
            'Call-site metadata at ELF address 0x100200: ELF or program is outside the selected ordinary unwind ABIs',
            'Call-site metadata at ELF address 0x100300: ELF or program is outside the selected ordinary unwind ABIs',
        ]

    def test_exact_accounting_independent_of_order(self):
        check(self.original + self.calls, self.labels)
        check(list(reversed(self.calls + self.original)), self.labels)

    def test_missing_or_duplicate_call_site(self):
        for calls in (self.calls[:-1], self.calls + self.calls[:1],
                      self.calls[:3] + self.calls[:1]):
            with self.subTest(calls=calls), self.assertRaises(AssertionError):
                check(self.original + calls, self.labels)

    def test_wrong_address_or_reason(self):
        for replacement in (
                self.calls[0].replace('0x100000', '0x100001'),
                self.calls[0].replace('ELF or program is outside', 'capture failed outside'),
                self.calls[0].replace('Call-site metadata', 'Different metadata')):
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                check(self.original + [replacement] + self.calls[1:], self.labels)

    def test_original_diagnostics_still_have_exact_count(self):
        for original in (self.original[:-1], self.original + ['unexpected error']):
            with self.subTest(original=original), self.assertRaises(AssertionError):
                check(original + self.calls, self.labels)

    def test_invalid_diagnostic_collection(self):
        for diagnostics in ('not a list', None, self.original + self.calls + [None]):
            with self.subTest(diagnostics=diagnostics), self.assertRaises(AssertionError):
                check(diagnostics, self.labels)


if __name__ == '__main__':
    unittest.main()
