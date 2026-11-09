#!/usr/bin/env python3
"""Reject wrong registers, borrowed ranges and enlarged thunk entry locations."""
from pathlib import Path
import runpy
import unittest


check = runpy.run_path(str(Path(__file__).with_name('curated-thunk-export.py')))['check_entry_location']


class EntryLocationTests(unittest.TestCase):
    def test_exact_entry_on_both_profiles(self):
        for target, register in (('x86_64', 5), ('aarch64', 0)):
            with self.subTest(target=target):
                check({'attrs': {'DW_AT_location': '0x18c (location list)'}},
                    ' 0000018c 0000000000400680 0000000000400681 (DW_OP_regx: ' + str(register) + ')\n'
                    ' 000001a0 <End of list>\n', 0x400680, target)

    def test_reject_wrong_register_or_extent(self):
        good = ' 0000018c 0000000000400680 0000000000400681 (DW_OP_regx: 0 (x0))\n 000001a0 <End of list>\n'
        for changed in (good.replace('regx: 0 (x0)', 'regx: 1 (x1)'),
                good.replace('400681', '400684'), good.replace('400680', '400670'),
                good.replace(' 000001a0 <End of list>', ''),
                good.replace(' 000001a0 <End of list>',
                    ' 000001a0 0000000000400684 0000000000400688 (DW_OP_regx: 0 (x0))\n 000001b4 <End of list>')):
            with self.subTest(changed=changed), self.assertRaises(AssertionError):
                check({'attrs': {'DW_AT_location': '0x18c (location list)'}}, changed, 0x400680, 'aarch64')

    def test_reject_unbounded_or_missing_location(self):
        for attrs in ({}, {'DW_AT_location': '2 byte block: 90 0 (DW_OP_regx: 0)'},
                {'DW_AT_location': '0x1ff (location list)'}):
            with self.subTest(attrs=attrs), self.assertRaises((AssertionError, ValueError)):
                check({'attrs': attrs}, '', 0x400680, 'aarch64')


if __name__ == '__main__':
    unittest.main()
