"""Negative controls for call-origin additions in the retained-symbol oracle."""
import copy
from pathlib import Path
import runpy
import struct
import unittest


MODULE = runpy.run_path(str(Path(__file__).parents[1] / 'integration/retained-function-aliases-export.py'))
check = MODULE['call_origin_inventory']


class CallOriginInventoryTest(unittest.TestCase):
    def setUp(self):
        self.identity = 'a' * 64
        self.name = 'forge_call_entry_' + self.identity + '_1000'
        text = bytearray(0x100)
        text[0x40:0x45] = b'\xe8' + (-0x45).to_bytes(4, 'little', signed=True)
        old_names = b'\0old\0'
        null = bytes(24)
        old_symbol = struct.pack('<IBBHQQ', 1, 18, 0, 1, 0x1020, 8)

        def section(kind, payload, flags=0, address=0, link=0, info=0, entry=0):
            return ((0, kind, flags, address, 0, len(payload), link, info, 1, entry), bytes(payload))

        self.original = {
            '': section(0, b''),
            '.text': section(1, text, flags=6, address=0x1000),
            '.strtab': section(3, old_names),
            '.symtab': section(2, null + old_symbol, link=2, info=1, entry=24),
            '.dynstr': section(3, old_names),
            '.dynsym': section(11, null + old_symbol, link=4, info=1, entry=24),
        }
        self.emitted = copy.deepcopy(self.original)
        self.emitted['.strtab'] = section(3, old_names + self.name.encode() + b'\0')
        addition = struct.pack('<IBBHQQ', len(old_names), 2, 0, 1, 0x1000, 0x10)
        self.emitted['.symtab'] = section(2, null + addition + old_symbol, link=2, info=2, entry=24)
        ranges = b'\x06' + struct.pack('<QQ', 0x1000, 0x1010)
        ranges += b'\x06' + struct.pack('<QQ', 0x1020, 0x1021) + b'\0'
        self.emitted['.debug_rnglists'] = section(1, ranges)
        self.dies = [
            {'tag': 'DW_TAG_subprogram', 'depth': 1, 'offset': 0x10, 'attrs': {'DW_AT_ranges': '0x0'}},
            {'tag': 'DW_TAG_subprogram', 'depth': 1, 'offset': 0x30, 'attrs': {
                'DW_AT_name': self.name, 'DW_AT_artificial': '1', 'DW_AT_declaration': '1'}},
            {'tag': 'DW_TAG_call_site', 'depth': 2, 'offset': 0x40, 'attrs': {
                'DW_AT_call_origin': '<0x30>', 'DW_AT_call_pc': '0x1040', 'DW_AT_call_return_pc': '0x1045'}},
        ]

    def test_preserved_inventory_and_proven_addition(self):
        observed = check(self.original, self.emitted, self.identity, self.dies)
        self.assertEqual([(row['name'], row['address'], row['size'], row['calls']) for row in observed],
            [(self.name, 0x1000, 0x10, 1)])

    def test_stripped_input_preserves_dynamic_inventory(self):
        del self.original['.symtab']
        del self.original['.strtab']
        # Reconstruct indices as they appear in the stripped ELF section table.
        row, raw = self.original['.dynsym']
        row = list(row)
        row[6] = 2
        self.original['.dynsym'] = (tuple(row), raw)
        self.assertEqual(len(check(self.original, self.emitted, self.identity, self.dies)), 1)

    def test_unchanged_inventory_without_additions(self):
        self.assertEqual(check(self.original, self.original, self.identity, []), [])

    def test_explicit_entry_above_body_start(self):
        # The symbol starts at the entry, not at the lower body address, and
        # stops at the end of the containing range rather than spanning gaps.
        self.dies[0]['attrs']['DW_AT_entry_pc'] = '0x1000'
        header, _ = self.emitted['.debug_rnglists']
        for spans in [[(0xff0, 0x1010)], [(0xff0, 0x1010), (0x1020, 0x1021)]]:
            with self.subTest(spans=spans):
                raw = b''.join(b'\x06' + struct.pack('<QQ', *span) for span in spans) + b'\0'
                self.emitted['.debug_rnglists'] = (header, raw)
                observed = check(self.original, self.emitted, self.identity, self.dies)
                self.assertEqual((observed[0]['address'], observed[0]['size']), (0x1000, 0x10))

    def test_rejects_wrong_missing_or_unnecessary_entry(self):
        header, _ = self.emitted['.debug_rnglists']
        controls = [
            ([(0xff0, 0x1010)], None),
            ([(0xff0, 0x1010)], '0x1001'),
            ([(0x1000, 0x1010)], '0x1000'),
            ([(0x1000, 0x1010), (0x1020, 0x1021)], '0x1020'),
        ]
        for spans, entry in controls:
            with self.subTest(spans=spans, entry=entry):
                dies = copy.deepcopy(self.dies)
                if entry is not None:
                    dies[0]['attrs']['DW_AT_entry_pc'] = entry
                raw = b''.join(b'\x06' + struct.pack('<QQ', *span) for span in spans) + b'\0'
                self.emitted['.debug_rnglists'] = (header, raw)
                with self.assertRaises(AssertionError):
                    check(self.original, self.emitted, self.identity, dies)

    def test_rejects_symbol_corruption(self):
        # Existing bytes, new binding/visibility/section/address/extent, and name.
        for section, offset in [('.symtab', 48), ('.symtab', 28), ('.symtab', 29),
                ('.symtab', 30), ('.symtab', 32), ('.symtab', 40),
                ('.strtab', 1), ('.strtab', 5), ('.dynsym', 24), ('.dynstr', 1)]:
            with self.subTest(section=section, offset=offset):
                emitted = copy.deepcopy(self.emitted)
                header, raw = emitted[section]
                raw = bytearray(raw)
                raw[offset] ^= 1
                emitted[section] = (header, bytes(raw))
                with self.assertRaises(AssertionError):
                    check(self.original, emitted, self.identity, self.dies)

    def test_rejects_unproved_origin(self):
        for key, value in [('DW_AT_call_origin', '<0x31>'), ('DW_AT_call_return_pc', '0x1046'),
                ('DW_AT_call_tail_call', '1')]:
            with self.subTest(key=key):
                dies = copy.deepcopy(self.dies)
                dies[-1]['attrs'][key] = value
                with self.assertRaises(AssertionError):
                    check(self.original, self.emitted, self.identity, dies)
        original = copy.deepcopy(self.original)
        header, raw = original['.text']
        raw = bytearray(raw)
        raw[0x41] += 1
        original['.text'] = (header, bytes(raw))
        with self.assertRaises(AssertionError):
            check(original, self.emitted, self.identity, self.dies)

    def test_rejects_unmatched_range_and_unaccounted_bytes(self):
        for name, offset in [('.debug_rnglists', 9), ('.strtab', None)]:
            with self.subTest(section=name):
                emitted = copy.deepcopy(self.emitted)
                header, raw = emitted[name]
                raw = bytearray(raw)
                if offset is None:
                    raw.extend(b'unaccounted\0')
                else:
                    raw[offset] += 1
                emitted[name] = (header, bytes(raw))
                with self.assertRaises(AssertionError):
                    check(self.original, emitted, self.identity, self.dies)
        emitted = copy.deepcopy(self.emitted)
        header, raw = emitted['.symtab']
        header = list(header)
        header[7] -= 1
        emitted['.symtab'] = (tuple(header), raw)
        with self.assertRaises(AssertionError):
            check(self.original, emitted, self.identity, self.dies)


if __name__ == '__main__':
    unittest.main()
