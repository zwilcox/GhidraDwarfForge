#!/usr/bin/env python3
"""Prove the historical-directory exception rejects unrelated DWARF changes."""
import importlib.util
from pathlib import Path
import struct
import unittest

SPEC = importlib.util.spec_from_file_location('comparison', Path(__file__).with_name('dwarf-revision-equivalence.py'))
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)

OLD = '''0x00000000: Compile Unit: length = 0x40, format = DWARF32, version = 0x0005, unit_type = DW_UT_compile, abbr_offset = 0x0000, addr_size = 0x08
0x0000000c: DW_TAG_compile_unit
              DW_AT_name [DW_FORM_strp] ("test.dbg.c")
0x00000010:   DW_TAG_base_type
                DW_AT_name [DW_FORM_strp] ("signed  integer")
                DW_AT_byte_size [DW_FORM_data1] (0x04)
0x00000018:   DW_TAG_subprogram
                DW_AT_name [DW_FORM_strp] ("probe")
                DW_AT_type [DW_FORM_ref4] (0x00000010 "signed  integer")
                DW_AT_low_pc [DW_FORM_addr] (0x0000000000401000)
                DW_AT_decl_file [DW_FORM_data1] ("D:/work/test.dbg.c")
                DW_AT_decl_line [DW_FORM_data1] (7)
                DW_AT_location [DW_FORM_exprloc] (DW_OP_fbreg -8)
0x00000030:   NULL
'''
NEW = OLD.replace('0x00000010', '0x00000014').replace('0x00000018:', '0x0000001c:').replace(
    '0x00000030:', '0x00000034:').replace('0x00000014:   DW_TAG_base_type',
    '              DW_AT_comp_dir [DW_FORM_strp] ("D:/work")\n0x00000014:   DW_TAG_base_type')


def elf(payload=b'line bytes', address=0x401000, identity=62, strings=b'strings', abbrev=b'\x01\x11\x01\x03\x0e\0\0\0'):
    names = b'\0.shstrtab\0.debug_info\0.debug_abbrev\0.debug_str\0.debug_line\0'
    contents = [b'', names, b'info', abbrev, strings, payload]
    labels = ['', '.shstrtab', '.debug_info', '.debug_abbrev', '.debug_str', '.debug_line']
    headers, data = [], bytearray(b'\0' * 64)
    for i, (name, content) in enumerate(zip(labels, contents)):
        headers.append(struct.pack('<IIQQQQIIQQ', names.index(name.encode() + b'\0'),
            0 if i == 0 else 3 if i == 1 else 1, 0, address if i == 5 else 0,
            len(data), len(content), 0, 0, 1, 0))
        data.extend(content)
    table = len(data)
    data.extend(b''.join(headers))
    data[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01' + b'\0' * 10,
        2, identity, 1, 0, 0, table, 0, 64, 0, 0, 64, len(headers), 1)
    return bytes(data)


class RevisionComparisonTest(unittest.TestCase):
    def test_documented_directory_only(self):
        self.assertEqual(COMPARE.compare_decoded(OLD, NEW, 'D:/work'), 4)

    def test_reject_metadata_and_value_changes(self):
        for before, after in [('"D:/work"', '"D:/elsewhere"'),
                ('DW_AT_comp_dir', 'DW_AT_description'),
                ('0x00000014 "signed', '0x0000001c "signed')]:
            changed = NEW.replace(before, after)
            self.assertNotEqual(changed, NEW)
            with self.subTest(before=before), self.assertRaises(ValueError):
                COMPARE.compare_decoded(OLD, changed, 'D:/work')
        for before, after in [('0x04', '0x08'), ('(7)', '(8)'), ('0x0000000000401000', '0x0000000000401001'),
                ('DW_OP_fbreg -8', 'DW_OP_fbreg -16'), ('signed  integer', 'signed integer'),
                ('DW_FORM_data1', 'DW_FORM_udata'), ('D:/work/test.dbg.c', 'D:/wrong/test.dbg.c'),
                ('DW_TAG_base_type', 'DW_TAG_pointer_type'), ('addr_size = 0x08', 'addr_size = 0x04')]:
            with self.subTest(before=before), self.assertRaises(ValueError):
                COMPARE.compare_decoded(OLD, NEW.replace(before, after), 'D:/work')

    def test_reject_wrong_baseline_and_unparsed_data(self):
        for old, new in [(NEW, NEW), (OLD, OLD), (OLD, NEW + 'unparsed garbage\n'),
                (OLD, NEW.replace('0x00000014 "signed', '0x00000099 "signed'))]:
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                COMPARE.compare_decoded(old, new, 'D:/work')

    def test_section_bytes_metadata_and_identity(self):
        original = elf()
        self.assertIn('.debug_line', COMPARE.compare_sections(original, original))
        for changed in (elf(b'line bytex'), elf(address=0x401001), elf(identity=183), original[:-1]):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                COMPARE.compare_sections(original, changed)

    def test_string_table_addition_is_exact(self):
        original = elf()
        abbreviation = b'\x01\x11\x01\x03\x0e\x1b\x0e\0\0\0'
        COMPARE.compare_sections(original, elf(strings=b'stringsD:/work\0', abbrev=abbreviation), 'D:/work')
        for strings in (b'strings', b'stringsD:/work\0extra', b'stringsD:/work\0D:/work\0',
                b'stringxD:/work\0'):
            with self.subTest(strings=strings), self.assertRaises(ValueError):
                COMPARE.compare_sections(original, elf(strings=strings, abbrev=abbreviation), 'D:/work')

        for changed in (abbreviation + b'\0', abbreviation.replace(b'\x03\x0e', b'\x03\x08'),
                abbreviation.replace(b'\x1b\x0e', b'')):
            with self.subTest(abbreviation=changed), self.assertRaises(ValueError):
                COMPARE.compare_sections(original, elf(strings=b'stringsD:/work\0', abbrev=changed), 'D:/work')


if __name__ == '__main__':
    unittest.main()
