#!/usr/bin/env python3
"""Reject executable changes while allowing the intentional appended listing catalog."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('catalog', Path(__file__).with_name('catalog-source-equivalence.py'))
CATALOG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CATALOG)


class CatalogComparisonTest(unittest.TestCase):
    baseline = b'int recovered(void) { return 7; }\n'
    suffix = CATALOG.HEADER + CATALOG.EXPLANATION + (
        b'/* Ghidra listing comment EOL at data:0x10 [NO_INSTRUCTION] */\n'
        b'/* stored \\u002f* text \\n */\n/* second row */\n')

    def test_exact(self):
        self.assertEqual(CATALOG.compare(self.baseline, self.baseline)['relation'], 'IDENTICAL')

    def test_catalog(self):
        result = CATALOG.compare(self.baseline, self.baseline + self.suffix)
        self.assertEqual(result['catalogRecords'], 1)
        self.assertEqual(result['catalogBytes'], len(self.suffix))

    def test_changes_rejected(self):
        candidates = [
            self.baseline.replace(b'7', b'8') + self.suffix,
            self.suffix + self.baseline,
            self.baseline + self.suffix + b'int injected;\n',
            self.baseline + self.suffix[:-1],
            self.baseline + self.suffix.replace(b'NO_INSTRUCTION', b'TOKEN_LINE'),
            self.baseline + self.suffix.replace(b'stored', b'*/ int injected; /*'),
            self.baseline + self.suffix.replace(b'stored', b'/* nested'),
            self.baseline + self.suffix.replace(b'stored', b'??/'),
            self.baseline + self.suffix.replace(b'stored', b'\x00'),
            self.baseline + CATALOG.HEADER + CATALOG.EXPLANATION,
            self.baseline + CATALOG.HEADER + CATALOG.EXPLANATION + b'/* unidentified payload */\n',
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(AssertionError):
                    CATALOG.compare(self.baseline, candidate)


if __name__ == '__main__':
    unittest.main()
