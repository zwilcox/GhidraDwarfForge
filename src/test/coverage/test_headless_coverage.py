"""Fail-closed completion and provenance controls without launching Ghidra."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('headless_coverage',
    Path(__file__).with_name('headless-coverage.py'))
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='coverage-receipt-')
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.jar = self.output / 'production.jar'
        self.jar.write_bytes(b'original production population')
        for index in range(2):
            (self.output / f'headless-{index}.exec').write_bytes(bytes([index]))
        self.receipt = self.output / 'receipt.json'
        self.record = {'schema': 1, 'status': 'PASS',
            'productionJarSha256': coverage.digest(self.jar),
            'execution': {f'headless-{i}.exec': coverage.digest(self.output / f'headless-{i}.exec')
                for i in range(2)}}
        self.write()

    def write(self):
        self.receipt.write_text(json.dumps(self.record))

    def validate(self):
        return coverage.validate_receipt(self.output, self.jar)

    def test_unchanged_completed_session(self):
        self.assertEqual('PASS', self.validate()['status'])

    def test_failed_or_incomplete_session(self):
        for status in ('INCOMPLETE', 'FAIL', None):
            self.record['status'] = status
            self.write()
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                self.validate()

    def test_changed_production_classes(self):
        self.jar.write_bytes(b'new compilation')
        with self.assertRaisesRegex(ValueError, 'production classes changed'):
            self.validate()

    def test_changed_execution(self):
        (self.output / 'headless-0.exec').write_bytes(b'foreign execution')
        with self.assertRaisesRegex(ValueError, 'execution data changed'):
            self.validate()

    def test_missing_session(self):
        (self.output / 'headless-1.exec').unlink()
        with self.assertRaisesRegex(ValueError, 'unrecorded or missing'):
            self.validate()

    def test_extra_execution(self):
        (self.output / 'stale.exec').write_bytes(b'old run')
        with self.assertRaisesRegex(ValueError, 'unrecorded or missing'):
            self.validate()

    def test_manifest_cannot_select_other_files(self):
        self.record['execution'] = {'../../other.exec': '0' * 64}
        self.write()
        with self.assertRaisesRegex(ValueError, 'unexpected recorded'):
            self.validate()


if __name__ == '__main__':
    unittest.main()
