"""Collection integrity controls; bytecode/probe validity has separate real-JVM tests."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile


SPEC = importlib.util.spec_from_file_location('javaexec_coverage',
    Path(__file__).with_name('javaexec-coverage.py'))
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class CollectionIntegrity(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='forge-javaexec-collection-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for folder in ('main', 'test', 'tasks', 'sessions', 'execution'):
            (self.root / folder).mkdir()
        self.production = {'ghidradwarfforge/Production.class': b'production identity'}
        self.tests = {'ghidradwarfforge/Test.class': b'test identity'}
        for folder, values in (('main', self.production), ('test', self.tests)):
            for name, data in values.items():
                path = self.root / folder / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        self.jar = self.root / 'production.jar'
        self.write_jar(self.jar, self.production)
        self.commit = 'a' * 40
        self.run = 'fixture-run'
        self.expected = ['firstSmoke', 'secondSmoke']
        collector.save(self.root / 'expected.json', self.expected)
        for index, task in enumerate(self.expected):
            execution = self.root / 'execution' / (task + '.exec')
            execution.write_bytes(b'execution fixture ' + bytes([index]))
            collector.save(self.root / 'tasks' / (task + '.json'), {'task': task, 'complete': True})
            collector.save(self.root / 'sessions' / (task + '.json'), {
                'schema': 1, 'task': task, 'session': 'forge-javaexec-' + str(index) * 32,
                'complete': True, 'commit': self.commit, 'run': self.run, 'host': 'Linux',
                'jacocoVersion': '0.8.16', 'productionFingerprint': self.independent_fingerprint(self.production),
                'testFingerprint': self.independent_fingerprint(self.tests),
                'executionSha256': hashlib.sha256(execution.read_bytes()).hexdigest()})
        self.args = argparse.Namespace(jar=self.jar, main_classes=[self.root / 'main'],
            test_classes=[self.root / 'test'], tasks=self.root / 'tasks', sessions=self.root / 'sessions',
            executions=self.root / 'execution', expected_tasks=self.root / 'expected.json',
            output=self.root / 'collected', commit=self.commit, run_id=self.run)

    @staticmethod
    def independent_fingerprint(values):
        content = ''.join(name + '\n' + hashlib.sha256(data).hexdigest() + '\n'
            for name, data in sorted(values.items()))
        return hashlib.sha256(content.encode()).hexdigest()

    @staticmethod
    def write_jar(path, values):
        with ZipFile(path, 'w') as archive:
            for name, data in values.items():
                archive.writestr(name, data)

    def validate(self):
        return collector.validate_collection(self.args.output, self.jar, self.expected, self.commit, self.run)

    def test_portable_collection_retains_both_sessions_and_disjoint_populations(self):
        collector.collect(self.args)
        result = self.validate()
        self.assertEqual([row['task'] for row in result['sessions']], self.expected)
        self.assertEqual((result['productionClasses'], result['testClasses']), (1, 1))
        self.assertEqual(collector.jar_classes(self.args.output / 'test-classes.jar'), self.tests)

    def test_compiled_production_must_equal_packaged_classes(self):
        (self.root / 'main/ghidradwarfforge/Production.class').write_bytes(b'different production')
        with self.assertRaisesRegex(ValueError, 'packaged production JAR differs'):
            collector.collect(self.args)
        self.assertFalse(self.args.output.exists())

    def test_negative_task_oracles_and_stale_receipts(self):
        receipt = self.root / 'sessions/firstSmoke.json'
        original = receipt.read_bytes()
        cases = {'complete': False, 'commit': 'b' * 40, 'run': 'another-run',
            'task': 'otherSmoke', 'session': 'untracked-session', 'jacocoVersion': 'wrong-version',
            'productionFingerprint': '0' * 64, 'testFingerprint': '0' * 64,
            'executionSha256': '0' * 64}
        for field, value in cases.items():
            with self.subTest(field=field):
                record = json.loads(original)
                record[field] = value
                collector.save(receipt, record)
                with self.assertRaises(ValueError):
                    collector.collect(self.args)
                self.assertFalse(self.args.output.exists())
        receipt.write_bytes(original)
        collector.save(self.root / 'tasks/firstSmoke.json', {'task': 'firstSmoke', 'complete': False})
        with self.assertRaisesRegex(ValueError, 'behavioral task did not complete'):
            collector.collect(self.args)

    def test_missing_or_additional_execution_is_not_silently_dropped(self):
        extra = self.root / 'execution/extra.exec'
        extra.write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'unexpected collection files'):
            collector.collect(self.args)
        extra.unlink()
        (self.root / 'execution/firstSmoke.exec').unlink()
        with self.assertRaisesRegex(ValueError, 'unexpected collection files'):
            collector.collect(self.args)

    def test_duplicate_session_rejected(self):
        receipt = self.root / 'sessions/secondSmoke.json'
        record = collector.read(receipt)
        record['session'] = collector.read(self.root / 'sessions/firstSmoke.json')['session']
        collector.save(receipt, record)
        with self.assertRaisesRegex(ValueError, 'duplicate JavaExec session'):
            collector.collect(self.args)

    def test_changed_portable_execution_and_receipt_are_rejected(self):
        collector.collect(self.args)
        execution = self.args.output / 'execution/firstSmoke.exec'
        original = execution.read_bytes()
        execution.write_bytes(b'tampered execution')
        with self.assertRaisesRegex(ValueError, 'changed or excessive'):
            self.validate()
        execution.write_bytes(original)
        receipt = self.args.output / 'sessions/firstSmoke.json'
        record = collector.read(receipt)
        record['host'] = 'different-host'
        collector.save(receipt, record)
        with self.assertRaisesRegex(ValueError, 'manifest does not match'):
            self.validate()

    def test_test_production_class_collision_rejected(self):
        path = self.root / 'test/ghidradwarfforge/Production.class'
        path.write_bytes(b'pretend test')
        with self.assertRaisesRegex(ValueError, 'populations overlap'):
            collector.collect(self.args)

    def test_required_task_set_cannot_be_truncated(self):
        collector.collect(self.args)
        with self.assertRaisesRegex(ValueError, 'unexpected collection files'):
            collector.validate_collection(self.args.output, self.jar,
                [*self.expected, 'missingSmoke'], self.commit, self.run)

    def test_symlinked_execution_rejected(self):
        target = self.root / 'execution/firstSmoke.exec'
        original = self.root / 'saved.exec'
        target.rename(original)
        try:
            target.symlink_to(original)
        except OSError as failure:
            self.skipTest('host cannot create test symlink: ' + str(failure))
        with self.assertRaisesRegex(ValueError, 'linked'):
            collector.collect(self.args)


if __name__ == '__main__':
    unittest.main()
