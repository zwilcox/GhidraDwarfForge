#!/usr/bin/env python3
"""Group provenance controls using synthetic receipts, not real JaCoCo probes."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('coverage_groups', HERE / 'integration-coverage-groups.py')
groups = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(groups)
INVENTORY = json.loads((HERE / 'integration-groups.json').read_text())
COMMIT = 'a' * 40


class GroupCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='forge-group-controls-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.jar = self.root / 'production.jar'
        with ZipFile(self.jar, 'w') as archive:
            archive.writestr('ghidradwarfforge/Fixture.class', b'not real bytecode')
        self.agent = self.root / 'agent.jar'
        self.agent.write_bytes(b'not a real agent')
        self.oracle = self.root / 'oracle.json'
        groups.coverage.save(self.oracle, {'status': 'PASS_SYNTHETIC_RECEIPT'})
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.identity = {'commit': COMMIT, 'run': '987', 'attempt': 2, 'target': 'mips32be'}
        self.collections = {}
        for group in ['primary', 'abi32', 'abi64']:
            root = self.inputs / group
            identity = {**self.identity, 'group': group, 'job': 'target-integration'}
            env = {'GITHUB_ACTIONS': 'true', 'GITHUB_JOB': 'target-integration', 'GITHUB_SHA': COMMIT,
                'GITHUB_RUN_ID': '987', 'GITHUB_RUN_ATTEMPT': '2', 'FORGE_CI_TARGET': 'mips32be',
                'FORGE_CI_GROUP': group}
            with patch.dict(os.environ, env):
                collection = groups.coverage.Collection('group-fixture', self.jar, 'native-java', environment={
                    'FORGE_INTEGRATION_COVERAGE_AGENT': str(self.agent),
                    'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(root / 'collections')})
                with collection.session(['java', 'Fixture'], group):
                    (collection.root / collection.record['sessions'][0]['file']).write_bytes(b'not real probes')
                collection.finish(self.oracle)
            self.collections[group] = collection
            groups.seal(root, self.jar, INVENTORY, identity)

    def admit(self):
        return groups.admit(self.inputs, self.jar, INVENTORY, **self.identity)

    def merge(self):
        output = self.root / 'merged'
        groups.merge(self.inputs, output, self.jar, INVENTORY, **self.identity)
        return output

    def verify(self, output):
        return groups.verify_merged(output, self.jar, INVENTORY,
            commit=COMMIT, run='987', target='mips32be')

    def test_complete_group_roundtrip_keeps_provenance(self):
        output = self.merge()
        result = self.verify(output)
        self.assertEqual({'primary', 'abi32', 'abi64'}, set(result['groups']))
        self.assertEqual(3, sum(row['sessions'] for row in result['groups'].values()))
        self.assertEqual(2, result['attempt'])
        for collection in self.collections.values():
            self.assertEqual('mips32be', collection.record['ciGroup']['target'])

    def test_empty_group_is_required_and_explicit(self):
        root = self.inputs / 'abi32'
        shutil.rmtree(root / 'collections')
        identity = groups.read(root / 'group.json')['identity']
        (root / 'group.json').unlink()
        groups.seal(root, self.jar, INVENTORY, identity)
        self.assertEqual(0, self.verify(self.merge())['groups']['abi32']['sessions'])

    def test_empty_group_survives_file_only_artifact_transport(self):
        root = self.inputs / 'abi32'
        shutil.rmtree(root / 'collections')
        identity = groups.read(root / 'group.json')['identity']
        (root / 'group.json').unlink()
        groups.seal(root, self.jar, INVENTORY, identity)
        (root / 'collections').rmdir()
        result = self.verify(self.merge())
        self.assertEqual(0, result['groups']['abi32']['sessions'])
        self.assertEqual(2, sum(group['sessions'] for group in result['groups'].values()))

    def test_nonempty_group_cannot_disappear_during_transport(self):
        shutil.rmtree(self.inputs / 'abi32/collections')
        with self.assertRaisesRegex(ValueError, 'payload changed after sealing'):
            self.admit()

    def test_missing_and_extra_group_rejected(self):
        root = self.inputs / 'abi64'
        root.rename(self.root / 'held')
        with self.assertRaisesRegex(ValueError, 'missing or extra'):
            self.admit()
        (self.root / 'held').rename(root)
        shutil.copytree(root, self.inputs / 'duplicate')
        with self.assertRaisesRegex(ValueError, 'missing or extra'):
            self.admit()

    def test_duplicate_group_identity_rejected(self):
        path = self.inputs / 'abi32/group.json'
        manifest = groups.read(path)
        manifest['identity']['group'] = 'primary'
        groups.coverage.save(path, manifest)
        with self.assertRaises(ValueError):
            self.admit()

    def test_stale_mismatched_and_unknown_manifests(self):
        path = self.inputs / 'primary/group.json'
        original = groups.read(path)
        for key, value in [('commit', 'b' * 40), ('run', '986'), ('attempt', 1),
                ('target', 'mips32le'), ('group', 'unknown'), ('job', 'other')]:
            changed = copy.deepcopy(original)
            changed['identity'][key] = value
            groups.coverage.save(path, changed)
            with self.subTest(field=key):
                with self.assertRaises(ValueError):
                    self.admit()
        groups.coverage.save(path, original)
        for field in ('inventorySha256', 'productionJarSha256'):
            changed = copy.deepcopy(original)
            changed[field] = 'c' * 64
            groups.coverage.save(path, changed)
            with self.assertRaisesRegex(ValueError, 'mismatched'):
                self.admit()

    def test_collection_identity_cannot_be_relabelled_by_manifest(self):
        collection = self.collections['primary']
        collection.record['ciGroup']['group'] = 'abi64'
        collection._save()
        with self.assertRaisesRegex(ValueError, 'different integration group'):
            self.admit()

    def test_collector_rejects_partial_identity(self):
        environment = {'FORGE_CI_TARGET': 'arm32'}
        with self.assertRaisesRegex(ValueError, 'incomplete grouped'):
            groups.coverage.ci_group_identity(environment)
        self.assertIsNone(groups.coverage.ci_group_identity({}))

    def test_duplicate_session_across_valid_groups_rejected(self):
        source = self.collections['primary']
        destination = self.collections['abi32']
        old = destination.record['sessions'][0]
        (destination.root / old['file']).unlink()
        replacement = copy.deepcopy(source.record['sessions'][0])
        destination.record['sessions'][0] = replacement
        shutil.copyfile(source.root / replacement['file'], destination.root / replacement['file'])
        destination._save()
        root = self.inputs / 'abi32'
        identity = groups.read(root / 'group.json')['identity']
        (root / 'group.json').unlink()
        groups.seal(root, self.jar, INVENTORY, identity)
        with self.assertRaisesRegex(ValueError, 'duplicate session'):
            self.admit()

    def test_changed_probe_bytes_rejected(self):
        collection = self.collections['primary']
        (collection.root / collection.record['sessions'][0]['file']).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'execution data changed'):
            self.admit()

    def test_symlinks_and_unrecorded_payload_rejected(self):
        collection = self.collections['primary']
        extra = collection.root / 'unrecorded.txt'
        extra.write_text('extra')
        with self.assertRaisesRegex(ValueError, 'unexpected grouped'):
            self.admit()
        extra.unlink()
        extra.symlink_to(self.oracle)
        with self.assertRaisesRegex(ValueError, 'invalid grouped'):
            self.admit()

    def test_merged_group_omission_rejected(self):
        output = self.merge()
        path = output / 'groups.json'
        evidence = groups.read(path)
        del evidence['groups']['abi32']
        groups.coverage.save(path, evidence)
        with self.assertRaisesRegex(ValueError, 'incomplete or mismatched'):
            self.verify(output)

    def test_merged_collection_identity_and_bytes_rechecked(self):
        output = self.merge()
        name = self.collections['primary'].root.name
        path = output / 'collections' / name / 'receipt.json'
        receipt = groups.read(path)
        receipt['ciGroup']['attempt'] = 1
        groups.coverage.save(path, receipt)
        with self.assertRaisesRegex(ValueError, 'group identity changed'):
            self.verify(output)

    def test_over_budget_payload_rejected_before_receipt_parse(self):
        collection = self.collections['primary']
        path = collection.root / collection.record['sessions'][0]['file']
        with path.open('r+b') as stream:
            stream.truncate(groups.coverage.MAX_EXEC_BYTES + 1)
        with self.assertRaisesRegex(ValueError, 'invalid grouped coverage payload'):
            self.admit()

    def test_target_budget_applies_across_groups(self):
        sizes = [sum(path.stat().st_size for path in collection.root.iterdir())
            for collection in self.collections.values()]
        with patch.object(groups, 'MAX_BYTES', max(sizes) + 1):
            with self.assertRaisesRegex(ValueError, 'target coverage exceeds size budget'):
                self.admit()


if __name__ == '__main__':
    unittest.main()
