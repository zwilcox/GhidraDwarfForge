#!/usr/bin/env python3
"""Reject unexplained bytecode drift, wrong Java levels and corrupt package manifests."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('package',
    Path(__file__).with_name('coverage-measurement-package.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageControls(unittest.TestCase):
    def test_changed_source_roots(self):
        old = {'p/A.class': b'a', 'p/A$1.class': b'b', 'p/B.class': b'c'}
        new = {'p/A.class': b'd', 'p/A$Nested.class': b'e', 'p/B.class': b'c', 'p/C.class': b'f'}
        sources = {'p/A.java': b'old', 'p/B.java': b'same'}
        current = {'p/A.java': b'new', 'p/B.java': b'same', 'p/C.java': b'added'}
        result = package.audit_classes(old, new, sources, current)
        self.assertEqual(result['changed'], ['p/A.class'])
        self.assertEqual(result['added'], ['p/A$Nested.class', 'p/C.class'])
        self.assertEqual(result['removed'], ['p/A$1.class'])
        self.assertEqual(result['unchangedShared'], 1)
        for kind in ('change', 'add', 'remove'):
            altered = copy.deepcopy(new)
            if kind == 'change':
                altered['p/B.class'] = b'drift'
            elif kind == 'add':
                altered['p/B$Invented.class'] = b'drift'
            else:
                del altered['p/B.class']
            with self.subTest(kind=kind), self.assertRaisesRegex(AssertionError, 'unexplained bytecode drift'):
                package.audit_classes(old, altered, sources, current)

    def test_class_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary)
            (module / 'lib').mkdir()
            source_zip = module / 'lib/GhidraDwarfForge-src.zip'
            with zipfile.ZipFile(source_zip, 'w') as archive:
                archive.writestr('src/main/java/p/A.java', 'class A {}')
            jar = module / 'lib/GhidraDwarfForge.jar'
            java21 = b'\xca\xfe\xba\xbe\x00\x00\x00\x41'
            for name, value, accepted in [('p/A.class', java21, True),
                    ('p/A.class', java21[:-1] + b'\x42', False),
                    ('p/Unknown.class', java21, False), ('p/A.class', b'garbage', False)]:
                with zipfile.ZipFile(jar, 'w') as archive:
                    archive.writestr(name, value)
                with self.subTest(name=name, value=value):
                    if accepted:
                        self.assertEqual(set(package.inventory(module)[0]), {name})
                    else:
                        with self.assertRaises(AssertionError):
                            package.inventory(module)
            with zipfile.ZipFile(jar, 'w') as archive:
                archive.writestr('p/A.class', java21[:-1] + b'\x45')
            self.assertIn('p/A.class', package.inventory(module, 69)[0])
            with self.assertRaises(AssertionError):
                package.inventory(module, 65)

    def test_production_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = {'baseline': 'a' * 40, 'candidate': 'b' * 40}
            receipts, installations = {}, {}
            for index, (role, commit) in enumerate(expected.items()):
                ghidra = root / (role + '-sdk')
                installations[role] = ghidra
                module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
                module.mkdir(parents=True)
                properties = b'version=12.2\n'
                (module / 'extension.properties').write_bytes(properties)
                manifest = (package.digest(properties) + '  extension.properties\n').encode()
                (module / 'RELEASE-SHA256SUMS').write_bytes(manifest)
                directory = root / role
                directory.mkdir()
                release = directory / 'release.zip'
                with zipfile.ZipFile(release, 'w') as archive:
                    archive.write(module / 'RELEASE-SHA256SUMS', 'GhidraDwarfForge/RELEASE-SHA256SUMS')
                    archive.write(module / 'extension.properties', 'GhidraDwarfForge/extension.properties')
                download = root / (role + '.zip')
                with zipfile.ZipFile(download, 'w') as archive:
                    archive.write(release, release.name)
                digest = package.digest(download.read_bytes())
                receipts[role] = {'requestedSha': commit, 'run': {'head_sha': commit, 'id': index},
                    'verifiedArchiveSha256': digest, 'artifact': {'digest': 'sha256:' + digest}}
            (root / 'receipts.json').write_text(json.dumps(receipts))
            result = package.installed_production(root, installations, expected)
            self.assertEqual({role: row['commit'] for role, row in result.items()}, expected)
            with self.assertRaises(AssertionError):
                package.installed_production(root, installations, dict(expected, candidate='c' * 40))
            (installations['baseline'] / 'Ghidra/Extensions/GhidraDwarfForge/extension.properties').write_text('version=12.0.3\n')
            with self.assertRaises(AssertionError):
                package.installed_production(root, installations, expected)

    def test_manifest_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary)
            payload = module / 'payload'
            payload.write_bytes(b'actual')
            expected = package.digest(b'actual')
            manifest = module / 'RELEASE-SHA256SUMS'
            manifest.write_text(expected + '  payload\n', encoding='utf-8')
            self.assertEqual(package.manifest(module), {'payload': expected})
            payload.write_bytes(b'changed')
            with self.assertRaisesRegex(AssertionError, 'manifest mismatch'):
                package.manifest(module)
            payload.write_bytes(b'actual')
            (module / 'untracked').write_bytes(b'new')
            with self.assertRaisesRegex(AssertionError, 'unmanifested'):
                package.manifest(module)
            manifest.write_text((expected + '  payload\n') * 2, encoding='utf-8')
            with self.assertRaises(AssertionError):
                package.manifest(module)


if __name__ == '__main__':
    unittest.main()
