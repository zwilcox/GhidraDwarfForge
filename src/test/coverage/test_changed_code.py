"""Git-diff and counter oracles for the changed-code gate (not JVM execution evidence)."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


SPEC = importlib.util.spec_from_file_location('changed_code', Path(__file__).with_name('changed-code.py'))
changed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(changed)


class ChangedCode(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='forge-changed-coverage-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.java = self.root / 'src/main/java/ghidradwarfforge/Fixture.java'
        self.java.parent.mkdir(parents=True)
        self.java.write_text('package ghidradwarfforge;\nclass Fixture {\n    int value = 1;\n}\n')
        self.git('init', '-q', '--initial-branch=fixture')
        self.base = self.commit()
        self.xml = self.root / 'coverage.xml'

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'user.name=Coverage fixture',
            '-c', 'user.email=coverage@example.invalid', '-c', 'commit.gpgsign=false',
            '-c', 'core.hooksPath=' + str(self.root / 'absent-hooks'), *args], cwd=self.root).decode().strip()

    def commit(self):
        self.git('add', 'src')
        self.git('commit', '-qm', 'coverage fixture', '--allow-empty')
        return self.git('rev-parse', 'HEAD')

    def measured(self, rows=None, name='Fixture.java'):
        document = ET.Element('report')
        source = ET.SubElement(ET.SubElement(document, 'package', name='ghidradwarfforge'),
            'sourcefile', name=name)
        for number, (mi, ci, mb, cb) in (rows or {}).items():
            ET.SubElement(source, 'line', nr=str(number), mi=str(mi), ci=str(ci), mb=str(mb), cb=str(cb))
        ET.ElementTree(document).write(self.xml)

    def report(self, commit=None):
        return changed.report(self.root, self.base, commit or self.git('rev-parse', 'HEAD'),
            self.xml, changed.TARGETS)

    def test_only_modified_lines_count_and_all_their_branches_count(self):
        self.java.write_text(self.java.read_text().replace('value = 1', 'value = flag ? 2 : 3'))
        self.commit()
        self.measured({2: (0, 10, 0, 8), 3: (2, 5, 1, 1), 4: (9, 0, 4, 0)})
        result = self.report()
        self.assertEqual(result['files']['ghidradwarfforge/Fixture.java']['changedLines'], [3])
        self.assertEqual(result['LINE']['percent'], '100.0')
        self.assertEqual(result['BRANCH']['percent'], '50.0')
        self.assertFalse(result['targetsMet'])
        self.assertEqual(result['files']['ghidradwarfforge/Fixture.java']['linesWithUncoveredBranches'], [3])

    def test_new_source_all_executable_lines_included(self):
        added = self.java.with_name('Added.java')
        added.write_text('class Added {\n    int x = 1;\n    int y = 2;\n}\n')
        self.commit()
        self.measured({2: (0, 2, 0, 0), 3: (3, 0, 0, 0)}, 'Added.java')
        result = self.report()
        self.assertEqual(result['LINE']['percent'], '50.0')
        self.assertIsNone(result['BRANCH']['targetMet'])
        self.assertFalse(result['targetsMet'])
        self.assertEqual(result['files']['ghidradwarfforge/Added.java']['uncoveredLines'], [3])

    def test_non_executable_comments_have_explicit_empty_scope(self):
        self.java.write_text(self.java.read_text() + '// explanatory comment\n')
        self.commit()
        self.measured({3: (0, 3, 0, 0)})
        result = self.report()
        self.assertEqual(result['status'], 'NOT_APPLICABLE')
        self.assertIsNone(result['LINE']['percent'])
        self.assertTrue(result['targetsMet'])

    def test_pure_rename_adds_no_scope(self):
        self.java.rename(self.java.with_name('Renamed.java'))
        self.commit()
        self.measured({3: (0, 3, 0, 0)}, 'Renamed.java')
        result = self.report()
        self.assertEqual(result['files'], {})
        self.assertEqual(result['pureRenames'][0]['to'], 'src/main/java/ghidradwarfforge/Renamed.java')
        self.assertEqual(result['status'], 'NOT_APPLICABLE')

    def test_deleted_lines_do_not_count_as_missed_new_code(self):
        self.java.write_text(self.java.read_text().replace('    int value = 1;\n', ''))
        self.commit()
        self.measured()
        result = self.report()
        self.assertEqual(result['files']['ghidradwarfforge/Fixture.java']['changedLines'], [])
        self.assertTrue(result['targetsMet'])

    def test_non_java_change_does_not_change_scope(self):
        (self.root / 'src/test.txt').write_text('test-only change')
        self.commit()
        self.measured({3: (0, 3, 0, 0)})
        self.assertEqual(self.report()['status'], 'NOT_APPLICABLE')

    def test_modified_source_must_exist_in_report(self):
        self.java.write_text(self.java.read_text().replace('value = 1', 'value = 2'))
        self.commit()
        self.measured({}, 'Unrelated.java')
        with self.assertRaisesRegex(ValueError, 'missing from measurement'):
            self.report()

    def test_missing_or_nonancestor_base_cannot_become_empty_scope(self):
        self.measured()
        self.base = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'comparison history'):
            self.report()
        original = self.git('rev-parse', 'HEAD')
        future = self.commit()
        self.base = future
        self.git('checkout', '-q', original)
        with self.assertRaisesRegex(ValueError, 'comparison history'):
            self.report(original)

    def test_dirty_or_wrong_source_commit_cannot_be_measured(self):
        self.measured()
        with self.assertRaisesRegex(ValueError, 'differs from source commit'):
            self.report('e' * 40)
        self.java.write_text('uncommitted changes')
        with self.assertRaisesRegex(ValueError, 'comparison history'):
            self.report()

    def test_untracked_production_source_rejected(self):
        self.measured()
        self.java.with_name('Untracked.java').write_text('class Untracked {}')
        with self.assertRaisesRegex(ValueError, 'uncommitted production'):
            self.report()

    def test_duplicate_negative_or_inconsistent_line_rows_rejected(self):
        for attributes in ('nr="3" mi="-1" ci="2" mb="0" cb="0"',
                'nr="3" mi="0" ci="0" mb="2" cb="0"',
                'nr="0" mi="1" ci="0" mb="0" cb="0"'):
            self.xml.write_text('<report><package name="p"><sourcefile name="X.java"><line '
                + attributes + '/></sourcefile></package></report>')
            with self.subTest(attributes=attributes), self.assertRaises(ValueError):
                self.report()
        self.measured({3: (0, 1, 0, 0)})
        document = ET.parse(self.xml)
        source = document.getroot().find('./package/sourcefile')
        source.append(source.find('line'))
        document.write(self.xml)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.report()

    def test_targets_are_exact_and_rounding_cannot_pass(self):
        self.measured()
        with self.assertRaisesRegex(ValueError, 'accepted milestone'):
            changed.report(self.root, self.base, self.base, self.xml, {**changed.TARGETS, 'line': 80})
        self.assertFalse(changed.metric(8996, 1004, 90)['targetMet'])
        self.assertEqual(changed.metric(8996, 1004, 90)['percent'], '90.0')
        self.assertTrue(changed.metric(85, 15, 85)['targetMet'])
        self.assertFalse(changed.metric(85, 15, 90)['targetMet'])


if __name__ == '__main__':
    unittest.main()
