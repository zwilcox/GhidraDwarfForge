"""Controls for full source classification and honest threshold arithmetic."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET


SPEC = importlib.util.spec_from_file_location('combined_report', Path(__file__).with_name('combined-report.py'))
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class ReportPolicy(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='forge-combined-policy-')
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'inventory.json'
        self.sources = {'ghidradwarfforge/A.java', 'ghidradwarfforge/B.java', 'ghidradwarfforge/C.java'}
        self.policy = {'schema': 1, 'groups': {
            'binaryAndLocationCorrectness': ['ghidradwarfforge/A.java'],
            'fileTransactionsAndValidation': ['ghidradwarfforge/B.java'],
            'remainingProduction': ['ghidradwarfforge/C.java']},
            'targets': {'overall': {'line': 85, 'branch': 80}, 'eachCriticalGroup': {'line': 95, 'branch': 90}}}

    def inventory(self):
        self.path.write_text(json.dumps(self.policy))
        return report.inventory(self.path, self.sources)

    def test_all_sources_classified_with_no_overlap(self):
        self.assertEqual(self.inventory(), self.policy)

    def test_new_source_requires_explicit_classification(self):
        self.sources.add('ghidradwarfforge/New.java')
        with self.assertRaisesRegex(ValueError, 'every production source'):
            self.inventory()

    def test_duplicate_membership_is_not_a_weighting_workaround(self):
        self.policy['groups']['remainingProduction'].append('ghidradwarfforge/A.java')
        with self.assertRaisesRegex(ValueError, 'every production source'):
            self.inventory()

    def test_dropped_production_source_rejected(self):
        self.policy['groups']['remainingProduction'].clear()
        with self.assertRaisesRegex(ValueError, 'every production source'):
            self.inventory()

    def test_weakened_target_is_not_silently_accepted(self):
        self.policy['targets']['eachCriticalGroup']['branch'] = 80
        with self.assertRaisesRegex(ValueError, 'accepted milestone'):
            self.inventory()

    def test_rounding_cannot_turn_a_miss_into_a_pass(self):
        values = {'LINE': {'covered': 8496, 'missed': 1504}, 'BRANCH': {'covered': 7996, 'missed': 2004}}
        result = report.assessed(values, {'line': 85, 'branch': 80})
        self.assertEqual((result['LINE']['percent'], result['BRANCH']['percent']), ('85.0', '80.0'))
        self.assertFalse(result['LINE']['targetMet'])
        self.assertFalse(result['BRANCH']['targetMet'])

    def test_exact_boundary_passes_and_empty_branch_scope_is_na(self):
        values = {'LINE': {'covered': 85, 'missed': 15}, 'BRANCH': {'covered': 0, 'missed': 0}}
        result = report.assessed(values, {'line': 85, 'branch': 80})
        self.assertTrue(result['LINE']['targetMet'])
        self.assertIsNone(result['BRANCH']['percent'])
        self.assertIsNone(result['BRANCH']['targetMet'])
        self.assertIsNone(report.assessed(values, None)['LINE']['targetMet'])

    def test_source_group_uses_counter_totals_not_average_percentages(self):
        small = {'LINE': {'covered': 1, 'missed': 0}, 'BRANCH': {'covered': 1, 'missed': 0}}
        large = {'LINE': {'covered': 0, 'missed': 99}, 'BRANCH': {'covered': 0, 'missed': 99}}
        result = report.assessed(report.add([small, large]), {'line': 85, 'branch': 80})
        self.assertEqual(result['LINE']['percent'], '1.0')
        self.assertEqual(result['BRANCH']['percent'], '1.0')

    def test_duplicate_negative_and_fractional_counters_rejected(self):
        for xml in (
            '<x><counter type="LINE" covered="1" missed="0"/><counter type="LINE" covered="1" missed="0"/></x>',
            '<x><counter type="LINE" covered="-1" missed="0"/></x>',
            '<x><counter type="BRANCH" covered="1.5" missed="0"/></x>'):
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                report.counters(ET.fromstring(xml))


if __name__ == '__main__':
    unittest.main()
