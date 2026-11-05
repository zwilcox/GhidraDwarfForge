"""Reject partial/mixed recordings rather than publishing misleading phase totals."""
import copy
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'performance/jfr-phases.py'
spec = importlib.util.spec_from_file_location('jfr_phases', path)
phases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(phases)


class PhaseSummaryTest(unittest.TestCase):
    def recording(self):
        events = []
        for index, phase in enumerate(['export', 'decompilation-and-source',
                'types-and-storage', 'native-production', 'elf-packaging']):
            events.append({'type': 'ghidradwarfforge.ExportPhase', 'values': {
                'phase': phase, 'completed': True, 'eventThread': {'javaThreadId': 7},
                'startTime': f'2026-11-04T12:00:0{index}.123456789-06:00',
                'duration': 'PT10S' if index == 0 else 'PT0.5S'}})
        return {'recording': {'events': events}}

    def test_inclusive_and_residual(self):
        result = phases.summarize(self.recording())
        self.assertEqual(result['unattributedExportSeconds'], 8)
        self.assertEqual(result['phases']['export']['elapsedSeconds'], 10)
        self.assertEqual(phases.duration_ns('PT1H2M3.000000001S'), 3723000000001)
        self.assertEqual(phases.instant_ns('2026-11-04T12:00:00.123456789-06:00'),
            phases.instant_ns('2026-11-04T18:00:00.123456789Z'))

    def test_reject_unusable_recordings(self):
        original = self.recording()
        variants = []
        missing = copy.deepcopy(original)
        missing['recording']['events'].pop()
        variants.append(missing)
        duplicate = copy.deepcopy(original)
        duplicate['recording']['events'].append(duplicate['recording']['events'][0])
        variants.append(duplicate)
        for key, value in [('completed', False), ('phase', 'unexpected'),
                ('duration', 'PT20S'), ('duration', 'PT-1S'),
                ('eventThread', {'javaThreadId': 8}),
                ('startTime', '2026-11-04T11:59:00Z')]:
            malformed = copy.deepcopy(original)
            malformed['recording']['events'][1]['values'][key] = value
            variants.append(malformed)
        overlap = copy.deepcopy(original)
        overlap['recording']['events'][1]['values']['duration'] = 'PT2S'
        variants.append(overlap)
        for recording in variants:
            with self.subTest(recording=recording), self.assertRaises(ValueError):
                phases.summarize(recording)


if __name__ == '__main__':
    unittest.main()
