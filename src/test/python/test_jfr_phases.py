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

    def test_coverage_phases_are_complete_and_bounded(self):
        recording = self.recording()
        for index, phase in enumerate(sorted(phases.COVERAGE_PHASES), start=5):
            event = copy.deepcopy(recording['recording']['events'][1])
            event['values'].update(phase=phase, startTime=f'2026-11-04T12:00:0{index}.123456789-06:00')
            recording['recording']['events'].append(event)
        result = phases.summarize(recording)
        self.assertEqual(result['unattributedExportSeconds'], 6.5)
        self.assertEqual(set(result['phases']), phases.PHASES | phases.COVERAGE_PHASES)
        for field, value in [('completed', False), ('duration', 'PT20S'),
                ('startTime', '2026-11-04T12:00:05.123456789-06:00')]:
            bad = copy.deepcopy(recording)
            bad['recording']['events'][-1]['values'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                phases.summarize(bad)
        for _ in range(2):
            recording['recording']['events'].pop()
            with self.assertRaises(ValueError):
                phases.summarize(recording)

    def test_annotations_preserve_complete_coverage_phase_requirement(self):
        recording = self.recording()
        for index, phase in enumerate(sorted(phases.TYPE_COVERAGE_PHASES | phases.ANNOTATION_PHASES), start=5):
            event = copy.deepcopy(recording['recording']['events'][1])
            event['values'].update(phase=phase, startTime=f'2026-11-04T12:00:0{index}.123456789-06:00')
            recording['recording']['events'].append(event)
        result = phases.summarize(recording)
        self.assertEqual(result['unattributedExportSeconds'], 5.5)
        del recording['recording']['events'][5]
        with self.assertRaises(ValueError):
            phases.summarize(recording)


def recording(names):
    children = sorted(names - {'export'})
    rows = ([('export', 0, 20)] if 'export' in names else []) + [(name, index + 1, 1)
        for index, name in enumerate(children)]
    return {'recording': {'events': [
        {'type': 'ghidradwarfforge.ExportPhase', 'values': {
            'phase': name, 'startTime': f'2026-11-05T00:00:{start:02d}Z',
            'duration': f'PT{duration}S', 'completed': True,
            'eventThread': {'javaThreadId': 7}}}
        for name, start, duration in rows]}}


class PhaseControls(unittest.TestCase):
    def test_export_with_call_site_recovery(self):
        names = phases.PHASES | phases.TYPE_COVERAGE_PHASES | phases.EQUATE_PHASES | {'call-site-recovery'}
        self.assertEqual(phases.summarize(recording(names))['phases']['call-site-recovery']['elapsedSeconds'], 1)
        with self.assertRaises(ValueError):
            phases.summarize(recording(names - {'annotation-inventory'}))

    def test_complete_generations(self):
        for names in phases.COMPLETE_PHASE_SETS:
            with self.subTest(names=names):
                result = phases.summarize(recording(names))
                self.assertEqual(set(result['phases']), names)
                self.assertEqual(result['unattributedExportSeconds'], 21 - len(names))
                self.assertEqual(result['phases']['export']['elapsedSeconds'], 20)

    def test_every_unrecognized_subset_rejected(self):
        names = sorted(phases.CURRENT_PHASES)
        for mask in range(1 << len(names)):
            selected = {name for bit, name in enumerate(names) if mask & (1 << bit)}
            if selected in phases.COMPLETE_PHASE_SETS:
                continue
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                phases.summarize(recording(selected))

    def test_invalid_events_and_timing(self):
        good = recording(phases.PHASES | phases.TYPE_COVERAGE_PHASES)
        for field, value in (('phase', 'invented'), ('completed', False),
                ('eventThread', {'javaThreadId': 8}),
                ('startTime', '2026-11-04T23:59:59Z'),
                ('duration', 'PT21S'), ('duration', 'PT0.0000000001S')):
            bad = copy.deepcopy(good)
            bad['recording']['events'][1]['values'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                phases.summarize(bad)
        bad = copy.deepcopy(good)
        bad['recording']['events'].append(copy.deepcopy(bad['recording']['events'][1]))
        with self.assertRaises(ValueError):
            phases.summarize(bad)
        bad = copy.deepcopy(good)
        bad['recording']['events'][2]['values']['startTime'] = '2026-11-05T00:00:01Z'
        with self.assertRaises(ValueError):
            phases.summarize(bad)


if __name__ == '__main__':
    unittest.main()
