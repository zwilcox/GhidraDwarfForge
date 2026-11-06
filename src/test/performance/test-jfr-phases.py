#!/usr/bin/env python3
"""Accept complete historical/current phase sets and reject misleading timelines."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('phases',
    Path(__file__).with_name('jfr-phases.py'))
phases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(phases)


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
    def test_complete_generations(self):
        for names in phases.COMPLETE_PHASE_SETS:
            with self.subTest(names=names):
                result = phases.summarize(recording(names))
                self.assertEqual(set(result['phases']), names)
                self.assertEqual(result['unattributedExportSeconds'], 21 - len(names))
                self.assertEqual(result['phases']['export']['elapsedSeconds'], 20)

    def test_every_unrecognized_subset_rejected(self):
        names = sorted(phases.PHASES | phases.TYPE_COVERAGE_PHASES | phases.EQUATE_PHASES)
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
