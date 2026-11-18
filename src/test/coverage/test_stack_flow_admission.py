"""Synthetic receipt controls; these are not runtime or coverage evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('stack_admission', Path(__file__).with_name('stack-flow-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture(width=32, role='exec'):
    initial = -1985229329 if width == 32 else -81985529216486895
    names = ['flow_diamond', 'flow_kill', 'flow_bypass', 'flow_loop',
        'flow_loop_kill', 'flow_redefine', 'flow_split']
    labels, locations, prepared = {}, {}, {}
    for index, name in enumerate(names):
        base = 1000 + index * 100
        row = {key: base + offset for key, offset in (
            ('entry', 0), ('live', 1), ('loaded', 3), ('join', 5), ('retired', 6), ('end', 10))}
        if name in ('flow_kill', 'flow_loop_kill'):
            row['changed'] = base + 4
        if name in ('flow_loop', 'flow_loop_kill'):
            row['loop'] = base + 2
        if name == 'flow_split':
            row.update(hole=base + 8, afterhole=base + 9)
        labels[name] = row
        live = ['live'] + (['join'] if name in ('flow_diamond', 'flow_loop', 'flow_redefine', 'flow_split') else [])
        if name == 'flow_loop':
            live += ['loop']
        locations[name] = [{'start': row[key], 'end': row[key] + 1, 'kind': 'stack', 'register': 7, 'offset': -8}
            for key in live]
        prepared[name + '_body'] = [[base, base + 8], [base + 9, base + 10]] if name == 'flow_split' else [[base, base + 10]]
        prepared[name + '_instructions'] = [{'address': base + offset, 'next': base + offset + 1, 'bytes': '90'}
            for offset in range(8)]
    debugger = {mode: {'status': 'PASS', 'navigation': ['next', 'step'], 'exitCode': 0, 'points': [], 'returns': []}
        for mode in ('compiler', 'forge')}
    for seed in (19, -19, initial):
        for choice in (0, 1):
            for name in names:
                row = labels[name]
                path = ['entry']
                if name == 'flow_redefine':
                    path += ['live', 'loaded'] * (choice + 2)
                elif name != 'flow_bypass' or choice:
                    path += ['live']
                if name in ('flow_loop', 'flow_loop_kill'):
                    path += (['loop', 'loaded', 'changed'] if name == 'flow_loop_kill' else ['loop', 'loaded']) * (choice + 2)
                elif name == 'flow_kill' and choice:
                    path += ['changed']
                path += ['join', 'retired']
                value, definitions, visits = -12345, 0, {}
                for marker in path:
                    pc = row[marker]
                    if marker == 'live':
                        value = seed + definitions if name == 'flow_redefine' else seed
                        definitions += 1
                    if marker == 'changed':
                        value ^= 90
                    visits[pc] = visits.get(pc, 0) + 1
                    point = {'function': name, 'seed': seed, 'choice': choice, 'linkPc': pc,
                        'pc': pc + (0 if role == 'exec' else 0x400000), 'visit': visits[pc],
                        'bytes': '90', 'logical': value, 'value': str(value)}
                    debugger['compiler']['points'].append(dict(point))
                    available = any(item['start'] <= pc < item['end'] for item in locations[name])
                    point['available'] = available
                    if available:
                        point['locationValue'] = value
                    else:
                        point['value'] = '<optimized out>'
                    if name == 'flow_redefine' and marker == 'live':
                        point['staleBackup'] = seed + definitions - 2 if definitions > 1 else -23456
                    debugger['forge']['points'].append(point)
                for mode in debugger.values():
                    mode['returns'].append({'function': name, 'seed': seed, 'choice': choice, 'value': value})
    sources = {'src/test/integration/' + name: 'a' * 64 for name in (
        'stack-control-flow-export.py', 'stack-control-flow-gdb.py', 'stack-control-flow-gdb.sh',
        'check-stack-control-flow.py', 'check-stack-first-use.py', 'check-dwarfdump.py',
        'integration_coverage.py', 'ghidra_scripts/PrepareStackControlFlow.java')}
    evidence = {'status': 'PASS_STACK_CONTROL_FLOW_MEASUREMENT', 'target': 'x86_64',
        'width': width, 'role': role, 'previousPackageCompared': False, 'jarSha256': 'a' * 64,
        'harnessSha256': sources, 'protected': {'input': 'b' * 64}, 'artifactSha256': ['c' * 64, 'd' * 64],
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'], 'projectBackupChanges': [],
        'labels': {'order': names, 'width': width // 8, 'initial': initial, 'functions': labels},
        'locations': locations, 'prepared': prepared, 'debugger': debugger}
    record = {'suite': 'stack-control-flow', 'layer': 'headless', 'host': 'posix',
        'productionJarSha256': 'a' * 64, 'sessions': [{'label': name} for name in ('import', 'fixed', 'repeat')]}
    return record, evidence


class Admission(unittest.TestCase):
    def test_all_profiles_and_cohort(self):
        cases = [admission.oracle(*fixture(width, role)) for width in (32, 64) for role in admission.ROLES]
        admission.cohort(cases)
        for index in range(len(cases)):
            with self.assertRaises(ValueError):
                admission.cohort(cases[:index] + cases[index + 1:])
        for changed in (cases + cases[:1], cases[:-1] + cases[:1]):
            with self.assertRaises(ValueError):
                admission.cohort(changed)

    def test_missing_sessions_and_evidence(self):
        record, evidence = fixture()
        for index in range(3):
            changed = copy.deepcopy(record)
            changed['sessions'].pop(index)
            with self.assertRaises(ValueError):
                admission.oracle(changed, evidence)
        for key, value in (('target', 'aarch64'), ('width', True), ('role', 'shared'),
                ('previousPackageCompared', True), ('jarSha256', 'b' * 64), ('harnessSha256', {}),
                ('protected', {}), ('artifactSha256', ['c' * 64]), ('validators', ['readelf']),
                ('projectBackupChanges', ['Effects.rep/program.db']), ('locations', {}), ('debugger', {})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                admission.oracle(record, {**evidence, key: value})
        for name in evidence['harnessSha256']:
            changed = copy.deepcopy(evidence)
            del changed['harnessSha256'][name]
            with self.assertRaises(ValueError):
                admission.oracle(record, changed)

    def test_each_return_and_trace_scenario(self):
        record, evidence = fixture()
        for mode in ('compiler', 'forge'):
            for index in range(42):
                changed = copy.deepcopy(evidence)
                changed['debugger'][mode]['returns'][index]['value'] += 1
                with self.assertRaises(ValueError):
                    admission.oracle(record, changed)
            for key, value in (('status', 'FAIL'), ('exitCode', 1), ('navigation', ['next']), ('points', [])):
                changed = copy.deepcopy(evidence)
                changed['debugger'][mode][key] = value
                with self.assertRaises(ValueError):
                    admission.oracle(record, changed)

    def test_instruction_value_lifetime_and_identity(self):
        record, evidence = fixture(64, 'pie-rebased')
        points = evidence['debugger']['forge']['points']
        available = next(i for i, point in enumerate(points) if point['available'])
        stale = next(i for i, point in enumerate(points) if 'staleBackup' in point)
        for index, key, value in ((0, 'linkPc', 999), (0, 'pc', 1000), (0, 'visit', 2),
                (0, 'logical', 123), (0, 'bytes', 'cc'), (0, 'available', True),
                (available, 'locationValue', 0), (available, 'value', '0'),
                (available, 'available', False), (stale, 'staleBackup', 19), (0, 'value', '7')):
            changed = copy.deepcopy(evidence)
            changed['debugger']['forge']['points'][index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                admission.oracle(record, changed)
        changed = copy.deepcopy(evidence)
        changed['debugger']['forge']['points'].pop(available)
        with self.assertRaises(ValueError):
            admission.oracle(record, changed)


if __name__ == '__main__':
    unittest.main()
