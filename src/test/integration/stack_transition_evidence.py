"""Retain bounded coverage evidence after the complete stack-transition oracle."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from integration_coverage import digest


def finish_measurement(measured, case, repository, module, before, after, project_before, project_after, labels):
    def read(name):
        return json.loads((case / name).read_text())

    result = read('result.json')
    assert result['status'] == 'PASS' and before == after
    phases = [read(phase + '.json') for phase in ('import', 'fixed', 'repeat')]
    model_hashes = [hashlib.sha256(json.dumps(row['functions'], sort_keys=True).encode()).hexdigest() for row in phases]
    assert len(set(model_hashes)) == 1
    reports = []
    for phase in ('fixed', 'repeat'):
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in (case / (phase + '.log')).read_text().splitlines() if 'GhidraDwarfForge report: {' in line]
        assert report['failure'] is None and not report['failedFunctions'] and report['counts']['functionsFailed'] == 0
        assert report['artifacts']['inputSha256'] == result['inputSha256']
        assert [report['artifacts']['outputSha256'], report['artifacts']['sourceSha256']] == result['artifactSha256']
        reports.append({'phase': phase, 'functionsFailed': report['counts']['functionsFailed'], 'artifacts': report['artifacts']})
    runtime = []
    for variant in ('compiler', 'forge'):
        observed = read(variant + '-gdb.json')
        assert observed['status'] == 'PASS' and observed['exitCodes'] == [0]
        cases = []
        for returned in observed['returned']:
            name, argument = returned['function'], returned['input']
            points = [row for row in observed['points'] if row['function'] == name and row['input'] == argument]
            label = labels[name]
            expected_pcs = [row['address'] for row in label['instructions'] if row['address'] <= label['return']]
            assert [row['linkPc'] for row in points] == expected_pcs
            availability = [any(low <= row['linkPc'] < high for low, high, _, _ in label['locations']) for row in points]
            assert [row['expectedAvailable'] for row in points] == availability
            if variant == 'forge':
                assert [row['available'] for row in points] == availability
                assert all(int(row['value']) == argument for row in points if row['available'])
            bias, = {row['pc'] - row['linkPc'] for row in points}
            physical = [row for row in points if 'rawRegisters' in row and 'stackValues' in row]
            assert physical and (variant != 'compiler' or any('compilerLocals' in row for row in physical))
            cases.append({**returned, 'points': len(points), 'availablePoints': sum(availability),
                'unavailablePoints': len(points) - sum(availability), 'physicalChecks': len(physical),
                'valueChecks': sum(availability) if variant == 'forge' else 0, 'runtimeBias': bias,
                'firstLinkPc': points[0]['linkPc'], 'lastLinkPc': points[-1]['linkPc']})
        assert len(cases) == 36 and Counter(row['function'] for row in cases) == Counter({name: 3 for name in labels})
        runtime.append({'variant': variant, 'status': observed['status'], 'exitCodes': observed['exitCodes'],
            'navigation': observed['navigation'], 'cases': cases, 'rawSha256': digest(case / (variant + '-gdb.json'))})
    locations = read('locations.log')
    assert locations['stack_value_transitions_locations'] == 'PASS' and set(locations['functions']) == set(labels)
    strict = read('strict-checks.log.check.json')
    assert strict['status'] == 'PASS' and strict['uncorroborated_errors'] == 0
    functions = [{'name': name, 'width': row['width'], 'shape': row['shape'], 'entry': row['entry'], 'end': row['end'],
        'return': row['return'], 'instructionPcs': [i['address'] for i in row['instructions'] if i['address'] <= row['return']],
        'locations': row['locations']} for name, row in sorted(labels.items())]
    harness = {str(Path(name).relative_to(repository)): value for name, value in before.items()
        if Path(name).is_relative_to(repository) and Path(name).relative_to(repository).parts[0] in ('src', 'ghidra_scripts')}
    assert digest(module / 'ghidra_scripts/GhidraDwarfForge.java') == digest(repository / 'ghidra_scripts/GhidraDwarfForge.java')
    evidence = {**result, 'status': 'PASS_STACK_TRANSITION_MEASUREMENT',
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'], 'harnessSha256': harness,
        'protectedBefore': before, 'protectedAfter': after, 'projectBefore': project_before, 'projectAfter': project_after,
        'modelHashes': model_hashes, 'reports': reports, 'functions': functions, 'locations': locations,
        'strict': strict, 'runtime': runtime, 'historicalComparisonMeasured': False}
    path = case / 'coverage-oracle.json'
    path.write_text(json.dumps(evidence, indent=4) + '\n')
    assert path.stat().st_size < 1024 * 1024
    measured.finish(path)
