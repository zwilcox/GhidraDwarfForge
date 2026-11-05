#!/usr/bin/env python3
"""Measure production compression on pinned saved workloads, with full consumer checks."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import tempfile


SOURCE = Path(__file__).resolve().parent
PERFORMANCE = SOURCE.parent / 'performance'


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference_case', type=Path)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--workload', choices=('sqlite', 'uboot'), required=True)
    parser.add_argument('--pairs', type=int, default=5)
    args = parser.parse_args()
    if not 3 <= args.pairs <= 10:
        parser.error('use 3..10 pairs')
    assert not os.environ.get('JAVA_TOOL_OPTIONS'), 'uncontrolled JVM options'
    support = load(PERFORMANCE / 'export-benchmark.py')
    consumer = load(PERFORMANCE / 'host-consumer.py')
    compression = load(SOURCE / 'compression-export.py')
    reference = args.reference_case.resolve(strict=True)
    summary = json.loads((reference / 'summary.json').read_text())
    assert summary['status'] == 'PASS'
    if args.workload == 'uboot':
        built = Path(summary['buildCase']).resolve(strict=True)
        receipt = json.loads((built / 'build-result.json').read_text())
        assert receipt['status'] == 'PASS' and receipt['version'] == '2025.01'
        assert receipt['archiveSha256'] == 'cdef7d507c93f1bbd9f015ea9bc21fa074268481405501945abc6f854d5b686f'
        for name, row in receipt['artifacts'].items():
            assert support.digest(built / name) == row['sha256']
        binary, compiler, program = built / 'u-boot.workload', built / 'u-boot.reference', 'UBoot'
        expected = json.loads((reference / 'export-0.report.json').read_text())
        addresses = json.loads((reference / 'function-addresses.json').read_text())
        workload = {'name': 'uboot', 'kind': 'pie', 'addresses': addresses, 'dtb': 'u-boot.dtb'}
    else:
        built, binary, compiler, program = reference, reference / 'sqlite-workload', None, 'SQLite'
        receipt = json.loads((reference / 'source-provenance.json').read_text())
        assert receipt['archiveSha256'] == '77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784'
        assert support.digest(binary) == summary['inputSha256']
        expected = json.loads((reference / 'export-0.report.json').read_text())
        addresses = {}
        for line in (reference / 'symbols.log').read_text().splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[2] in ('main', 'benchmark_checkpoint', 'sqlite3_step', 'sqlite3_exec'):
                assert fields[2] not in addresses
                addresses[fields[2]] = int(fields[0], 16)
        assert len(addresses) == 4
        workload = {'name': 'sqlite', 'kind': 'exec', 'addresses': addresses}
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    for line in (module / 'RELEASE-SHA256SUMS').read_text().splitlines():
        digest, name = line.split(None, 1)
        path = (module / name.lstrip('*')).resolve(strict=True)
        assert path.is_relative_to(module.resolve()) and support.digest(path) == digest
    root = SOURCE.parents[2] / 'build/test-results/compression-workload'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.workload + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        return support.run(command, case / (name + '.log'), **kwargs)

    protected = {Path(__file__).resolve(), SOURCE / 'compression-export.py',
        PERFORMANCE / 'export-benchmark.py', PERFORMANCE / 'headless-observations.py',
        PERFORMANCE / 'host-consumer.py', PERFORMANCE / 'jfr-phases.py', binary,
        ghidra / 'support/launch.properties', reference / 'summary.json'}
    for directory in (reference / 'project', module):
        protected.update(p for p in directory.rglob('*') if p.is_file())
    if compiler is not None:
        protected.update((compiler, built / 'u-boot.dtb', built / 'build-result.json'))
    before = {str(p): support.digest(p) for p in sorted(protected)}
    write('protected-before.json', before)
    project = case / 'project'
    shutil.copytree(reference / 'project', project)
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    write('environment.json', {'host': platform.platform(), 'loadAverage': os.getloadavg(),
        'workload': workload, 'pairs': args.pairs, 'reference': str(reference),
        'jarSha256': support.digest(module / 'lib/GhidraDwarfForge.jar'),
        'scope': 'Same installed exporter and copied saved program, alternating none/zlib pairs. '
            'GNU time covers fresh wrapper/JVM/export, excluding analysis, validators and GDB. '
            'CPU includes descendants; RSS is process-family high water, not summed memory. '
            'Warm caches and host load uncontrolled. Profiles are separate from timed populations.'})
    output = case / (binary.name + '.dbg')
    samples, modes, semantic = [], {}, None
    def validate_mode(mode):
        sidecar = output
        validation = case / ('validation-' + mode)
        validation.mkdir()
        for label, command in [('llvm', ['llvm-dwarfdump', '--verify', sidecar]),
                ('strict', ['python3', SOURCE / 'check-dwarfdump.py', sidecar,
                    validation / 'strict-checks.log', '--original', binary]),
                *[(view, ['readelf', '--debug-dump=' + view, sidecar])
                    for view in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc')],
                ('identity', ['readelf', '-h', '-SW', '-n', binary, sidecar])]:
            support.run(command, validation / (label + '.log'), timeout=600)
            support.require_clean(validation / (label + '.log'))
        consumer.validate_gdb(workload, built, validation, case, sidecar, binary, compiler)

    sequence = [(pair, mode, False) for pair in range(args.pairs)
        for mode in (('none', 'zlib') if pair % 2 == 0 else ('zlib', 'none'))]
    sequence += [(args.pairs, mode, True) for mode in ('none', 'zlib')]
    for pair, mode, profile in sequence:
        name = ('profile-' if profile else str(pair) + '-') + mode
        print(name, flush=True)
        command = [module / 'support/ghidra-dwarf-forge-headless', '--ghidra-dir=' + str(ghidra),
            '--project-dir=' + str(project), '--project-name=' + program, '--program=' + binary.name,
            '--input=' + str(binary), '--output=' + str(output), '--compress-debug-sections=' + mode]
        try:
            if profile:
                os.environ['JAVA_TOOL_OPTIONS'] = '-Xlog:jfr+startup=off -XX:StartFlightRecording=filename=' + \
                    str(case / (name + '.jfr')) + ',settings=profile,dumponexit=true'
            sample = run(name, command, measured=True, timeout=1800)
        finally:
            os.environ.pop('JAVA_TOOL_OPTIONS', None)
        sample['runtime'] = support.verify_headless(case / (name + '.log'), module, exported=True)
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in (case / (name + '.log')).read_text().splitlines()
            if 'GhidraDwarfForge report: {' in line]
        assert report['failure'] is None
        for key in ('status', 'counts', 'failedFunctions', 'skippedFunctions'):
            assert report[key] == expected[key], key
        write(name + '.report.json', report)
        observed = compression.sections(output)
        plain = {name: value['plainSha256'] for name, value in observed.items()}
        current = {'sections': plain, 'source': support.digest(Path(str(output) + '.c'))}
        if semantic is None:
            semantic = current
        assert current == semantic, 'source or decompressed DWARF changed'
        assert any(row['compressed'] for row in observed.values()) == (mode == 'zlib')
        value = {'sha256': support.digest(output), 'bytes': output.stat().st_size, 'sections': observed}
        if mode not in modes:
            modes[mode] = value
            shutil.copyfile(output, case / (mode + '.dbg'))
        assert value == modes[mode], 'mode output is nondeterministic'
        sample.update(pair=pair, mode=mode, artifactSha256=value['sha256'])
        if profile:
            write(name + '.metrics.json', sample)
            run(name + '-events', [Path(os.environ['JAVA_HOME']) / 'bin/jfr', 'print', '--json',
                '--events', 'ghidradwarfforge.ExportPhase', case / (name + '.jfr')])
            run(name + '-phases', ['python3', PERFORMANCE / 'jfr-phases.py',
                case / (name + '-events.log'), case / (name + '-summary.json')])
            # Validate the actual just-published pair before another export
            # rewrites its source timestamp. Do not suppress GDB's stale-source warning.
            validate_mode(mode)
            shutil.copy2(output, case / (mode + '.dbg'))
            shutil.copy2(Path(str(output) + '.c'), case / (mode + '.dbg.c'))
        else:
            samples.append(sample)
            write('samples.json', samples)
    assert modes['zlib']['bytes'] < modes['none']['bytes']
    after = {str(p): support.digest(p) for p in sorted(protected)}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changed = [p for p in project_before.keys() | project_after.keys() if project_before.get(p) != project_after.get(p)]
    assert set(changed) <= {program + '.rep/idata/~index.bak', program + '.rep/idata/~journal.bak'}, changed
    write('summary.json', {'status': 'PASS', 'workload': workload, 'samples': samples, 'modes': modes,
        'semantic': semantic, 'projectBackupChanges': changed, 'protectedUnchanged': True,
        'mediansSeconds': {mode: statistics.median(s['elapsedSeconds'] for s in samples if s['mode'] == mode)
            for mode in modes}, 'maximumResidentKiB': {mode: max(s['maximumResidentKiB'] for s in samples
                if s['mode'] == mode) for mode in modes},
        'scope': 'Paired production opt-in storage comparison on one Linux host; no general speed or memory claim.'})
    print('compression-workload=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
