#!/usr/bin/env python3
"""Pinned real-application workload; separate import, repeated exports and JFR."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import tempfile
import zipfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('benchmark_support', source / 'export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
URL = 'https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip'
SOURCE_ID = '2024-08-13 09:16:08 c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6fc2b6c60e91b16c63f69a1e33'
ARCHIVE_SHA256 = '77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784'
SOURCE_SHA3 = '186a1baa476b6d546de155160ca6d30ff7b7e6ee375f0bb6445e1a3d180a7dad'

def project_changes(before, after):
    # The pinned Ghidra project filesystem rotates backup index/journal files
    # even when the Program is opened read-only. Retain and report that evidence.
    changes = [{'path': name, 'before': before.get(name), 'after': after.get(name)}
        for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)]
    allowed = {'SQLite.rep/idata/~index.bak', 'SQLite.rep/idata/~journal.bak'}
    assert all(row['path'] in allowed for row in changes), 'program or non-backup project bytes changed'
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--profile', action='store_true')
    args = parser.parse_args()
    if not 2 <= args.repeats <= 10:
        parser.error('repeats must be between 2 and 10')
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    repository = source.parents[2]
    root = repository / 'build/test-results/sqlite-benchmark'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='run.', dir=root))
    print('sqlite benchmark: ' + str(case), flush=True)
    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')
    def run(name, command, **kwargs):
        return support.run(command, case / (name + '.log'), **kwargs)
    protected = [source / 'sqlite-benchmark.py', source / 'export-benchmark.py', source / 'fixtures/sqlite-workload.c']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    write('environment.json', {'host': platform.platform(), 'cpuCount': os.cpu_count(),
        'loadAverageAtStart': os.getloadavg(), 'ghidra': str(ghidra), 'repeats': args.repeats,
        'jarSha256': support.digest(module / 'lib/GhidraDwarfForge.jar'),
        'measurementBoundary': 'Fresh JVM per export, including startup/decompilation; GNU time process-family high-water RSS, not aggregate concurrent memory. Warm caches and other host work are not controlled.',
        'sqliteSourceUrl': URL, 'sqliteSourceId': SOURCE_ID, 'sqliteSourceSha3_256': SOURCE_SHA3,
        'primaryReference': 'https://www.sqlite.org/releaselog/3_46_1.html',
        'license': 'Public domain SQLite deliverable; https://www.sqlite.org/copyright.html'})
    for tool in ('gcc', 'readelf', 'llvm-dwarfdump', 'gdb-multiarch', 'java'):
        run('version-' + tool, [tool, '--version'])
    archive = case / 'sqlite.zip'
    run('download', ['curl', '--fail', '--location', '--retry', '3', '--max-time', '120', URL, '--output', archive])
    assert support.digest(archive) == ARCHIVE_SHA256
    amalgamation = case / 'amalgamation'
    amalgamation.mkdir()
    with zipfile.ZipFile(archive) as zipped:
        for name in ('sqlite3.c', 'sqlite3.h'):
            (amalgamation / name).write_bytes(zipped.read('sqlite-amalgamation-3460100/' + name))
    assert hashlib.sha3_256((amalgamation / 'sqlite3.c').read_bytes()).hexdigest() == SOURCE_SHA3
    assert ('#define SQLITE_SOURCE_ID      "' + SOURCE_ID + '"') in (amalgamation / 'sqlite3.c').read_text()
    write('source-provenance.json', {'archiveSha256': support.digest(archive),
        'files': {name: support.digest(amalgamation / name) for name in ('sqlite3.c', 'sqlite3.h')}})
    binary = case / 'sqlite-workload'
    run('compile', ['gcc', '-O2', '-g0', '-fno-pie', '-no-pie', '-fno-omit-frame-pointer', '-DSQLITE_THREADSAFE=0',
        '-I' + str(amalgamation), amalgamation / 'sqlite3.c', source / 'fixtures/sqlite-workload.c', '-ldl', '-lm', '-o', binary], timeout=300)
    input_hash = support.digest(binary)
    run('plain', [binary])
    support.require_clean(case / 'plain.log')
    assert (case / 'plain.log').read_text() == 'sqlite-workload=PASS count=100 sum=5050\n'
    run('symbols', ['nm', '-n', binary])
    addresses = {}
    wanted = {'benchmark_checkpoint', 'sqlite3_step', 'sqlite3_exec', 'main'}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in wanted:
            addresses[fields[2]] = int(fields[0], 16)
    assert addresses.keys() == wanted
    project = case / 'project'
    project.mkdir()
    imported = run('import', [ghidra / 'support/analyzeHeadless', project, 'SQLite', '-import', binary,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '1200', '-max-cpu', '4'], timeout=1800, measured=True)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    wrapper = module / 'support/ghidra-dwarf-forge-headless'
    sidecar = case / 'sqlite-workload.dbg'
    command = [wrapper, '--ghidra-dir=' + str(ghidra), '--project-dir=' + str(project), '--project-name=SQLite',
        '--program=sqlite-workload', '--input=' + str(binary), '--output=' + str(sidecar)]
    samples, hashes = [], None
    for iteration in range(args.repeats + int(args.profile)):
        profiling = iteration == args.repeats
        name = 'profile' if profiling else 'export-' + str(iteration)
        print('sqlite benchmark: ' + name, flush=True)
        previous_options = os.environ.get('JAVA_TOOL_OPTIONS')
        try:
            if profiling:
                os.environ['JAVA_TOOL_OPTIONS'] = (previous_options or '') + ' -Xlog:jfr+startup=off -XX:StartFlightRecording=filename=' + str(case / 'export.jfr') + ',settings=profile,dumponexit=true'
            sample = run(name, command, timeout=1800, measured=True)
        finally:
            if previous_options is None:
                os.environ.pop('JAVA_TOOL_OPTIONS', None)
            else:
                os.environ['JAVA_TOOL_OPTIONS'] = previous_options
        lines = [line.split('GhidraDwarfForge report: ', 1)[1] for line in (case / (name + '.log')).read_text().splitlines()
            if 'GhidraDwarfForge report: ' in line]
        assert len(lines) == 1
        report, end = json.JSONDecoder().raw_decode(lines[0])
        assert lines[0][end:].strip() in ('', '(GhidraScript)') and report['failure'] is None
        write(name + '.report.json', report)
        observed = [support.digest(sidecar), support.digest(Path(str(sidecar) + '.c'))]
        if hashes is not None:
            assert hashes == observed, 'nondeterministic repeated export'
        hashes = observed
        assert support.digest(binary) == input_hash
        sample.update({'counts': report['counts'], 'status': report['status'], 'profiled': profiling})
        if not profiling:
            samples.append(sample)
        else:
            write('profile.metrics.json', sample)
        write('samples.json', samples)
    strict = source.parent / 'integration/check-dwarfdump.py'
    for name, argv in [('llvm', ['llvm-dwarfdump', '--verify', sidecar]),
            ('strict', ['python3', strict, sidecar, case / 'strict-checks.log', '--original', binary]),
            *[(view, ['readelf', '--debug-dump=' + view, sidecar]) for view in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc')],
            ('header', ['readelf', '-h', sidecar]), ('sections', ['readelf', '-SW', sidecar]), ('notes', ['readelf', '-n', sidecar])]:
        run(name, argv, timeout=300)
        support.require_clean(case / (name + '.log'))
    assert 'No errors.' in (case / 'llvm.log').read_text()
    behavior = case / 'behavior.gdb'
    behavior.write_text('\n'.join([
        'set pagination off', 'set confirm off', 'set debuginfod enabled off', 'set auto-solib-add off',
        'set disable-randomization off', 'set startup-with-shell off',
        'file ' + str(binary), 'symbol-file ' + str(sidecar), 'python',
        'exits = []', 'gdb.events.exited.connect(lambda event: exits.append(getattr(event, "exit_code", None)))',
        'expected = ' + repr(addresses),
        'for name, address in expected.items():',
        '    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)',
        '    assert symbol is not None and symbol.is_function and symbol.type.code == gdb.TYPE_CODE_FUNC, name',
        '    assert symbol.symtab is not None and symbol.symtab.filename.endswith(".dbg.c"), name',
        '    assert int(gdb.parse_and_eval("&" + name)) == address, name',
        'end', 'ptype benchmark_checkpoint', 'list benchmark_checkpoint',
        'break *benchmark_checkpoint', 'run',
        'python assert int(gdb.parse_and_eval("$pc")) == expected["benchmark_checkpoint"]',
        'python assert int(gdb.parse_and_eval("*(unsigned int*)&observed_count")) == 100',
        'python assert int(gdb.parse_and_eval("*(unsigned int*)&observed_sum")) == 5050',
        'disable breakpoints', 'next', 'python',
        'if not exits: gdb.execute("step")',
        'if not exits: gdb.execute("continue")',
        'assert exits == [0]', 'end', 'echo sqlite-benchmark-gdb=PASS\\n', '']))
    run('gdb', ['gdb-multiarch', '-q', '-nx', '-batch', '-x', behavior], timeout=180)
    support.require_clean(case / 'gdb.log')
    assert 'sqlite-benchmark-gdb=PASS' in (case / 'gdb.log').read_text()
    after = {str(p): support.digest(p) for p in protected}
    write('protected-after.json', after)
    assert before == after and support.digest(binary) == input_hash
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    metadata_changes = project_changes(project_before, project_after)
    summary = {'status': 'PASS', 'inputSha256': input_hash, 'inputBytes': binary.stat().st_size,
        'sidecarBytes': sidecar.stat().st_size, 'sourceBytes': Path(str(sidecar) + '.c').stat().st_size,
        'artifactSha256': hashes, 'import': imported, 'exports': samples,
        'exportMedianSeconds': statistics.median(row['elapsedSeconds'] for row in samples),
        'exportMaximumResidentKiB': max(row['maximumResidentKiB'] for row in samples),
        'counts': samples[-1]['counts'], 'strict': json.loads((case / 'strict-checks.log.check.json').read_text()),
        'determinism': 'PASS', 'originalAndProgramDatabaseBytesUnchanged': True, 'projectMetadataChanges': metadata_changes, 'gdbBehavior': 'PASS',
        'gdbBehaviorScope': 'Named DWARF functions, addresses, synthetic source, raw global values, next/step and normal exit; recovered signature correctness is a separate acceptance criterion.',
        'scope': 'One Linux x86-64 non-PIE SQLite3.46.1 workload, O2, THREADSAFE=0; no firmware, other host or speedup claim.'}
    write('summary.json', summary)
    print('sqlite-benchmark=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
