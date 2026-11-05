#!/usr/bin/env python3
"""Evaluate compression/indexes on private sidecar copies, retaining failed candidates."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import statistics
import tempfile

SOURCE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), SOURCE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference_case', type=Path)
    parser.add_argument('--workload', choices=('sqlite', 'uboot'), required=True)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--objcopy', default='llvm-objcopy', help='Recorded rewriting tool; GNU BFD rejects some matched sidecars')
    args = parser.parse_args()
    if not 3 <= args.rounds <= 10:
        parser.error('use 3..10 rounds')
    support, consumer = load('export-benchmark'), load('host-consumer')
    inventory = load('section-inventory')
    incoming = args.reference_case.resolve(strict=True)
    summary = json.loads((incoming / 'summary.json').read_text())
    assert summary['status'] == 'PASS'
    if args.workload == 'uboot':
        built = Path(summary['buildCase']).resolve(strict=True)
        receipt = json.loads((built / 'build-result.json').read_text())
        for name, metadata in receipt['artifacts'].items():
            assert support.digest(built / name) == metadata['sha256']
        binary, reference = built / 'u-boot.workload', built / 'u-boot.reference'
        original = incoming / 'u-boot.dbg'
        addresses = json.loads((incoming / 'function-addresses.json').read_text())
        workload = {'name': 'uboot', 'kind': 'pie', 'addresses': addresses, 'dtb': 'u-boot.dtb'}
    else:
        binary, reference, built = incoming / 'sqlite-workload', None, incoming
        assert support.digest(binary) == summary['inputSha256']
        original = incoming / 'sqlite-workload.dbg'
        addresses = {}
        for line in (incoming / 'symbols.log').read_text().splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[2] in ('main', 'benchmark_checkpoint', 'sqlite3_step', 'sqlite3_exec'):
                assert fields[2] not in addresses
                addresses[fields[2]] = int(fields[0], 16)
        assert len(addresses) == 4
        workload = {'name': 'sqlite', 'kind': 'exec', 'addresses': addresses}
    assert support.digest(original) == summary['artifactSha256'][0]
    original_sections = inventory.inspect(original)['sectionSha256']
    root = SOURCE.parents[2] / 'build/test-results/consumer-candidates'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='run.', dir=root))
    print(case, flush=True)
    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')
    def run(directory, name, command, **kwargs):
        return support.run(command, directory / (name + '.log'), **kwargs)
    protected = [original, Path(str(original) + '.c'), binary, incoming / 'summary.json',
        Path(__file__).resolve(), SOURCE / 'export-benchmark.py', SOURCE / 'host-consumer.py',
        SOURCE / 'section-inventory.py']
    if reference is not None:
        protected += [reference, built / 'u-boot.dtb', built / 'build-result.json']
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    for tool in ('gdb-multiarch', args.objcopy, 'readelf', 'llvm-dwarfdump'):
        run(case, 'version-' + Path(tool).name, [tool, '--version'])
    variants = ('baseline', 'zlib', 'zstd', 'gdb-index', 'debug-names')
    results = {}
    for variant in variants:
        directory = case / variant
        directory.mkdir()
        output = directory / original.name
        try:
            generation = []
            hashes = []
            for repeat in range(2):
                target_dir = directory / str(repeat)
                target_dir.mkdir()
                target = target_dir / original.name
                shutil.copyfile(original, target)
                if variant in ('zlib', 'zstd'):
                    command = [args.objcopy, '--compress-debug-sections=' + variant,
                        original, target]
                elif variant in ('gdb-index', 'debug-names'):
                    command = ['env', 'GDB=gdb-multiarch', 'OBJCOPY=' + args.objcopy, 'gdb-add-index',
                        *(['-dwarf-5'] if variant == 'debug-names' else []), target]
                else:
                    command = ['true']
                generation.append(run(target_dir, 'generate', command, timeout=300, measured=True))
                support.require_clean(target_dir / 'generate.log')
                hashes.append(support.digest(target))
            assert hashes[0] == hashes[1], 'candidate generation is nondeterministic'
            shutil.copyfile(directory / '0' / original.name, output)
            decompressed = directory / 'decompressed.dbg'
            if variant == 'baseline':
                shutil.copyfile(output, decompressed)
            else:
                run(directory, 'decompress', [args.objcopy, '--decompress-debug-sections', output, decompressed])
                support.require_clean(directory / 'decompress.log')
            observed_sections = inventory.inspect(decompressed)['sectionSha256']
            for name, digest in original_sections.items():
                if variant == 'debug-names' and name == '.debug_str':
                    # GDB's DWARF5 index may append strings; existing offsets
                    # must still name the unchanged original string prefix.
                    for label, artifact in (('original', original), ('candidate', decompressed)):
                        run(directory, 'strings-' + label, [args.objcopy, '--dump-section',
                            '.debug_str=' + str(directory / (label + '.strings')), artifact,
                            directory / (label + '.scratch')])
                    assert (directory / 'candidate.strings').read_bytes().startswith(
                        (directory / 'original.strings').read_bytes())
                else:
                    assert observed_sections[name] == digest, 'emitted DWARF changed: ' + name
            if variant == 'debug-names':
                assert '.debug_names' in observed_sections
            for name, command in [('llvm', ['llvm-dwarfdump', '--verify', output]),
                    ('strict', ['python3', SOURCE.parent / 'integration/check-dwarfdump.py', output,
                        directory / 'strict-checks.log', '--original', binary]),
                    ('sections', ['readelf', '-h', '-SW', '-n', output]),
                    *[(view, ['readelf', '--debug-dump=' + view, output])
                        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc')]]:
                run(directory, name, command, measured=True, timeout=300)
                support.require_clean(directory / (name + '.log'))
            assert 'No errors.' in (directory / 'llvm.log').read_text()
            if variant == 'gdb-index':
                assert '.gdb_index' in (directory / 'sections.log').read_text()
            consumer.validate_gdb(workload, built, directory, incoming, output, binary, reference)
            results[variant] = {'status': 'VALIDATED', 'artifactSha256': hashes[0],
                'fileBytes': output.stat().st_size, 'generation': generation, 'samples': [],
                'strict': json.loads((directory / 'strict-checks.log.check.json').read_text())}
        except Exception as error:
            results[variant] = {'status': 'FAILED', 'error': str(error),
                'scope': 'Retained negative candidate; do not report passing timing or compatibility.'}
        write('candidates.json', results)
    assert results['baseline']['status'] == 'VALIDATED', 'baseline oracle must pass before comparing candidates'
    for repeat in range(args.rounds):
        order = variants[repeat % len(variants):] + variants[:repeat % len(variants)]
        if repeat % 2:
            order = tuple(reversed(order))
        for variant in order:
            if results[variant]['status'] != 'VALIDATED':
                continue
            directory = case / variant
            output = directory / original.name
            script = directory / ('measure-' + str(repeat) + '.gdb')
            script.write_text('\n'.join(['set pagination off', 'set confirm off', 'set debuginfod enabled off',
                'set auto-solib-add off', 'set index-cache enabled off', 'python', 'import time, json',
                'started = time.perf_counter_ns()', 'gdb.execute("symbol-file " + ' + repr(str(output)) + ')',
                'loaded = time.perf_counter_ns()', 'expected = ' + repr(addresses),
                'for name, address in expected.items():', '    if name in ("main", "do_echo"): continue',
                '    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)',
                '    assert symbol and symbol.is_function and symbol.symtab, name',
                '    assert int(symbol.value().address) == address, name', 'done = time.perf_counter_ns()',
                'print("consumer-metrics=" + json.dumps({"loadSeconds": (loaded-started)/1e9, '
                    '"lookupSeconds": (done-loaded)/1e9}))', 'end', '']))
            sample = run(directory, 'measure-' + str(repeat),
                ['gdb-multiarch', '-nx', '-q', '-batch', '-x', script], measured=True, timeout=180)
            support.require_clean(directory / ('measure-' + str(repeat) + '.log'))
            internal, = [json.loads(line.split('=', 1)[1]) for line in
                (directory / ('measure-' + str(repeat) + '.log')).read_text().splitlines()
                if line.startswith('consumer-metrics=')]
            sample.update(round=repeat, internal=internal)
            results[variant]['samples'].append(sample)
            write('candidates.json', results)
    for result in results.values():
        if result['status'] == 'VALIDATED':
            result['medianProcessSeconds'] = statistics.median(s['elapsedSeconds'] for s in result['samples'])
            result['medianLoadSeconds'] = statistics.median(s['internal']['loadSeconds'] for s in result['samples'])
            result['medianLookupSeconds'] = statistics.median(s['internal']['lookupSeconds'] for s in result['samples'])
    assert before == {str(p): support.digest(p) for p in protected}
    write('summary.json', {'status': 'EXPERIMENT_COMPLETE', 'workload': workload, 'results': results,
        'protectedUnchanged': True, 'loadAverageAtEnd': os.getloadavg(),
        'scope': 'Private-copy experiments only. Two generation runs, independent validators and runtime GDB; '
            'rotating fresh-GDB measurements with index cache disabled. Warm filesystem cache, uncontrolled '
            'host load. Baseline generation is a no-op, not export time. Failed candidates retained. '
            'No production feature or Windows/LLDB compatibility claim.'})
    print('consumer-candidates=EXPERIMENT_COMPLETE ' + str(case), flush=True)


if __name__ == '__main__':
    main()
