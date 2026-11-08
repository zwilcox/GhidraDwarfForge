#!/usr/bin/env python3
"""Validate byte-preserved relocated companions, including native Windows exports."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import runpy
import shlex
import shutil
import subprocess

import lldb_consumer

SCRIPTS = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(SCRIPTS / 'formatter-export.py'))
digest, run, gdb = (HELPERS[name] for name in ('digest', 'run', 'gdb'))


def negative_bundles(original, sidecar, companion, work, debugger):
    for control in ('missing-original', 'wrong-original', 'wrong-sidecar'):
        bundle = work / control
        bundle.mkdir()
        copied_sidecar, copied_companion = bundle / sidecar.name, bundle / companion.name
        shutil.copy2(sidecar, copied_sidecar)
        shutil.copy2(companion, copied_companion)
        if control != 'missing-original':
            shutil.copy2(original, bundle / original.name)
        if control.startswith('wrong-'):
            changed = bundle / original.name if control == 'wrong-original' else copied_sidecar
            with changed.open('ab') as stream:
                stream.write(b'wrong generation')
        expected = 'No such file or directory' if control == 'missing-original' else 'stale or mismatched Forge formatter artifact'
        commands = ['gdb-multiarch', '-nx', '-batch', '-ex', 'set debuginfod enabled off',
            '-ex', 'file ' + json.dumps(str(original), ensure_ascii=False),
            '-ex', 'symbol-file ' + json.dumps(str(copied_sidecar), ensure_ascii=False),
            '-ex', 'source ' + str(copied_companion),
            '-ex', 'python assert not getattr(gdb, "_forge_formatters", {})']
        for name, command in [('gdb', commands), ('lldb', [debugger, '--no-lldbinit', '--batch',
                '-o', 'target create ' + shlex.quote(str(original)),
                '-o', 'target symbols add --shlib ' + shlex.quote(str(original)) + ' ' + shlex.quote(str(copied_sidecar)),
                '-o', 'command script import ' + shlex.quote(str(copied_companion))])]:
            log = bundle / (name + '.log')
            log.with_suffix('.command.json').write_text(json.dumps(command, indent=4) + '\n')
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
            log.write_text(result.stdout)
            assert expected in result.stdout and 'Forge formatters loaded:' not in result.stdout, result.stdout[-5000:]
            assert 'AssertionError' not in result.stdout, result.stdout[-5000:]


@contextmanager
def unavailable_producer_source(source, record, work):
    """Require transported sources; restore this owned fixture even on failure."""
    hidden = work / 'hidden-producer-source'
    hidden.mkdir()
    moved = []
    try:
        for name in record['sha256']:
            if name.endswith('.c') or (name.startswith('forge-src-') and name.endswith('.json')):
                original, retained = source / name, hidden / name
                original.rename(retained)
                moved.append((original, retained))
        assert moved
        yield
    finally:
        for original, retained in reversed(moved):
            assert not original.exists(), 'producer source unexpectedly recreated during consumer test'
            retained.rename(original)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('incoming', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--producer-host', choices=['Linux', 'Windows'], required=True)
    parser.add_argument('--lldb', required=True)
    parser.add_argument('--dwarfdump', required=True)
    args = parser.parse_args()
    incoming = args.incoming.resolve()
    prior = json.loads((incoming / 'result.json').read_text())
    if args.producer_host == 'Windows':
        assert prior['status'] == 'PASS_WINDOWS_FORMATTER_PRODUCER' and prior['host'] == 'Windows'
        assert prior['packagedNatives']
        records = [(incoming / item['role'], item) for item in prior['artifacts']]
        assert {item['role'] for _, item in records} == {'exec', 'pie'}
    else:
        assert prior['status'] == 'PASS_BASIC_PRODUCTION_FORMATTERS' and prior['target'] == 'x86_64'
        records = [(incoming, prior['portableArtifacts'])]
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    results = []
    for source, record in records:
        work = root / record['role']
        work.mkdir()
        transported = work / 'transported'
        transported.mkdir()
        for name, expected in record['sha256'].items():
            assert name not in ('', '.', '..') and Path(name).name == name
            assert digest(source / name) == expected
            shutil.copy2(source / name, transported / name)
            assert digest(transported / name) == expected
        original, reference = transported / 'original', transported / 'compiler-reference'
        original.chmod(0o755)
        reference.chmod(0o755)
        sidecar, companion = transported / record['sidecar'], transported / record['companion']
        for index, command in enumerate([
                ['readelf', '-h', '-S', '-n', str(original)], ['readelf', '-h', '-S', '-n', str(sidecar)],
                *[['readelf', '--debug-dump=' + dump, str(sidecar)] for dump in ['info', 'abbrev', 'aranges', 'decodedline']],
                ['llvm-dwarfdump', '--verify', str(sidecar)],
                ['python3', str(SCRIPTS / 'check-dwarfdump.py'), str(sidecar), str(work / 'strict.log'),
                    '--tool', args.dwarfdump, '--original', str(original)]]):
            text = run(command, work / ('validator-%d.log' % index))
            if command[0] == 'readelf':
                assert 'Warning:' not in text and 'Error:' not in text
        with unavailable_producer_source(source, record, work):
            gdb(reference, None, None, work / 'compiler-gdb.log', None, None)
            # DWARF retains the producer's source directory. Supply the transported
            # source explicitly, including Windows-to-Linux moves, without rewriting
            # any artifact or ignoring missing-source warnings.
            text = gdb(original, sidecar, companion, work / 'gdb.log', None, None, reference,
                source_directory=transported)
            assert 'formatter-gdb-controls=PASS' in text and '\nwarning:' not in text
            gdb(original, sidecar, companion, work / 'gdb-mi.log', None, None, mi=True,
                source_directory=transported)
            text = lldb_consumer.run(original, sidecar, work / 'lldb', args.lldb, 'x86_64',
                ['breakpoint set --name forge_formatter_marker'], [
                    'command script import ' + shlex.quote(str(companion)),
                    'frame variable forge_flags forge_node',
                    'script import sys; sys.path.insert(0, ' + repr(str(SCRIPTS)) +
                        '); import formatter_checks; formatter_checks.lldb_checks(lldb.debugger, ' + repr(str(reference)) + ')',
                    'forge-formatters unload', 'continue'], {})
            assert 'formatter-lldb-controls=PASS' in text and 'unknown=0x4' in text
            negative_bundles(original, sidecar, companion, work, args.lldb)
        for name, expected in record['sha256'].items():
            assert digest(source / name) == digest(transported / name) == expected
        results.append({'role': record['role'], 'transportedSha256': record['sha256']})
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_PORTABLE_FORMATTER_CONSUMERS',
        'producerHost': args.producer_host, 'artifacts': results,
        'gdb': 'CLI/MI, type/width/module/stale controls', 'lldb': '18.1.3 summaries/native children and controls'}, indent=4) + '\n')
    print('formatter-portable=PASS producer=' + args.producer_host)


if __name__ == '__main__':
    main()
