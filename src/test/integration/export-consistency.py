#!/usr/bin/env python3
"""Reject changes during real export staging and validate deterministic retries."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def report_records(log):
    marker = 'GhidraDwarfForge.java> GhidraDwarfForge report: '
    return [json.loads(line.split(marker, 1)[1].strip().removesuffix(' (GhidraScript)'))
            for line in log.splitlines() if marker in line]


def verify_export_failures(ghidra, project, original, consumer, producer, work):
    work.mkdir()
    copy = work / 'selected-input'
    shutil.copyfile(original, copy)
    project_marker = project / 'Consistency.rep' / 'forge-owned-sentinel'
    project_marker.write_text('saved project sentinel')
    fake = work / 'invalid.so'
    fake.write_text('not a native library')
    native_alias = work / 'native-output.dbg.c'
    os.link(fake, native_alias)
    output = work / 'existing.dbg'
    source = Path(str(output) + '.c')
    output.write_text('previous sidecar')
    source.write_text('previous source')
    cases = [
        ('original-import', copy, original, consumer, producer, 'protected input'),
        ('project-directory', original, project_marker, consumer, producer, 'inside the saved project'),
        ('native-sidecar', original, fake, fake, producer, 'protected input'),
        ('native-source', original, work / 'native-output.dbg', fake, producer, 'protected input'),
        ('invalid-library', original, output, fake, producer, 'Could not load or call libdwarf'),
        ('missing-producer-symbol', original, output, consumer, consumer, 'Could not load or call libdwarf'),
    ]
    try:
        for name, selected, artifact, lib, libp, message in cases:
            protected = {original, copy, project_marker, fake, native_alias, output, source, consumer, producer,
                         artifact, Path(str(artifact) + '.c')}
            before = {p: digest(p) if p.exists() else None for p in protected}
            log = work / (name + '.log')
            command = [ROOT / 'support/ghidra-dwarf-forge-headless', '--ghidra-dir=' + str(ghidra),
                       '--project-dir=' + str(project), '--project-name=Consistency', '--program=/' + original.name,
                       '--input=' + str(selected), '--output=' + str(artifact), '--libdwarf=' + str(lib),
                       '--libdwarfp=' + str(libp), '--log=' + str(log)]
            with (work / (name + '.stdout')).open('w') as stdout:
                run = subprocess.run(command, stdout=stdout, stderr=subprocess.STDOUT, timeout=180)
            reports = report_records(log.read_text())
            assert run.returncode == 10 and len(reports) == 1 and reports[0]['status'] == 'FATAL', name
            assert message in reports[0]['failure']['message'], (name, reports[0]['failure'])
            assert before == {p: digest(p) if p.exists() else None for p in protected}, name
            assert not list(work.glob('*.staged')) and not list(work.glob('.forge-generation-*')), name
            print('headless-export-failure=PASS ' + name, flush=True)
    finally:
        project_marker.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=('x86_64', 'aarch64'))
    parser.add_argument('output', type=Path)
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--libdwarf', type=Path)
    parser.add_argument('--libdwarfp', type=Path)
    args = parser.parse_args()
    assert bool(args.libdwarf) == bool(args.libdwarfp)
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    natives = module / 'os/linux_x86_64'
    consumer = args.libdwarf or next(natives.glob('libdwarf.so.*.*.*'))
    producer = args.libdwarfp or next(natives.glob('libdwarfp.so.*.*.*'))
    fixture = ROOT / 'build/fixtures' / args.target / 'semantic.exec.reference'
    protected = {str(p): digest(p) for p in (fixture, module / 'lib/GhidraDwarfForge.jar',
        module / 'ghidra_scripts/GhidraDwarfForge.java', consumer, producer)}
    original = work / 'original'; shutil.copy2(fixture, original)
    project = work / 'project'; project.mkdir()
    commands = []

    def run(label, command, timeout=360):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (work / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True,
                timeout=timeout, env={**os.environ, 'LC_ALL': 'C'})
        return (work / (label + '.log')).read_text()

    log = run('export', [ghidra / 'support/analyzeHeadless', project, 'Consistency', '-import', original,
        '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript', 'ExportConsistencyControls.java',
        original, work / 'outputs', consumer, producer])
    assert 'export-consistency-controls=PASS controls=4' in log
    assert log.count('export-consistency-control=PASS companion=') == 4
    assert 'Original ELF changed during export' in log and 'Ghidra program changed during export' in log
    for selected in ('false', 'true'):
        start = 'cleanup-warning-start companion=' + selected
        end = 'cleanup-warning-end companion=' + selected
        transcript = log.split(start, 1)[1].split(end, 1)[0]
        records = report_records(transcript)
        assert len(records) == 1 and records[0]['status'] == 'PARTIAL', records
        report = records[0]
        assert any('Export committed. Staging cleanup failed at ' in item for item in report['diagnostics'])
        assert report['counts']['diagnostics'] == len(report['diagnostics'])
        for prefix in ('input', 'output', 'source'):
            assert digest(Path(report['artifacts'][prefix + 'Path'])) == report['artifacts'][prefix + 'Sha256']
        if selected == 'true':
            companion = Path(report['artifacts']['outputPath'] + '.gdb.py')
            assert 'GDB companion SHA-256: ' + digest(companion) in transcript
    run('compiler-gdb', ['bash', SCRIPTS / 'export-consistency-gdb.sh', args.target, original,
        original, work / 'compiler-runtime'])
    reference_warnings = [line for line in (work / 'compiler-runtime.log').read_text().splitlines()
                          if 'warning:' in line.lower()]
    assert all(args.target == 'aarch64' and re.fullmatch(
        r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', line)
        for line in reference_warnings), reference_warnings
    if args.target == 'x86_64':
        verify_export_failures(ghidra, project, original, consumer, producer, work / 'failed-exports')
    artifacts = []
    for mode in ('pair', 'companion'):
        artifact = work / 'outputs' / mode / 'forge.dbg'
        text = run(mode + '-gnu', ['readelf', '-h', '-S', '--debug-dump=info,abbrev,aranges,decodedline', artifact])
        assert not any(word in text.lower() for word in ('warning:', 'error:'))
        run(mode + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        run(mode + '-strict-command', [sys.executable, SCRIPTS / 'check-dwarfdump.py', artifact,
            work / (mode + '-strict.log'), '--tool', args.dwarfdump, '--original', original])
        run(mode + '-gdb', ['bash', SCRIPTS / 'export-consistency-gdb.sh', args.target, original,
            artifact, work / (mode + '-runtime')])
        warnings = [line for line in (work / (mode + '-runtime.log')).read_text().splitlines() if 'warning:' in line.lower()]
        assert warnings == reference_warnings, warnings
        artifacts.append({'mode': mode, 'sha256': digest(artifact), 'sourceSha256': digest(Path(str(artifact) + '.c'))})
    assert digest(original) == digest(fixture)
    assert protected == {name: digest(Path(name)) for name in protected}
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_EXPORT_CONSISTENCY', 'target': args.target,
        'controls': 4, 'successfulExports': 8, 'protected': protected, 'artifacts': artifacts,
        'compilerReferenceWarnings': reference_warnings}, indent=4) + '\n')
    print(args.target + ' export consistency PASS', flush=True)


if __name__ == '__main__':
    main()
