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
    run('compiler-gdb', ['bash', SCRIPTS / 'export-consistency-gdb.sh', args.target, original,
        original, work / 'compiler-runtime'])
    reference_warnings = [line for line in (work / 'compiler-runtime.log').read_text().splitlines()
                          if 'warning:' in line.lower()]
    assert all(args.target == 'aarch64' and re.fullmatch(
        r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', line)
        for line in reference_warnings), reference_warnings
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
        'controls': 4, 'successfulExports': 6, 'protected': protected, 'artifacts': artifacts,
        'compilerReferenceWarnings': reference_warnings}, indent=4) + '\n')
    print(args.target + ' export consistency PASS', flush=True)


if __name__ == '__main__':
    main()
