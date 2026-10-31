#!/usr/bin/env python3
"""Saved automatic THIS semantics, raw references and compiler-correlated values."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=['x86_64', 'aarch64'])
    parser.add_argument('--role', choices=['exec', 'pie', 'pie-rebased'], default='exec')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    repository = Path(__file__).resolve().parents[3]
    harness = repository / 'src/test/integration'
    results = repository / 'build/test-results/object-parameter'
    results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '-' + args.role + '-', dir=results))
    print('object-parameter-results=' + str(case), flush=True)
    commands = []

    def run(label, command, timeout=240):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (case / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (case / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=timeout)

    prefix = '' if args.target == 'x86_64' else 'aarch64-linux-gnu-'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    source = repository / 'src/test/fixtures/object-parameter.cpp'
    reference, stripped, output = case / 'reference', case / 'stripped', case / 'forge.dbg'
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    protected = {str(p): digest(p) for p in [source, module]}
    run('compile', [prefix + 'g++', '-O0', '-g', '-gdwarf-5', '-fno-stack-protector',
        '-fno-omit-frame-pointer', *flags, source, '-o', reference])
    run('strip', [prefix + 'objcopy', '--strip-all', reference, stripped])
    protected.update({str(p): digest(p) for p in [reference, stripped]})
    run('symbols', [prefix + 'nm', '-S', reference])
    run('disassembly', [prefix + 'objdump', '-d', reference])
    labels = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        name = fields[-1]
        if name in ['object_live', 'ordinary_live']:
            labels[name] = int(fields[0], 16)
        elif 'inspect_object' in name:
            assert 'method' not in labels
            labels['method'] = int(fields[0], 16)
    assert labels.keys() == {'method', 'object_live', 'ordinary_live'}
    (case / 'labels.json').write_text(json.dumps(labels, indent=4) + '\n')
    run('compiler-llvm', ['llvm-dwarfdump', '--verify', reference])
    run('compiler-gdb', ['bash', harness / 'object-parameter-gdb.sh', case, args.target, 'compiler', reference])
    assert 'object-parameter-gdb=compiler PASS' in (case / 'compiler-gdb.log').read_text()
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Object', '-import', reference,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', harness / 'ghidra_scripts',
        *rebase, '-postScript', 'PrepareObjectParameter.java', case / 'prepared.json'])
    assert 'object-parameter-preparation=PASS' in (case / 'import.log').read_text()
    assert json.loads((case / 'prepared.json').read_text())['javaVersion'].startswith('21.')
    before = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
    pair = None
    for iteration in ['first', 'repeat']:
        run('export-' + iteration, [ghidra / 'support/analyzeHeadless', project, 'Object', '-process', 'reference',
            '-readOnly', '-noanalysis', '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)])
        assert 'GhidraDwarfForge symbol export PASS' in (case / ('export-' + iteration + '.log')).read_text()
        current = [digest(output), digest(Path(str(output) + '.c'))]
        assert pair is None or pair == current
        pair = current
    after = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    allowed = {str(project / 'Object.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
    assert changed <= allowed, changed
    (case / 'project-backup-changes.json').write_text(json.dumps(sorted(changed), indent=4) + '\n')
    for name, artifact in [('original', reference), ('output', output)]:
        run(name + '-elf', ['readelf', '-hSWn', artifact])
    assert reference.read_bytes()[:20] == output.read_bytes()[:20]
    assert reference.read_bytes()[48:52] == output.read_bytes()[48:52]
    assert re.findall(r'Build ID: (\w+)', (case / 'original-elf.log').read_text()) == re.findall(
        r'Build ID: (\w+)', (case / 'output-elf.log').read_text())
    for view in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
        run(view, ['readelf', '--debug-dump=' + view, output])
        assert 'Warning:' not in (case / (view + '.log')).read_text()
    run('references', ['python3', harness / 'check-object-parameters.py', case / 'info.log'])
    run('llvm', ['llvm-dwarfdump', '--verify', output])
    assert 'No errors.' in (case / 'llvm.log').read_text()
    run('strict', ['python3', harness / 'check-dwarfdump.py', output, case / 'dwarfdump.log', '--original', reference])
    run('forge-gdb', ['bash', harness / 'object-parameter-gdb.sh', case, args.target, 'forge', output])
    assert 'object-parameter-gdb=forge PASS' in (case / 'forge-gdb.log').read_text()
    diagnostics = []
    for phase in ['compiler', 'forge']:
        warnings = [line for line in (case / (phase + '-gdb.log')).read_text().splitlines()
            if re.match(r'\s*(warning:|error:)', line, re.I)]
        if args.target == 'x86_64':
            assert not warnings, warnings
        else:
            assert all(re.fullmatch(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ '
                r'has a corrupt string table index', line) for line in warnings), warnings
        diagnostics.append(Counter(re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in warnings))
    assert diagnostics[0] == diagnostics[1], diagnostics
    assert protected == {p: digest(Path(p)) for p in protected}
    assert not list(case.glob('.*.tmp'))
    (case / 'acceptance.json').write_text(json.dumps({'status': 'OBJECT_PARAMETER_PASS',
        'target': args.target, 'role': args.role, 'protected': protected, 'outputPair': pair,
        'observations': json.loads((case / 'forge-observations.json').read_text())}, indent=4) + '\n')
    print('object-parameter-export=PASS', flush=True)


if __name__ == '__main__':
    main()
