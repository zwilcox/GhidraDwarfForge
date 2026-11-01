#!/usr/bin/env python3
"""Real saved-program THIS, hidden return transport and ordinary-name controls."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=['x86_64', 'aarch64'])
    parser.add_argument('--role', choices=['exec', 'pie', 'pie-rebased'], default='exec')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    root = Path(__file__).resolve().parents[3]
    harness = root / 'src/test/integration'
    results = root / 'build/test-results/object-return'
    results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '-' + args.role + '-', dir=results))
    print('object-return-results=' + str(case), flush=True)
    commands = []

    def run(label, argv, timeout=300):
        argv = list(map(str, argv))
        commands.append({'label': label, 'argv': argv})
        (case / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (case / (label + '.log')).open('w') as log:
            subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=timeout)

    fixture = root / 'src/test/fixtures/object-return.cpp'
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    protected = {str(p): digest(p) for p in [fixture, Path(__file__), harness / 'check-object-return.py',
        harness / 'alias_relationships.py', harness / 'object-return-gdb.py', harness / 'object-return-gdb.sh',
        harness / 'ghidra_scripts/PrepareObjectReturn.java', harness / 'ghidra_scripts/RebaseFixtureProgram.java',
        harness / 'qemu-socket.sh', harness / 'check-dwarfdump.py', *[p for p in module.rglob('*') if p.is_file()]]}
    prefix = '' if args.target == 'x86_64' else 'aarch64-linux-gnu-'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    reference, stripped, output = case / 'reference', case / 'stripped', case / 'forge.dbg'
    run('compile', [prefix + 'g++', '-O0', '-g', '-gdwarf-5', '-fno-stack-protector', '-fno-omit-frame-pointer', *flags, fixture, '-o', reference])
    run('strip', [prefix + 'objcopy', '--strip-all', reference, stripped])
    protected.update({str(p): digest(p) for p in [reference, stripped]})
    run('symbols', [prefix + 'nm', '-S', '-C', reference])
    labels = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if fields[-1] in ['object_return_live', 'ordinary_roles_live']:
            labels[fields[-1]] = int(fields[0], 16)
        elif 'recovered::Counter::inspect_result(' in line:
            labels['method'] = int(fields[0], 16)
        elif fields[-1] == 'ordinary_roles':
            labels['ordinary'] = int(fields[0], 16)
    assert len(labels) == 4
    (case / 'labels.json').write_text(json.dumps(labels, indent=4) + '\n')
    run('compiler-llvm', ['llvm-dwarfdump', '--verify', reference])
    run('compiler-gdb', ['bash', harness / 'object-return-gdb.sh', case, args.target, 'compiler', reference])
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'ObjectReturn', '-import', reference,
        '-analysisTimeoutPerFile', '120', '-scriptPath', harness / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareObjectReturn.java', 'curate', case / 'prepared.json', args.target])
    assert 'object-return-preparation=PASS' in (case / 'import.log').read_text()
    prepared = json.loads((case / 'prepared.json').read_text())
    assert prepared['javaVersion'].startswith('21.')
    assert Path(unquote(urlsplit(prepared['origin']).path)) == module / 'lib/GhidraDwarfForge.jar'
    if args.role == 'pie-rebased':
        assert prepared['rebaseDelta'] >= 0x2000000
    method, = [row for row in prepared['observations'] if row['name'].endswith('::inspect_result')]
    assert [p.get('kind') for p in method['parameters']] == ['RETURN_STORAGE_PTR', 'THIS', None]
    assert len(prepared['model']['classScopes']['bindings']) == 1
    snapshot = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
    pair = None
    for mode in ['first', 'repeat']:
        run('export-' + mode, [ghidra / 'support/analyzeHeadless', project, 'ObjectReturn', '-process', 'reference',
            '-readOnly', '-noanalysis', '-scriptPath', harness / 'ghidra_scripts',
            '-postScript', 'PrepareObjectReturn.java', 'observe', case / (mode + '-model.json'), args.target,
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)])
        log = (case / ('export-' + mode + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in log
        assert json.loads((case / (mode + '-model.json')).read_text()) == prepared
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert report['failure'] is None and not report['failedFunctions']
        (case / (mode + '-report.json')).write_text(json.dumps(report, indent=4) + '\n')
        current = [digest(output), digest(Path(str(output) + '.c'))]
        assert pair is None or pair == current
        pair = current
        if mode == 'first':
            shutil.copyfile(output, case / 'first.dbg')
            shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
    after = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
    changed = {p for p in snapshot.keys() | after.keys() if snapshot.get(p) != after.get(p)}
    assert changed <= {'ObjectReturn.rep/idata/~index.bak', 'ObjectReturn.rep/idata/~journal.bak'}
    for name, data in [('project-before', snapshot), ('project-after', after)]:
        (case / (name + '.json')).write_text(json.dumps(data, indent=4) + '\n')
    for name, artifact in [('reference', reference), ('forge', output)]:
        run(name + '-elf', ['readelf', '-hSWn', artifact])
    assert reference.read_bytes()[:20] == output.read_bytes()[:20]
    assert reference.read_bytes()[48:52] == output.read_bytes()[48:52]
    assert re.findall(r'Build ID: (\w+)', (case / 'reference-elf.log').read_text()) == re.findall(r'Build ID: (\w+)', (case / 'forge-elf.log').read_text())
    for view in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
        run(view, ['readelf', '--debug-dump=' + view, output])
        assert 'Warning:' not in (case / (view + '.log')).read_text()
    run('type-identity', ['python3', harness / 'check-object-return.py', case])
    run('llvm', ['llvm-dwarfdump', '--verify', output])
    assert 'No errors.' in (case / 'llvm.log').read_text()
    run('strict', ['python3', harness / 'check-dwarfdump.py', output, case / 'strict.log', '--original', reference])
    run('forge-gdb', ['bash', harness / 'object-return-gdb.sh', case, args.target, 'forge', output])
    observations = [json.loads((case / (mode + '-observations.json')).read_text()) for mode in ['compiler', 'forge']]
    for observed in observations:
        assert observed['status'] == 'PASS' and observed['aggregate'] == [10, 4, 21]
        assert observed['ordinaryReturn'] == 42 and observed['exitCodes'] == [0]
        if args.role != 'exec':
            assert observed['bias'] != 0
    def warnings(mode):
        return Counter(re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in (case / (mode + '-gdb.log')).read_text().splitlines()
            if re.match(r'\s*(warning:|error:)', line, re.I))
    assert warnings('compiler') == warnings('forge')
    assert protected == {p: digest(Path(p)) for p in protected}
    assert not list(case.glob('.*.tmp'))
    (case / 'acceptance.json').write_text(json.dumps({'status': 'OBJECT_RETURN_PASS', 'target': args.target,
        'role': args.role, 'outputPair': pair, 'protected': protected, 'observations': observations,
        'projectBackupChanges': sorted(changed)}, indent=4) + '\n')
    print('object-return-export=PASS', flush=True)


if __name__ == '__main__':
    main()
