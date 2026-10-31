#!/usr/bin/env python3
"""Real saved lexical evidence through the production exporter and GDB."""
import argparse
from collections import Counter
import hashlib
import json
import re
from pathlib import Path
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
    results = repository / 'build/test-results/lexical-shadow'
    results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '-' + args.role + '-', dir=results))
    print('lexical-shadow-results=' + str(case), flush=True)
    commands = []

    def run(label, command, timeout=240):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (case / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (case / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=timeout)

    target = args.target
    prefix = '' if target == 'x86_64' else 'aarch64-linux-gnu-'
    reference, stripped, output = case / 'reference', case / 'stripped', case / 'forge.dbg'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    source = repository / 'src/test/fixtures/lexical-shadow.c'
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    protected = {str(p): digest(p) for p in [source, module]}
    run('compile', [prefix + 'gcc', '-O0', '-g', '-gdwarf-5', '-fno-stack-protector',
        '-fno-omit-frame-pointer', *flags, source, '-o', reference])
    run('strip', [prefix + 'objcopy', '--strip-all', reference, stripped])
    protected.update({str(p): digest(p) for p in [reference, stripped]})
    run('symbols', [prefix + 'nm', '-S', reference])
    run('disassembly', [prefix + 'objdump', '-d', reference])
    wanted = {'scoped', 'outer_begin', 'outer_live', 'inner_begin', 'inner_live', 'inner_end', 'outer_end'}
    labels = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if fields[-1] in wanted:
            assert fields[-1] not in labels
            labels[fields[-1]] = int(fields[0], 16)
    assert labels.keys() == wanted
    order = ['scoped', 'outer_begin', 'outer_live', 'inner_begin', 'inner_live', 'inner_end', 'outer_end']
    assert all(labels[a] < labels[b] for a, b in zip(order, order[1:]))
    (case / 'labels.json').write_text(json.dumps(labels, indent=4) + '\n')
    harness = repository / 'src/test/integration'
    run('compiler-llvm', ['llvm-dwarfdump', '--verify', reference])
    run('compiler-gdb', ['bash', harness / 'lexical-shadow-gdb.sh', case, target, 'compiler', reference])
    assert 'lexical-shadow-gdb=compiler PASS' in (case / 'compiler-gdb.log').read_text()
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Lexical', '-import', stripped,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', harness / 'ghidra_scripts',
        *rebase, '-postScript', 'PrepareLexicalShadow.java', case / 'labels.json',
        case / 'compiler-storage.json', case / 'prepared.json'])
    assert 'lexical-shadow-preparation=PASS' in (case / 'import.log').read_text()
    assert json.loads((case / 'prepared.json').read_text())['javaVersion'].startswith('21.')
    project_before = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
    pair = None
    for iteration in ['first', 'repeat']:
        run('export-' + iteration, [ghidra / 'support/analyzeHeadless', project, 'Lexical', '-process', 'stripped',
            '-readOnly', '-noanalysis', '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)])
        assert 'GhidraDwarfForge symbol export PASS' in (case / ('export-' + iteration + '.log')).read_text()
        current = [digest(output), digest(Path(str(output) + '.c'))]
        assert pair is None or pair == current
        pair = current
    project_after = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
    changed = {p for p in project_before.keys() | project_after.keys() if project_before.get(p) != project_after.get(p)}
    allowed = {str(project / 'Lexical.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
    (case / 'project-backup-changes.json').write_text(json.dumps(sorted(changed), indent=4) + '\n')
    assert changed <= allowed, ('saved program changed during read-only export', changed)
    run('elf', ['readelf', '-hSWn', output])
    run('input-elf', ['readelf', '-hSWn', stripped])
    original_header, sidecar_header = stripped.read_bytes()[:64], output.read_bytes()[:64]
    flags_offset = 48 if original_header[4] == 2 else 36
    assert original_header[:20] == sidecar_header[:20], 'target identity changed'
    assert original_header[flags_offset:flags_offset + 4] == sidecar_header[flags_offset:flags_offset + 4], 'ABI flags changed'
    assert re.findall(r'Build ID: (\w+)', (case / 'input-elf.log').read_text()) == re.findall(
        r'Build ID: (\w+)', (case / 'elf.log').read_text()), 'build identity changed'
    for view in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
        run(view, ['readelf', '--debug-dump=' + view, output])
        assert 'Warning:' not in (case / (view + '.log')).read_text()
    assert (case / 'info.log').read_text().count('(DW_TAG_lexical_block)') == 2
    run('scope-dies', ['python3', harness / 'check-lexical-shadow.py', case])
    run('address-index', ['python3', harness / 'check-code-address-index.py', output, '--negative-controls'])
    run('llvm', ['llvm-dwarfdump', '--verify', output])
    assert 'No errors.' in (case / 'llvm.log').read_text()
    run('strict', ['python3', harness / 'check-dwarfdump.py', output, case / 'dwarfdump.log', '--original', stripped])
    run('forge-gdb', ['bash', harness / 'lexical-shadow-gdb.sh', case, target, 'forge', output])
    assert 'lexical-shadow-gdb=forge PASS' in (case / 'forge-gdb.log').read_text()
    diagnostics = []
    for phase in ['compiler', 'forge']:
        warnings = [line for line in (case / (phase + '-gdb.log')).read_text().splitlines()
            if re.match(r'\s*(warning:|error:)', line, re.I)]
        if target == 'x86_64':
            assert not warnings, warnings
        else:
            assert all(re.fullmatch(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ '
                r'has a corrupt string table index', line) for line in warnings), warnings
        diagnostics.append(Counter(re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in warnings))
    assert diagnostics[0] == diagnostics[1], diagnostics
    assert protected == {p: digest(Path(p)) for p in protected}
    receipt = {'status': 'LEXICAL_SHADOW_PASS', 'target': target, 'role': args.role,
        'javaRuntime': 21, 'protected': protected, 'outputPair': pair,
        'observations': len(json.loads((case / 'forge-observations.json').read_text())),
        'scope': 'nested contiguous explicit blocks, shadow lookup, initialization gaps; full goal remains open'}
    (case / 'acceptance.json').write_text(json.dumps(receipt, indent=4) + '\n')
    print(json.dumps(receipt, indent=4))


if __name__ == '__main__':
    main()
