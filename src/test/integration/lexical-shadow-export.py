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
    parser.add_argument('--discontiguous', action='store_true', help='record an explicit analyst visibility gap around an effect-free instruction')
    parser.add_argument('--calls', action='store_true', help='compose both lexical identities with inspected calls')
    parser.add_argument('--controls', action='store_true', help='also test stale/coalesced evidence, actual decompiler failure and cancellation')
    parser.add_argument('--coverage-controls', action='store_true', help='also test production coverage staging cancellation and failure preservation')
    parser.add_argument('--source-lines', type=int, help='also compare a single-file baseline with partitioned source')
    parser.add_argument('--java', type=Path, help='explicit Java runtime; launch the production headless entry point directly')
    args = parser.parse_args()
    if args.source_lines is not None and not 1 <= args.source_lines <= 2147483647:
        parser.error('--source-lines must be in 1..2147483647')
    ghidra = args.ghidra.resolve(strict=True)
    headless = [ghidra / 'support/analyzeHeadless']
    if args.java:
        java = args.java.resolve(strict=True)
        vmargs = subprocess.check_output([java, '-cp', ghidra / 'support/LaunchSupport.jar',
            'LaunchSupport', ghidra, '-vmargs'], text=True).splitlines()
        headless = [java, *vmargs, '-Xmx2G', '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2',
            '-Djava.awt.headless=true', '-cp', ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar',
            'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless']
    repository = Path(__file__).resolve().parents[3]
    results = repository / 'build/test-results/lexical-shadow'
    results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '-' + args.role + '-', dir=results))
    if args.java:
        # Ghidra caches compiled scripts under user.home. A cache created by a
        # newer runtime cannot be loaded by Java 21; keep this explicit-runtime
        # run isolated instead of deleting or rewriting the user's cache.
        for name in ('java-home', 'java-tmp'):
            (case / name).mkdir()
        headless[1:1] = ['-Duser.home=' + str(case / 'java-home'),
            '-Djava.io.tmpdir=' + str(case / 'java-tmp')]
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
    if args.calls:
        flags.append('-DFORGE_LEXICAL_CALLS')
    if args.discontiguous:
        flags.append('-DFORGE_LEXICAL_GAP')
    source = repository / 'src/test/fixtures/lexical-shadow.c'
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    harness = repository / 'src/test/integration'
    files = [source, module, Path(__file__), *harness.glob('lexical-shadow*'),
        harness / 'check-multifile-semantics.py',
        harness / 'check-lexical-shadow.py', harness / 'ghidra_scripts/PrepareLexicalShadow.java',
        harness / 'ghidra_scripts/LexicalDecompilerFailureExport.java',
        harness / 'ghidra_scripts/CancelDuringElfCopy.java']
    protected = {str(p): digest(p) for p in files if p.is_file()}
    run('compile', [prefix + 'gcc', '-O0', '-g', '-gdwarf-5', '-fno-stack-protector',
        '-fno-omit-frame-pointer', *flags, source, '-o', reference])
    run('strip', [prefix + 'objcopy', '--strip-all', reference, stripped])
    protected.update({str(p): digest(p) for p in [reference, stripped]})
    run('symbols', [prefix + 'nm', '-S', reference])
    run('disassembly', [prefix + 'objdump', '-d', reference])
    wanted = {'scoped', 'outer_begin', 'outer_live', 'inner_begin', 'inner_live', 'inner_end', 'outer_end'}
    if args.calls:
        wanted.update(['lexical_leaf', 'outer_call', 'outer_returned', 'inner_call', 'inner_returned'])
    if args.discontiguous:
        wanted.update(['inner_gap_begin', 'inner_gap_end'])
    labels = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if fields[-1] in wanted:
            assert fields[-1] not in labels
            labels[fields[-1]] = int(fields[0], 16)
            if fields[-1] == 'lexical_leaf':
                labels['leaf_end'] = int(fields[0], 16) + int(fields[1], 16)
    assert labels.keys() == wanted | ({'leaf_end'} if args.calls else set())
    order = ['scoped', 'outer_begin', 'outer_live', 'inner_begin', 'inner_live', 'inner_end', 'outer_end']
    assert all(labels[a] < labels[b] for a, b in zip(order, order[1:]))
    if args.discontiguous:
        assert labels['inner_live'] < labels['inner_gap_begin'] < labels['inner_gap_end'] < labels['inner_end']
    (case / 'labels.json').write_text(json.dumps(labels, indent=4) + '\n')
    harness = repository / 'src/test/integration'
    run('compiler-llvm', ['llvm-dwarfdump', '--verify', reference])
    run('compiler-gdb', ['bash', harness / 'lexical-shadow-gdb.sh', case, target, 'compiler', reference])
    assert 'lexical-shadow-gdb=compiler PASS' in (case / 'compiler-gdb.log').read_text()
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [*headless, project, 'Lexical', '-import', stripped,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', harness / 'ghidra_scripts',
        *rebase, '-postScript', 'PrepareLexicalShadow.java', case / 'labels.json',
        case / 'compiler-storage.json', case / 'prepared.json'])
    assert 'lexical-shadow-preparation=PASS' in (case / 'import.log').read_text()
    assert json.loads((case / 'prepared.json').read_text())['javaVersion'].startswith('21.')
    project_before = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
    source_options = []
    if args.source_lines is not None:
        baseline = case / 'baseline' / output.name
        baseline.parent.mkdir()
        run('export-baseline', [*headless, project, 'Lexical', '-process', 'stripped',
            '-readOnly', '-noanalysis', '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(baseline)])
        assert 'GhidraDwarfForge symbol export PASS' in (case / 'export-baseline.log').read_text()
        run('baseline-llvm', ['llvm-dwarfdump', '--verify', baseline])
        run('baseline-strict', ['python3', harness / 'check-dwarfdump.py', baseline,
            case / 'baseline-dwarfdump.log', '--original', stripped])
        run('baseline-gdb', ['bash', harness / 'lexical-shadow-gdb.sh', case, target, 'forge', baseline])
        assert 'lexical-shadow-gdb=forge PASS' in (case / 'baseline-gdb.log').read_text()
        for name in ('observations', 'calls'):
            observed = case / ('forge-' + name + '.json')
            if observed.exists():
                (case / ('baseline-' + name + '.json')).write_bytes(observed.read_bytes())
        source_options = ['--source-lines=' + str(args.source_lines)]
    pair = None
    inventory = None
    for iteration in ['first', 'repeat']:
        run('export-' + iteration, [*headless, project, 'Lexical', '-process', 'stripped',
            '-readOnly', '-noanalysis', '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output), *source_options])
        assert 'GhidraDwarfForge symbol export PASS' in (case / ('export-' + iteration + '.log')).read_text()
        current = [digest(output), digest(Path(str(output) + '.c'))]
        assert pair is None or pair == current
        pair = current
        if args.source_lines is not None:
            current_inventory = {p.name: digest(p) for p in case.glob('forge-src-*')}
            assert current_inventory and (inventory is None or inventory == current_inventory)
            inventory = current_inventory
    if args.source_lines is not None:
        run('source-semantics', ['python3', harness / 'check-multifile-semantics.py',
            stripped, baseline, output, case / 'source-semantics'])
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
    if args.source_lines is not None:
        for name in ('observations', 'calls'):
            observed = case / ('baseline-' + name + '.json')
            if observed.exists():
                assert json.loads(observed.read_text()) == json.loads((case / ('forge-' + name + '.json')).read_text())
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
    if args.calls:
        compiler_calls = json.loads((case / 'compiler-calls.json').read_text())
        forge_calls = json.loads((case / 'forge-calls.json').read_text())
        assert compiler_calls == forge_calls and {r['block'] for r in forge_calls} == {'outer', 'inner'}
    receipt = {'status': 'LEXICAL_SHADOW_PASS', 'target': target, 'role': args.role,
        'discontiguous': args.discontiguous, 'calls': args.calls,
        'sourceLines': args.source_lines, 'sourceInventory': inventory,
        'javaRuntime': 21, 'protected': protected, 'outputPair': pair,
        'observations': len(json.loads((case / 'forge-observations.json').read_text())),
        'scope': 'explicit analyst block visibility, shadow lookup, initialization gaps; full goal remains open'}
    (case / 'acceptance.json').write_text(json.dumps(receipt, indent=4) + '\n')
    if args.coverage_controls:
        run('coverage-staging-driver', ['python3', harness / 'coverage-staging.py', ghidra, case], timeout=900)
        run('coverage-limit-driver', ['python3', harness / 'coverage-staging.py', ghidra, case, '--real-limit'], timeout=900)
        run('coverage-byte-limit-driver', ['python3', harness / 'coverage-staging.py', ghidra, case, '--byte-limit'], timeout=1200)
        run('coverage-curation-driver', ['python3', harness / 'coverage-curation.py', ghidra, case], timeout=900)
        receipt['coverageCuration'] = 'PASS'
        receipt['coverageStaging'] = 'PASS'
        (case / 'acceptance.json').write_text(json.dumps(receipt, indent=4) + '\n')
    if args.controls:
        run('negative-driver', ['python3', harness / 'lexical-shadow-controls.py', case, ghidra], timeout=900)
        run('failure-driver', ['python3', harness / 'lexical-shadow-failure.py', case, ghidra], timeout=900)
        receipt['controls'] = ['stale', 'coalesced', 'native-decompiler-failure', 'copy-cancellation']
        (case / 'acceptance.json').write_text(json.dumps(receipt, indent=4) + '\n')
    assert protected == {p: digest(Path(p)) for p in protected}
    print(json.dumps(receipt, indent=4))


if __name__ == '__main__':
    main()
