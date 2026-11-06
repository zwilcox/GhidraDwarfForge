#!/usr/bin/env python3
"""Validate real intrinsic context and same-spelled ordinary calls through installed exports."""
import argparse
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


def snapshot(root):
    return {str(p.relative_to(root)): digest(p) for p in root.rglob('*')
        if p.is_file() and not p.name.endswith('.lock')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra', 'consumer', 'producer', 'results'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    harness = Path(__file__).resolve().parent
    args.results.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='intrinsic-', dir=args.results)).resolve()
    print('intrinsic-context-results=' + str(root), flush=True)
    project, scripts = root / 'project', root / 'scripts'
    project.mkdir()
    scripts.mkdir()
    helper = harness / 'ghidra_scripts/VerifyIntrinsicContext.java'
    shutil.copy2(helper, scripts)
    module = args.ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    source = harness.parent / 'fixtures/intrinsic-context-x86_64.c'
    protected = {str(p.resolve()): digest(p) for p in [source, helper, Path(__file__), args.consumer, args.producer,
        harness / 'intrinsic-context-gdb.py', module / 'lib/GhidraDwarfForge.jar',
        module / 'ghidra_scripts/GhidraDwarfForge.java']}
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        assert process.returncode == 0, (label, process.returncode)
        return (root / (label + '.log')).read_text()

    run('compile', ['gcc', '-O0', '-g', '-gdwarf-5', '-fno-pie', '-no-pie', '-fno-omit-frame-pointer',
        '-Wall', '-Wextra', '-Werror', source, '-o', root / 'reference'])
    original = root / 'original'
    run('strip', ['objcopy', '--strip-debug', root / 'reference', original])
    protected[str(original)] = digest(original)
    protected[str(root / 'reference')] = digest(root / 'reference')
    run('compiler-runtime', [root / 'reference'])
    common = [args.ghidra / 'support/analyzeHeadless', project, 'Intrinsics', '-scriptPath',
        str(scripts) + ';' + str(module / 'ghidra_scripts')]
    setup = run('setup', common + ['-import', original, '-postScript', helper.name, root / 'setup.json'])
    assert 'intrinsic-context-observation=PASS' in setup and 'ERROR REPORT SCRIPT ERROR' not in setup
    states = [snapshot(project)]
    outputs, projections = {}, {}
    for mode in ('off', 'assembly', 'pcode', 'both'):
        output = root / (mode + '.dbg')
        generations = []
        for phase in ('first', 'second'):
            log = run(mode + '-' + phase, common + ['-process', 'original', '-noanalysis', '-readOnly',
                '-postScript', helper.name, root / (mode + '-' + phase + '.json'),
                '-postScript', 'GhidraDwarfForge.java', '--input', original, '--output', output,
                '--libdwarf', args.consumer, '--libdwarfp', args.producer, '--source-context=' + mode])
            assert 'intrinsic-context-observation=PASS' in log and 'GhidraDwarfForge symbol export PASS' in log
            assert 'ERROR REPORT SCRIPT ERROR' not in log
            origin, = re.findall(r'(?m)^INFO  SCRIPT: (.+GhidraDwarfForge\.java) \(HeadlessAnalyzer\)', log)
            assert Path(origin).resolve() == (module / 'ghidra_scripts/GhidraDwarfForge.java').resolve()
            generations.append({p.name: digest(p) for p in (output, Path(str(output) + '.c'))})
            states.append(snapshot(project))
        assert generations[0] == generations[1]
        observation = json.loads((root / (mode + '-first.json')).read_text())
        assert observation == json.loads((root / (mode + '-second.json')).read_text())
        assert Path(unquote(urlsplit(observation['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
        rows = Path(str(output) + '.c').read_text().splitlines()
        headings = [row for row in rows if row.startswith('/* Ghidra instruction context ')]
        context_lines = set()
        if mode == 'off':
            assert not headings
        else:
            entry = observation['intrinsic_context']['entry']
            intrinsic_headings = [h for h in headings if 'INTRINSIC_CALLOTHER' in h]
            owner = lambda h: int(re.search(r'for (?:ram:)?(?:0x)?([0-9a-f]+)', h)[1], 16)
            assert intrinsic_headings and all(owner(h) == entry for h in intrinsic_headings), headings
            controls = {observation[name]['entry'] for name in ('ordinary_context', 'halt_baddata', 'cpuid_basic_info')}
            assert not any(owner(h) in controls for h in headings), 'ordinary CALL acquired diagnostic context'
            assert all('INTRINSIC_CALLOTHER' in h or 'NATIVE_WARNING_UNMAPPED' in h for h in headings)
            assert 'BAD_INSTRUCTION_RETURN' not in '\n'.join(rows)
            for index, row in enumerate(rows):
                if row in headings:
                    end = index
                    while end < len(rows) and rows[end].startswith('/* ') and rows[end].endswith(' */'):
                        context_lines.add(end + 1)
                        end += 1
            context = '\n'.join(rows[i - 1] for i in sorted(context_lines))
            address, = observation['intrinsic_context']['intrinsicAddresses']
            focus = re.findall(r'focus=(?:ram:)?(?:0x)?([0-9a-f]+)', context)
            assert focus and all(int(value, 16) == address for value in focus)
            assert ('assembly:' in context) == (mode in ('assembly', 'both'))
            assert ('raw instruction p-code' in context) == (mode in ('pcode', 'both'))
            assert ('effective flow-override p-code' in context) == (mode in ('pcode', 'both'))
        for view in ('info', 'abbrev', 'aranges', 'decodedline'):
            text = run(mode + '-' + view, ['readelf', '--debug-dump=' + view, output])
            assert not re.search(r'warning:|error:', text, re.I)
        run(mode + '-identity', ['readelf', '-hSWn', original, output])
        assert 'No errors.' in run(mode + '-llvm', ['llvm-dwarfdump', '--verify', output])
        run(mode + '-strict', ['python3', harness / 'check-dwarfdump.py', output,
            root / (mode + '-strict.log'), '--original', original])
        mapped = [(int(m[2], 16), int(m[1])) for m in re.finditer(r'(?m)^\S+\s+(\d+)\s+(0x[0-9a-fA-F]+)\b',
            (root / (mode + '-decodedline.log')).read_text())]
        assert mapped and all(line not in context_lines for _, line in mapped)
        projections[mode] = [(address, rows[line - 1]) for address, line in mapped]
        assert projections[mode] == projections['off'], 'context changed executable address/source-text pairs'
        (root / (mode + '-context-lines.json')).write_text(json.dumps(sorted(context_lines)) + '\n')
        gdb_script = root / (mode + '.gdb')
        gdb_script.write_text('set pagination off\nset confirm off\nset debuginfod enabled off\n'
            'set auto-solib-add off\nset disable-randomization off\nfile ' + str(original) +
            '\nsymbol-file ' + str(output) + '\npython\n'
            'import os\nos.environ["FORGE_INTRINSIC_CASE"] = ' + repr(str(root)) + '\n'
            'os.environ["FORGE_INTRINSIC_MODE"] = ' + repr(mode) + '\nend\nsource ' +
            str(harness / 'intrinsic-context-gdb.py') + '\nquit\n')
        gdb = run(mode + '-gdb', ['gdb-multiarch', '-nx', '-batch', '-x', gdb_script])
        assert 'intrinsic-context-gdb=PASS' in gdb and not re.search(r'(?im)^warning:', gdb)
        outputs[mode] = {'generations': generations, 'contextLines': len(context_lines),
            'gdb': json.loads((root / (mode + '-gdb.json')).read_text())}
    changed = {p for p in states[0].keys() | states[1].keys() if states[0].get(p) != states[1].get(p)}
    assert changed <= {'Intrinsics.rep/idata/~index.bak', 'Intrinsics.rep/idata/~journal.bak'}
    assert all(state == states[1] for state in states[1:])
    assert protected == {p: digest(Path(p)) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_INSTALLED_INTRINSIC_CONTEXT',
        'target': 'x86_64', 'outputs': outputs, 'protectedSha256': protected,
        'projectSha256': states[-1], 'firstReopenBackups': sorted(changed)}, indent=4) + '\n')
    print('intrinsic-context=PASS')


if __name__ == '__main__':
    main()
