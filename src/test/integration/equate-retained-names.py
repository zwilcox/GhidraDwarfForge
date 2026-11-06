#!/usr/bin/env python3
"""Retained C++ symbols must survive analyst renames and synthetic equate lookup."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


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
    root = Path(tempfile.mkdtemp(prefix='retained-equates-', dir=args.results)).resolve()
    print('retained-equates-results=' + str(root), flush=True)
    project, scripts = root / 'project', root / 'scripts'
    project.mkdir()
    scripts.mkdir()
    script = harness / 'ghidra_scripts/VerifyRetainedEquateNames.java'
    shutil.copy2(script, scripts / script.name)
    module = args.ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    source = harness.parent / 'fixtures/equate-retained-names.cpp'
    protected = {str(p): digest(p) for p in [source, script, Path(__file__),
        module / 'lib/GhidraDwarfForge.jar', module / 'ghidra_scripts/GhidraDwarfForge.java']}
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        (root / (label + '.stdout')).write_text(result.stdout)
        (root / (label + '.stderr')).write_text(result.stderr)
        assert result.returncode == 0, (label, root, result.stderr[-1500:])
        return result.stdout + result.stderr

    run('compile', ['g++', '-O0', '-g', '-gdwarf-5', '-fno-pie', '-no-pie',
        '-Wall', '-Wextra', '-Werror', source, '-o', root / 'reference'])
    original = root / 'original'
    run('strip-debug', ['objcopy', '--strip-debug', root / 'reference', original])
    protected[str(original)] = digest(original)
    protected[str(root / 'reference')] = digest(root / 'reference')
    run('original-symbols', ['nm', '-S', original])
    common = [args.ghidra / 'support/analyzeHeadless', project, 'Retained', '-scriptPath',
        str(scripts) + ';' + str(module / 'ghidra_scripts')]
    setup = run('setup', common + ['-import', original, '-postScript', script.name, 'setup', root / 'setup.json'])
    assert 'retained-equate-names=PASS' in setup and 'ERROR REPORT SCRIPT ERROR' not in setup
    states = [snapshot(project)]
    generations = []
    for phase in ('read1', 'read2'):
        text = run(phase, common + ['-process', 'original', '-noanalysis', '-readOnly',
            '-postScript', script.name, 'read', root / (phase + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--input', original, '--output', root / 'forge.dbg',
            '--libdwarf', args.consumer, '--libdwarfp', args.producer])
        assert 'retained-equate-names=PASS' in text and 'GhidraDwarfForge symbol export PASS' in text
        assert 'ERROR REPORT SCRIPT ERROR' not in text
        script_origin, = re.findall(r'(?m)^INFO  SCRIPT: (.+GhidraDwarfForge\.java) \(HeadlessAnalyzer\)', text)
        assert Path(script_origin).resolve() == (module / 'ghidra_scripts/GhidraDwarfForge.java').resolve(), script_origin
        states.append(snapshot(project))
        generations.append({name: digest(root / name) for name in ('forge.dbg', 'forge.dbg.c')})
    assert generations[0] == generations[1]
    assert (root / 'read1.json').read_bytes() == (root / 'read2.json').read_bytes()
    changes = [key for key in states[0].keys() | states[1].keys() if states[0].get(key) != states[1].get(key)]
    assert set(changes) <= {'Retained.rep/idata/~index.bak', 'Retained.rep/idata/~journal.bak'}
    assert states[1] == states[2]
    for index, state in enumerate(states):
        (root / ('project-' + str(index) + '.json')).write_text(json.dumps(state, indent=4) + '\n')
    sidecar = root / 'forge.dbg'
    for view in ('info', 'abbrev', 'aranges', 'decodedline'):
        assert not re.search('warning:|error:', run(view, ['readelf', '--debug-dump=' + view, sidecar]), re.I)
    run('identity', ['readelf', '-hSWn', original, sidecar])
    assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', sidecar])
    run('strict', ['python3', harness / 'check-dwarfdump.py', sidecar, root / 'strict.log', '--original', original])
    check = '''import gdb, json
from pathlib import Path
root = Path(__file__).parent
data = json.loads((root / 'read1.json').read_text())
constants = [c for e in data['constants'] for c in e['constants']]
assert len(constants) == 10
for original, curated in (('retained_lookup', 'curated_retained_function'),
        ('forge_equate_type_u64', 'curated_type_named_function')):
    assert int(gdb.parse_and_eval('&' + original)) == int(gdb.parse_and_eval('&' + curated))
    assert gdb.lookup_global_symbol(original) is None
point = gdb.Breakpoint('retained_lookup', temporary=True)
gdb.execute('run')
assert gdb.newest_frame().name() == 'curated_retained_function'
checks = []
for constant in constants:
    value = constant['value']
    expected = value['value'] if value['signed'] else value['value'] & ((1 << value['bits']) - 1)
    for expression in (constant['name'], "'forge.dbg.c'::" + constant['name']):
        actual = gdb.parse_and_eval(expression)
        assert int(actual) == expected and actual.address is None
        assert actual.type.sizeof == 8
        if not value['signed']:
            assert str(actual.type) == 'const forge_equate_type_u64_1', str(actual.type)
        checks.append({'expression': expression, 'value': int(actual), 'type': str(actual.type)})
gdb.Breakpoint('forge_equate_type_u64', temporary=True)
gdb.execute('continue')
assert gdb.newest_frame().name() == 'curated_type_named_function'
exits = []
gdb.events.exited.connect(lambda e: exits.append(e.exit_code))
gdb.execute('continue')
assert exits == [0]
(root / 'gdb-result.json').write_text(json.dumps(checks, indent=4) + '\\n')
print('retained-equates-gdb=PASS')
'''
    (root / 'check.py').write_text(check)
    (root / 'check.gdb').write_text('set pagination off\nset confirm off\nset debuginfod enabled off\n'
        'set auto-solib-add off\nset disable-randomization off\nfile ' + str(original) + '\nsymbol-file ' +
        str(sidecar) + '\nsource ' + str(root / 'check.py') + '\nquit\n')
    assert 'retained-equates-gdb=PASS' in run('gdb', ['gdb-multiarch', '-nx', '-batch', '-x', root / 'check.gdb'])
    assert not (root / 'gdb.stderr').read_text().strip()
    assert protected == {p: digest(Path(p)) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_RETAINED_DEMANGLED_EQUATES',
        'protected': protected, 'generations': generations, 'projectBackupChanges': changes,
        'scope': 'Native x86-64 GNU C++ fixture; actual saved renames, default export, retained function breakpoints and synthetic value/type collision.'}, indent=4) + '\n')
    print('retained-equates=PASS')


if __name__ == '__main__':
    main()
