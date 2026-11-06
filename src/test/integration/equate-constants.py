#!/usr/bin/env python3
"""Isolated production constant emission, strict validators and cross-target GDB lookup."""
import argparse
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
    parser.add_argument('fixture', type=Path)
    parser.add_argument('observations', type=Path)
    parser.add_argument('output_parent', type=Path)
    parser.add_argument('--classpath', required=True)
    parser.add_argument('--java', required=True)
    parser.add_argument('--consumer', type=Path, required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--dwarfdump', required=True)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix='equate-constants-', dir=args.output_parent)).resolve()
    fixture = args.fixture.resolve(strict=True)
    original = fixture / 'stripped'
    observations = args.observations.resolve(strict=True)
    protected = {str(p): digest(p) for p in [original, observations, args.consumer, args.producer]}
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (root / (label + '.stdout')).write_text(result.stdout)
        (root / (label + '.stderr')).write_text(result.stderr)
        (root / (label + '.status.json')).write_text(json.dumps({'returncode': result.returncode}) + '\n')
        assert result.returncode == 0, (label, root, result.stderr[-1000:])
        return result.stdout

    labels = json.loads((fixture / 'labels.json').read_text())['annotation_probe']
    (root / 'equates.c').write_text('/* Synthetic equate lookup; no executable source rows. */\n')
    for generation in ('one', 'two'):
        run(generation, [args.java, '-cp', args.classpath, 'ghidradwarfforge.nativeapi.EquateConstantsSmoke',
            original, root / (generation + '.dbg'), args.consumer, args.producer, observations,
            labels['address'], labels['bytes']])
    sidecar = root / 'one.dbg'
    assert sidecar.read_bytes() == (root / 'two.dbg').read_bytes()
    for view in ('info', 'abbrev', 'aranges', 'decodedline'):
        run(view, ['readelf', '--debug-dump=' + view, sidecar])
        assert not re.search('warning:|error:', (root / (view + '.stderr')).read_text(), re.I)
    run('identity', ['readelf', '-hSWn', original, sidecar])
    assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', sidecar])
    run('strict', ['python3', Path(__file__).with_name('check-dwarfdump.py'), sidecar,
        root / 'dwarfdump.log', '--tool', args.dwarfdump, '--original', original])
    constants = [c for e in json.loads(observations.read_text())['constants'] for c in e['constants']]
    constants.append({'name': 'forge_equate_type_u64', 'value': {'bits': 64, 'signed': False, 'value': 99}})
    for bits in (1, 3, 7, 9, 24, 31, 63, 64):
        constants += [{'name': 'width_signed_' + str(bits),
            'value': {'bits': bits, 'signed': True, 'value': -(1 << (bits - 1))}},
            {'name': 'width_unsigned_' + str(bits),
            'value': {'bits': bits, 'signed': False, 'value': (1 << bits) - 1}}]
    (root / 'expected.json').write_text(json.dumps(constants, indent=4) + '\n')
    variables = [block for block in re.split(r'(?m)^ (?=<\d+><[0-9a-f]+>:)',
        (root / 'info.stdout').read_text()) if '(DW_TAG_variable)' in block]
    assert len(variables) == len(constants)
    for block in variables:
        assert block.startswith('<1>'), 'constant has a fabricated lexical owner'
        assert set(re.findall(r'DW_AT_\w+', block)) == {
            'DW_AT_name', 'DW_AT_type', 'DW_AT_const_value', 'DW_AT_artificial', 'DW_AT_external'}
        assert re.search(r'DW_AT_artificial\s*:\s*1', block)
    script = '''import gdb, json
from pathlib import Path
root = Path(__file__).parent
constants = json.loads((root / 'expected.json').read_text())
checked = []
for constant in constants:
    value = constant['value']
    expected = value['value'] if value['signed'] else value['value'] & ((1 << value['bits']) - 1)
    for expression in (constant['name'], "'equates.c'::" + constant['name']):
        actual = gdb.parse_and_eval(expression)
        assert int(actual) == expected, (expression, str(actual), expected)
        assert actual.type.sizeof == (value['bits'] + 7) // 8, (expression, str(actual.type))
        assert actual.address is None, (expression, 'fabricated address')
        assert 'forge_equate_type_' in str(actual.type) and 'const' in str(actual.type), (expression, str(actual.type))
        if value['bits'] == 64 and not value['signed']:
            assert str(actual.type) == 'const forge_equate_type_u64_1', str(actual.type)
        checked.append({'expression': expression, 'value': int(actual), 'bytes': actual.type.sizeof,
            'type': str(actual.type)})
(root / 'gdb-result.json').write_text(json.dumps(checked, indent=4) + '\\n')
print('equate-gdb=PASS checks=' + str(len(checked)))
'''
    (root / 'check.py').write_text(script)
    gdb_commands = ['set pagination off', 'set confirm off', 'file ' + str(original),
        'set auto-solib-add off', 'symbol-file ' + str(sidecar), 'source ' + str(root / 'check.py'), 'quit']
    (root / 'check.gdb').write_text('\n'.join(gdb_commands) + '\n')
    assert 'equate-gdb=PASS' in run('gdb', ['gdb-multiarch', '-nx', '-batch', '-x', root / 'check.gdb'])
    assert not (root / 'gdb.stderr').read_text().strip(), 'unexplained GDB diagnostic'
    assert protected == {p: digest(Path(p)) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_ISOLATED_PRODUCTION_CONSTANTS',
        'protected': protected, 'artifactSha256': digest(sidecar), 'constants': len(constants),
        'gdbChecks': len(constants) * 2, 'deterministic': True,
        'scope': 'Production producer; offline target GDB lookup. Default Ghidra wiring and live-frame lookup pending.'}, indent=4) + '\n')
    print('equate-constants=PASS ' + str(root))


if __name__ == '__main__':
    main()
