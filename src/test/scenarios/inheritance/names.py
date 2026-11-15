#!/usr/bin/env python3
"""Compare mangled symbols and lookup aliases for analyst-renamed classes."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--models', type=Path, required=True)
    parser.add_argument('--classpath', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--targets', nargs='+', choices=('x86_64', 'aarch64'), default=['x86_64', 'aarch64'])
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    java = str(Path(os.environ['JAVA_HOME']) / 'bin/java')
    classpath = args.classpath.read_text().strip()
    commands, results = [], []

    def run(label, command, extra_env=None):
        argv = list(map(str, command))
        commands.append({'label': label, 'argv': argv})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            subprocess.run(argv, env={**os.environ, **(extra_env or {})}, stdout=log, stderr=subprocess.STDOUT,
                timeout=150, check=True)
        return (root / (label + '.log')).read_text()

    for target in args.targets:
        for role in ('exec', 'pie', 'exec-no-rtti', 'pie-no-rtti'):
            supplied = args.models.resolve() / (target + '-' + role)
            original_model = json.loads((supplied / 'model.json').read_text())
            for variant in ('readable-control', 'renamed-mangled', 'renamed-alias', 'qualified-alias', 'duplicate-alias'):
                renamed = variant != 'readable-control'
                label = target + '-' + role + '-' + variant
                case = root / label
                case.mkdir()
                runtime = case / 'runtime.elf'
                shutil.copy2(supplied / 'runtime.elf', runtime)
                original = hashlib.sha256(runtime.read_bytes()).hexdigest()
                model = copy.deepcopy(original_model)
                keys = {row['name']: ('Recovered' if renamed else '') + row['name'] for row in model['classes']}
                names = {key: 'Shared' if variant == 'duplicate-alias' else value for key, value in keys.items()}
                for row in model['classes']:
                    original_name = row['name']
                    row['typeName'] = names[original_name]
                    if variant in ('renamed-alias', 'qualified-alias'):
                        row['scopeName'] = row['name']
                    if variant == 'qualified-alias':
                        row['namespace'] = 'ns'
                    if variant == 'duplicate-alias':
                        row['namespace'], row['scopeName'] = original_name, 'Shared'
                    row['name'] = keys[original_name]
                for row in model['bases']:
                    row['derived'], row['base'] = keys[row['derived']], keys[row['base']]
                for row in model['methods']:
                    row['owner'] = keys[row['owner']]
                for row in model['globals']:
                    row['type'] = keys[row['type']]
                model_file = case / 'model.json'
                model_file.write_text(json.dumps(model, indent=4) + '\n')
                names_file = case / 'names.json'
                expected = {}
                original_classes = {row['name']: row for row in original_model['classes']}
                for phase, types in [('dynamic', {'single_base': 'Single', 'multiple_right': 'Multiple',
                        'diamond_base': 'Diamond', 'diamond_right': 'Diamond', 'abstract_base': 'Concrete'}),
                        ('static', {'single_base': 'Base', 'multiple_right': 'Right',
                        'diamond_base': 'VirtualBase', 'diamond_right': 'VirtualRight', 'abstract_base': 'Abstract'})]:
                    expected[phase] = {variable: {'name': names[kind], 'size': original_classes[kind]['size'],
                        'members': [member['name'] for member in original_classes[kind]['members']]}
                        for variable, kind in types.items()}
                names_file.write_text(json.dumps(expected, indent=4) + '\n')
                debug = case / 'producer.dbg'
                run(label + '-producer', [java, '-cp', classpath, 'ghidradwarfforge.nativeapi.InheritanceProducerProbe',
                    os.environ['LIBDWARF'], os.environ['LIBDWARFP'], runtime, model_file, debug])
                tables = json.loads((supplied / 'vtables.json').read_text())
                for table in tables:
                    original_name, = re.findall(r'^_ZTV\d+(.*)$', table['name'])
                    if variant == 'readable-control':
                        table['name'] = 'vtable for ' + original_name
                    elif variant == 'renamed-mangled':
                        table['name'] = '_ZTV' + str(len(names[original_name].encode('utf-8'))) + names[original_name]
                    elif variant == 'qualified-alias':
                        table['name'] = '_ZTVN2ns' + str(len(original_name)) + original_name + 'E'
                    elif variant == 'duplicate-alias':
                        table['name'] = '_ZTVN' + str(len(original_name)) + original_name + '6SharedE'
                table_file = case / 'vtables.json'
                table_file.write_text(json.dumps(tables, indent=4) + '\n')
                artifact = case / 'forge-vtables.dbg'
                run(label + '-package', [java, '-cp', classpath, 'ghidradwarfforge.elf.VtablePackagingProbe',
                    runtime, debug, table_file, artifact])
                assert 'No errors.' in run(label + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
                for tool, command in [('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline']),
                        ('strict', [os.environ['DWARFDUMP']])]:
                    assert not re.search(r'warning:|error:', run(label + '-' + tool, [*command, artifact]), re.I)
                run(label + '-gdb', ['bash', HERE / 'gdb.sh', case, target, 'forge-vtables', HERE / 'name-gdb.py'],
                    {'INHERITANCE_NAMES': str(names_file), 'INHERITANCE_EXPECT_STATIC': '1' if variant == 'readable-control' else '0'})
                observed = json.loads((case / 'forge-vtables.gdb.json').read_text())
                assert observed['status'] == ('PASS_STATIC_NAME_CONTROL' if variant == 'readable-control' else 'PASS_RECOVERED_VTABLE_NAMES')
                assert hashlib.sha256(runtime.read_bytes()).hexdigest() == original
                results.append({'target': target, 'role': role, 'variant': variant, 'observed': observed,
                    'inputSha256': original, 'artifactSha256': hashlib.sha256(artifact.read_bytes()).hexdigest()})
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_VTABLE_NAMES', 'cases': results,
        'scope': 'explicit synthetic object names with fixture evidence; not Ghidra vtable admission'}, indent=4) + '\n')
    print('vtable-names=PASS', root)


if __name__ == '__main__':
    main()
