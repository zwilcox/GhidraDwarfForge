#!/usr/bin/env python3
"""Curate stripped ELF fixtures, reopen saved programs, and test ordinary Forge export."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[3]
spec = importlib.util.spec_from_file_location('object_checker', HERE.parents[1] / 'integration/check-object-parameters.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()



def fixture_names(model, variant):
    classes = {row['name']: row for row in model['classes']}
    result = {}
    for phase, types in [('dynamic', {'single_base': 'Single', 'multiple_right': 'Multiple',
            'diamond_base': 'Diamond', 'diamond_right': 'Diamond', 'abstract_base': 'Concrete'}),
            ('static', {'single_base': 'Base', 'multiple_right': 'Right',
            'diamond_base': 'VirtualBase', 'diamond_right': 'VirtualRight', 'abstract_base': 'Abstract'})]:
        result[phase] = {variable: {'name': 'Recovered_' + kind if variant == 'renamed' else 'Shared' if variant == 'duplicate' else kind,
            'size': classes[kind]['size'], 'members': [member['name'] for member in classes[kind]['members']]}
            for variable, kind in types.items()}
    return result


def patch_retained_sizes(path, tables):
    import struct
    data = bytearray(path.read_bytes())
    assert data[:6] == b'\x7fELF\x02\x01'
    shoff = struct.unpack_from('<Q', data, 40)[0]
    width, count = struct.unpack_from('<HH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * width) for i in range(count)]
    sizes = {table['name']: table['size'] for table in tables}
    seen = set()
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        text = data[strings[4]:strings[4] + strings[5]]
        for at in range(section[4], section[4] + section[5], section[9]):
            offset = struct.unpack_from('<I', data, at)[0]
            name = text[offset:text.index(0, offset)].decode()
            if name in sizes:
                assert name not in seen
                seen.add(name)
                struct.pack_into('<Q', data, at + 16, sizes[name])
    assert seen == set(sizes)
    path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--models', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--targets', nargs='+', choices=('x86_64', 'aarch64'), default=['x86_64', 'aarch64'])
    parser.add_argument('--roles', nargs='+', choices=('exec', 'pie', 'exec-no-rtti', 'pie-no-rtti'),
        default=['exec', 'pie', 'exec-no-rtti', 'pie-no-rtti'])
    parser.add_argument('--variant', choices=('valid', 'missing', 'stale', 'conflict', 'renamed', 'qualified', 'duplicate', 'retained'), default='valid')
    parser.add_argument('--rebase', action='store_true', help='Rebase after saving evidence, without refreshing it')
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    commands, cases = [], []
    scripts = ';'.join(map(str, (HERE, REPOSITORY / 'ghidra_scripts')))
    headless = args.ghidra.resolve() / 'support/analyzeHeadless'
    settings = root / 'settings'
    settings.mkdir()
    temporary = Path(os.environ.get('TMPDIR', str(root / 'tmp'))).resolve()
    temporary.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'TMPDIR': str(temporary), 'JAVA_TOOL_OPTIONS':
        f'-Duser.home={settings} -Djava.io.tmpdir={temporary}'}

    def run(label, command, timeout=240, extra_env=None):
        argv = list(map(str, command))
        commands.append({'label': label, 'argv': argv})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        log = root / (label + '.log')
        with log.open('w') as stream:
            subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, env={**env, **(extra_env or {})}, timeout=timeout, check=True)
        return log.read_text()

    for target in args.targets:
        for role in args.roles:
            label = target + '-' + role
            case = root / label
            case.mkdir()
            model_dir = args.models.resolve() / label
            model = json.loads((model_dir / 'model.json').read_text())
            ref = args.references.resolve() / label
            runtime = case / 'runtime.elf'
            shutil.copy2(ref / 'runtime.elf', runtime)
            tables = json.loads((model_dir / 'vtables.json').read_text())
            if args.variant == 'retained':
                command = ['objcopy' if target == 'x86_64' else 'aarch64-linux-gnu-objcopy']
                for table in tables:
                    command += ['--add-symbol', f"{table['name']}={table['section']}:{table['address'] - table['sectionAddress']},local,object"]
                # GNU objcopy does not set symbol sizes; fill only these owned fixture records below.
                run(label + '-retain-symbols', [*command, runtime])
                patch_retained_sizes(runtime, tables)
            original = digest(runtime)
            project = case / 'project'
            project.mkdir()
            produced = case / 'forge-vtables.dbg'
            output_args = [
                '--libdwarf=' + os.environ['LIBDWARF'], '--libdwarfp=' + os.environ['LIBDWARFP'],
                '--output=' + str(produced)]
            for phase in ('curate', 'reopen'):
                command = [headless, project, 'Inheritance', '-scriptPath', scripts, '-noanalysis']
                if phase == 'curate':
                    command += ['-import', runtime, '-postScript', 'PrepareInheritanceFixture.java', model_dir / 'model.json']
                    command += ['-postScript', 'ProbeVtableBindings.java', model_dir / 'vtables.json',
                        case / 'vtable-witnesses.json', 'save-only']
                    if args.variant not in ('valid', 'retained'):
                        command += ['-postScript', 'MutateVtableFixture.java', args.variant,
                            model_dir / 'model.json', case / 'vtable-witnesses.json']
                    if args.rebase:
                        command += ['-postScript', 'RebaseInheritanceFixture.java']
                    command += ['-postScript', 'GhidraDwarfForge.java', *output_args]
                else:
                    command = [REPOSITORY / 'support/ghidra-dwarf-forge-headless',
                        '--ghidra-dir=' + str(args.ghidra.resolve()), '--project-dir=' + str(project),
                        '--project-name=Inheritance', '--program=runtime.elf', *output_args]
                log = run(label + '-' + phase, command)
                reports = re.findall(r'GhidraDwarfForge report: (\{.*\})', log)
                assert len(reports) == 1, label + '-' + phase
                report = json.loads(reports[0])
                assert report['status'] in ('SUCCESS', 'PARTIAL'), report['status']
                assert report['counts']['functionsFailed'] == 0, report['failedFunctions']
                assert not re.search(r'REPORT SCRIPT ERROR|Error running script|Exception in thread', log), label + '-' + phase
                assert 'Omitted explicit inheritance' not in log, label
                if args.variant in ('stale', 'conflict'):
                    reason = 'bytes changed' if args.variant == 'stale' else 'conflicting table identity'
                    assert 'Omitted explicit vtable' in log and reason in log, (label, args.variant)
                else:
                    assert 'Omitted explicit vtable' not in log, label
                if phase == 'curate':
                    assert 'inheritance-curation=PASS' in log
                    if args.rebase:
                        assert 'inheritance-rebase=PASS' in log
                    first = digest(produced), digest(Path(str(produced) + '.c'))
                    database = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
                    (case / 'project-before.json').write_text(json.dumps(database, indent=4) + '\n')
                else:
                    assert first == (digest(produced), digest(Path(str(produced) + '.c'))), 'reopen changed generation'
                    after = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
                    changed = {name: {'before': database.get(name), 'after': after.get(name)}
                        for name in sorted(database.keys() | after.keys()) if database.get(name) != after.get(name)}
                    (case / 'project-preservation.json').write_text(json.dumps({'before': database, 'after': after,
                        'changed': changed}, indent=4) + '\n')
                    assert any(name.startswith('Inheritance.rep/idata/') for name in database)
                    assert not changed, changed
            artifact = produced
            symbols = run(label + '-symbols', ['readelf', '-sW', artifact])
            negative = args.variant in ('missing', 'stale', 'conflict')
            for table in tables:
                name = table['name']
                if args.variant in ('qualified', 'duplicate'):
                    original_name, = re.findall(r'^_ZTV\d+(.*)$', name)
                    name = (f'_ZTVN6origin{len(original_name)}{original_name}E' if args.variant == 'qualified'
                        else f'_ZTVN{len(original_name)}{original_name}6SharedE')
                matches = [line.split() for line in symbols.splitlines() if line.split() and line.split()[-1] == name]
                if negative:
                    assert not matches, (label, name, matches)
                    continue
                assert len(matches) == 1 and matches[0][3] == 'OBJECT', (label, table['name'], matches)
                assert int(matches[0][1], 16) == table['address'] and int(matches[0][2]) == table['size']
            assert 'No errors.' in run(label + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
            for validator, command in [('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline']),
                    ('strict', [os.environ['DWARFDUMP']])]:
                output = run(label + '-' + validator, [*command, artifact])
                assert not re.search(r'warning:|error:', output, re.I), label + '-' + validator
                if validator == 'gnu':
                    dies = checker.read_dies(output)
                    bases = [die for die in dies.values() if die['tag'] == 'DW_TAG_inheritance']
                    methods = [die for die in dies.values() if 'DW_AT_vtable_elem_location' in die['attributes']]
                    assert len(bases) == len(model['bases']) and len(methods) == len(model['methods'])
                    assert all('DW_AT_object_pointer' in die['attributes'] for die in methods)
                    pure = [die for die in methods if re.search(r'\b2\b.*pure_virtual', die['attributes']['DW_AT_virtuality'])]
                    assert len(pure) == sum(row.get('virtuality') == 2 for row in model['methods']) == 1
                    assert all('DW_AT_low_pc' not in die['attributes'] and 'DW_AT_ranges' not in die['attributes'] for die in pure)
                    mixed_owner = pure[0]['parent']
                    sibling, = [die for die in methods if die['parent'] == mixed_owner and die['name'] == 'base_value']
                    definitions = [die for die in dies.values() if 'DW_AT_low_pc' in die['attributes'] and
                        die['attributes'].get('DW_AT_specification', '').endswith(f"<0x{sibling['offset']:x}>")]
                    assert len(definitions) == 1, 'mixed canonical class lost its local method definition'
            if args.variant == 'valid':
                run(label + '-gdb', ['bash', HERE / 'gdb.sh', case, target, 'forge-vtables'])
                actual = json.loads((case / 'forge-vtables.gdb.json').read_text())
                expected = json.loads((ref / 'c11-vtables.gdb.json').read_text())
                for field in ('dynamicTypes', 'baseValues', 'offsets', 'inheritedValues'):
                    assert actual[field] == expected[field], (label, field, actual[field], expected[field])
            else:
                names = fixture_names(model, args.variant)
                name_file = case / 'names.json'
                name_file.write_text(json.dumps(names, indent=4) + '\n')
                run(label + '-gdb', ['bash', HERE / 'gdb.sh', case, target, 'forge-vtables', HERE / 'name-gdb.py'],
                    extra_env={'INHERITANCE_NAMES': str(name_file), 'INHERITANCE_EXPECT_STATIC': '1' if negative else '0'})
                actual = json.loads((case / 'forge-vtables.gdb.json').read_text())
                assert actual['status'] == ('PASS_STATIC_NAME_CONTROL' if negative else 'PASS_RECOVERED_VTABLE_NAMES')
            assert digest(runtime) == original
            cases.append({'target': target, 'role': role, 'variant': args.variant, 'rebased': args.rebase, 'observed': actual, 'inputSha256': original,
                'sidecarSha256': digest(produced), 'sourceSha256': first[1], 'savedProgramUnchanged': True,
                'projectMetadataChanges': changed})
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_SAVED_INHERITANCE_EXPORT', 'cases': cases,
        'scope': 'ordinary export of curated saved programs with persisted vtable evidence and original-ELF admission'}, indent=4) + '\n')
    print('inheritance-extraction=PASS', root)


if __name__ == '__main__':
    main()
