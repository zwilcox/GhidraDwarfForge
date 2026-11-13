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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--models', type=Path, required=True)
    parser.add_argument('--classpath', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--targets', nargs='+', choices=('x86_64', 'aarch64'), default=['x86_64', 'aarch64'])
    parser.add_argument('--roles', nargs='+', choices=('exec', 'pie', 'exec-no-rtti', 'pie-no-rtti'),
        default=['exec', 'pie', 'exec-no-rtti', 'pie-no-rtti'])
    parser.add_argument('--rebase', action='store_true', help='Rebase after saving evidence, without refreshing it')
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    commands, cases = [], []
    java = str(Path(os.environ['JAVA_HOME']) / 'bin/java')
    classpath = args.classpath.read_text().strip()
    scripts = ';'.join(map(str, (HERE, REPOSITORY / 'ghidra_scripts')))
    headless = args.ghidra.resolve() / 'support/analyzeHeadless'
    settings = root / 'settings'
    settings.mkdir()
    temporary = Path(os.environ.get('TMPDIR', str(root / 'tmp'))).resolve()
    temporary.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'TMPDIR': str(temporary), 'JAVA_TOOL_OPTIONS':
        f'-Duser.home={settings} -Djava.io.tmpdir={temporary}'}

    def run(label, command, timeout=240):
        argv = list(map(str, command))
        commands.append({'label': label, 'argv': argv})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        log = root / (label + '.log')
        with log.open('w') as stream:
            subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, env=env, timeout=timeout, check=True)
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
            original = digest(runtime)
            project = case / 'project'
            project.mkdir()
            produced = case / 'producer.dbg'
            output_args = [
                '--libdwarf=' + os.environ['LIBDWARF'], '--libdwarfp=' + os.environ['LIBDWARFP'],
                '--output=' + str(produced)]
            for phase in ('curate', 'reopen'):
                command = [headless, project, 'Inheritance', '-scriptPath', scripts, '-noanalysis']
                if phase == 'curate':
                    command += ['-import', runtime, '-postScript', 'PrepareInheritanceFixture.java', model_dir / 'model.json']
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
            artifact = case / 'forge-vtables.dbg'
            run(label + '-package', [java, '-cp', classpath, 'ghidradwarfforge.elf.VtablePackagingProbe',
                runtime, produced, model_dir / 'vtables.json', artifact])
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
            run(label + '-gdb', ['bash', HERE / 'gdb.sh', case, target, 'forge-vtables'])
            actual = json.loads((case / 'forge-vtables.gdb.json').read_text())
            expected = json.loads((ref / 'c11-vtables.gdb.json').read_text())
            for field in ('dynamicTypes', 'baseValues', 'offsets', 'inheritedValues'):
                assert actual[field] == expected[field], (label, field, actual[field], expected[field])
            assert digest(runtime) == original
            cases.append({'target': target, 'role': role, 'rebased': args.rebase, 'observed': actual, 'inputSha256': original,
                'sidecarSha256': digest(produced), 'sourceSha256': first[1], 'savedProgramUnchanged': True,
                'projectMetadataChanges': changed})
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_SAVED_INHERITANCE_EXPORT', 'cases': cases,
        'scope': 'ordinary export of curated saved programs; vtable symbols supplied separately from compiler evidence'}, indent=4) + '\n')
    print('inheritance-extraction=PASS', root)


if __name__ == '__main__':
    main()
