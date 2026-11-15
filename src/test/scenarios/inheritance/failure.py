#!/usr/bin/env python3
"""Native decompiler failure with saved inheritance, table identities and adjustment thunks."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('object_checker', HERE.parents[1] / 'integration/check-object-parameters.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--extraction', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--targets', nargs='+', choices=('x86_64', 'aarch64'), default=['x86_64', 'aarch64'])
    parser.add_argument('--roles', nargs='+', choices=('exec', 'pie', 'exec-no-rtti', 'pie-no-rtti'), default=['pie-no-rtti'])
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    commands, cases = [], []
    settings = root / 'settings'
    settings.mkdir()
    temporary = Path(os.environ.get('TMPDIR', str(root / 'tmp'))).resolve()
    temporary.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'JAVA_TOOL_OPTIONS': f'-Duser.home={settings} -Djava.io.tmpdir={temporary}'}

    def run(label, argv, timeout=240):
        argv = list(map(str, argv))
        commands.append({'label': label, 'argv': argv})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        log = root / (label + '.log')
        with log.open('w') as stream:
            subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, env=env, check=True, timeout=timeout)
        return log.read_text()

    for target in args.targets:
        for role in args.roles:
            label = target + '-' + role
            case = args.extraction.resolve() / label
            project = case / 'project'
            witness = json.loads((case / 'thunks.json').read_text())
            failed_address, = [row['target'] for row in witness['thunks'] if row['kind'] == 'virtual']
            output = case / 'failed-vtables.dbg'
            protected = {str(path): digest(path) for path in [case / 'runtime.elf', case / 'forge-vtables.dbg', case / 'forge-vtables.dbg.c']}
            database = {str(path): digest(path) for path in project.rglob('*') if path.is_file()}
            pair = None
            for iteration in ('first', 'repeat'):
                host = root / (label + '-' + iteration + '-host')
                host.mkdir()
                log = run(label + '-' + iteration, [args.ghidra.resolve() / 'support/analyzeHeadless', host, 'FailureHost',
                    '-deleteProject', '-noanalysis', '-scriptPath', HERE,
                    '-postScript', 'InheritanceDecompilerFailureExport.java', project, 'Inheritance',
                    output, os.environ['LIBDWARF'], os.environ['LIBDWARFP']])
                assert 'inheritance-decompiler-failure=PASS' in log, label
                assert 'Flow exceeded maximum allowable instructions' in log
                assert not re.search(r'REPORT SCRIPT ERROR|Error running script|Exception in thread', log)
                current = [digest(output), digest(Path(str(output) + '.c'))]
                assert pair is None or pair == current, 'failed export is not deterministic'
                pair = current
            source = Path(str(output) + '.c').read_text()
            assert 'Flow exceeded maximum allowable instructions' in source
            assert 'No errors.' in run(label + '-llvm', ['llvm-dwarfdump', '--verify', output])
            info = run(label + '-gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline', output])
            strict = run(label + '-strict', [os.environ['DWARFDUMP'], output])
            assert not re.search(r'warning:|error:', info + strict, re.I)
            dies = checker.read_dies(info)
            failed, = [die for die in dies.values() if die['tag'] == 'DW_TAG_subprogram' and
                int(die['attributes'].get('DW_AT_low_pc', '-1').split()[-1], 0) == failed_address]
            assert failed['name'] == 'Diamond::root_value'
            assert not {'DW_AT_type', 'DW_AT_specification', 'DW_AT_abstract_origin', 'DW_AT_object_pointer',
                'DW_AT_decl_file', 'DW_AT_decl_line', 'DW_AT_virtuality', 'DW_AT_vtable_elem_location'} & failed['attributes'].keys()
            assert not any(die['parent'] == failed['offset'] for die in dies.values()), 'failed method borrowed parameters or locals'
            assert len([die for die in dies.values() if 'DW_AT_vtable_elem_location' in die['attributes']]) == 14
            baseline = (args.extraction.resolve() / (label + '-gnu.log')).read_text()
            assert sum(die['tag'] == 'DW_TAG_inheritance' for die in dies.values()) == sum(
                die['tag'] == 'DW_TAG_inheritance' for die in checker.read_dies(baseline).values()) > 0
            trampolines = [die for die in dies.values() if 'DW_AT_trampoline' in die['attributes']]
            assert len(trampolines) == 3
            assert sum(die['attributes']['DW_AT_trampoline'].endswith(f"<0x{failed['offset']:x}>") for die in trampolines) == 1
            # Runtime derived types still rely on independent canonical layouts and admitted tables.
            run(label + '-gdb', ['bash', HERE / 'gdb.sh', case, target, 'failed-vtables'])
            observed = json.loads((case / 'failed-vtables.gdb.json').read_text())
            expected = json.loads((case / 'forge-vtables.gdb.json').read_text())
            for field in ('dynamicTypes', 'baseValues', 'offsets', 'inheritedValues'):
                assert observed[field] == expected[field], (label, field)
            assert protected == {path: digest(Path(path)) for path in protected}
            after = {str(path): digest(path) for path in project.rglob('*') if path.is_file()}
            (root / (label + '-project-preservation.json')).write_text(json.dumps({'before': database, 'after': after}, indent=4) + '\n')
            assert database == after, 'read-only failure test changed saved project'
            cases.append({'target': target, 'role': role, 'failedMethod': 'Diamond::root_value', 'failedAddress': failed_address,
                'outputPair': pair, 'virtualMethodsRetained': 14, 'thunkRelationshipsRetained': 3,
                'preserved': protected, 'projectUnchanged': True, 'observed': observed})
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_NATIVE_INHERITANCE_FAILURE', 'cases': cases}, indent=4) + '\n')
    print('inheritance-native-failure=PASS', root)


if __name__ == '__main__':
    main()
