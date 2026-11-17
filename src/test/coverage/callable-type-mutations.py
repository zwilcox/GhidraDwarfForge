#!/usr/bin/env python3
"""Compile selected encoding faults and require the real output oracle to detect them."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


MUTANTS = (
    ('missing-ellipsis', 'if (subroutine.variadic()) {',
        'if (false) {', 'variadic parameter children', 'normal'),
    ('missing-noreturn', 'if (declaration.noReturn()) {',
        'if (false) {', 'noreturn flag', 'normal'),
    ('unknown-is-normal', '!callingConvention.equals("unknown")',
        'true', 'calling convention', 'unknown'),
)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'output', 'java-home', 'ghidra'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(repo / 'src/test/integration'))
    spec = importlib.util.spec_from_file_location('callable_types', repo / 'src/test/integration/callable-type-producer.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    baseline = args.baseline.resolve(strict=True)
    result = json.loads((baseline / 'result.json').read_text())
    assert result['status'] == 'PASS_CALLABLE_TYPE_PRODUCER'
    assert all(oracle.digest(path) == sha for path, sha in result['protected'].items())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = {row['label']: row for row in json.loads((baseline / 'commands.json').read_text())}
    command = [part for part in commands['producer']['command'] if not part.startswith('-javaagent:')]
    command[0] = str(args.java_home.resolve() / 'bin/java')
    cp_index = command.index('-cp') + 1
    main_index = command.index('ghidradwarfforge.nativeapi.CallableTypeProducerProbe')
    assert len(command) == main_index + 6
    classpath = command[cp_index]
    source = repo / 'src/main/java/ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter.java'
    original = source.read_text()
    request = json.loads((baseline / 'request.json').read_text())
    symbols = request
    parser_path = repo / 'src/test/integration/check-object-parameters.py'
    spec = importlib.util.spec_from_file_location('callable_mutant_dies', parser_path)
    dies = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dies)
    outcomes = []
    for label, before, after, expected, mode in (('baseline', '', '', None, 'normal'), *MUTANTS):
        assert not before or original.count(before) == 1, label
        with tempfile.TemporaryDirectory(prefix=label + '-', dir=output) as temp:
            root = Path(temp)
            changed = root / 'ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter.java'
            changed.parent.mkdir(parents=True)
            changed.write_text(original.replace(before, after) if before else original)
            compile_path = os.pathsep.join([classpath,
                *map(str, sorted(args.ghidra.resolve().glob('Ghidra/**/lib/*.jar')))])
            compile_command = [str(args.java_home.resolve() / 'bin/javac'), '-proc:none',
                '-Xlint:all,-serial,-path', '-Werror', '-cp', compile_path, '-d', str(root), str(changed)]
            compiled = subprocess.run(compile_command, capture_output=True, text=True, timeout=60)
            (output / (label + '-compile.log')).write_text(compiled.stdout + compiled.stderr)
            assert compiled.returncode == 0, 'compilation failure is not mutation detection'
            selected = list(command)
            selected[cp_index] = str(root) + os.pathsep + classpath
            selected[main_index + 4] = str(root)
            exported = subprocess.run(selected, capture_output=True, text=True, timeout=60)
            (output / (label + '-producer.log')).write_text(exported.stdout + exported.stderr)
            assert exported.returncode == 0 and 'callable-type-producer=PASS' in exported.stdout, \
                'producer crash or exception is not output-oracle detection'
            artifact = root / (mode + '.dbg')
            readelf = subprocess.run(['readelf', '--debug-dump=info', artifact],
                capture_output=True, text=True, timeout=30)
            assert readelf.returncode == 0 and not readelf.stderr.strip()
            (output / (label + '-info.log')).write_text(readelf.stdout)
            try:
                oracle.oracle(readelf.stdout, mode, symbols, dies)
            except AssertionError as error:
                assert expected is not None and error.args == (expected,), (label, error.args)
                detection = repr(error.args[0])
            else:
                assert expected is None, 'real output oracle missed ' + label
                detection = 'BASELINE_PASS'
            outcomes.append({'name': label, 'status': 'DETECTED' if expected else 'BASELINE_PASS',
                'detection': detection, 'compileCommand': compile_command, 'command': selected})
    assert source.read_text() == original
    assert all(oracle.digest(path) == sha for path, sha in result['protected'].items())
    (output / 'result.json').write_text(json.dumps({'status': 'PASS', 'mutantsDetected': len(MUTANTS),
        'coverageCollected': False, 'productionSourceSha256': oracle.digest(source),
        'baselineResultSha256': oracle.digest(baseline / 'result.json'), 'results': outcomes,
        'scope': 'Three selected callable metadata faults; no repository-wide mutation score'}, indent=4) + '\n')
    print('callable-type-mutations=PASS faults=' + str(len(MUTANTS)))


if __name__ == '__main__':
    main()
