#!/usr/bin/env python3
"""Selected production faults against completed native failure fixtures; no coverage agent."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


MUTANTS = (
    ('missing-native-cleanup', 'section-null', 'if (!finished) {', 'if (false) {'),
    ('unbounded-producer-buffer-count', 'buffer-count-large',
        'bufferCount <= 0 || bufferCount > 100_000', 'bufferCount <= 0'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'output', 'java-home', 'ghidra'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    baseline = args.baseline.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = json.loads((baseline / 'result.json').read_text())
    assert result['status'] == 'PASS_ISOLATED_PRODUCER_FAILURES' and len(result['controls']) == 28
    digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    for path, expected in result['protected'].items():
        assert digest(path) == expected
    assert digest(baseline / 'producer-fault-shim.so') == result['shimSha256']
    repo = Path(__file__).resolve().parents[3]
    for path, expected in result['harnessSha256'].items():
        assert digest(repo / path) == expected, path
    source = repo / 'src/main/java/ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter.java'
    original = source.read_text()
    commands = {row['name']: row for row in json.loads((baseline / 'commands.json').read_text())}
    spec = importlib.util.spec_from_file_location('mutation_outcomes', Path(__file__).with_name('mutation-check.py'))
    outcomes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(outcomes)
    java = args.java_home.resolve() / 'bin/java'
    javac = args.java_home.resolve() / 'bin/javac'
    results = []
    start = time.monotonic()
    for label, mode, before, after in MUTANTS:
        assert original.count(before) == 1, label
        command = [part for part in commands[mode]['command'] if not part.startswith('-javaagent:')]
        command[0] = str(java)
        classpath_index = command.index('-cp') + 1
        main_index = command.index('ghidradwarfforge.nativeapi.ProducerFailureProbe')
        assert len(command) == main_index + 9
        original_classpath = command[classpath_index]
        for mutant in (False, True):
            name = label + ('-mutant' if mutant else '-baseline')
            with tempfile.TemporaryDirectory(prefix=name + '-', dir=output) as temporary:
                root = Path(temporary)
                changed = root / 'ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter.java'
                changed.parent.mkdir(parents=True)
                changed.write_text(original.replace(before, after) if mutant else original)
                compile_path = os.pathsep.join([original_classpath,
                    *map(str, sorted(args.ghidra.resolve().glob('Ghidra/**/lib/*.jar')))])
                compile_command = [str(javac), '-Xlint:all,-serial,-path', '-proc:none', '-Werror',
                    '-cp', compile_path, '-d', str(root), str(changed)]
                compiled = subprocess.run(compile_command, capture_output=True, text=True, timeout=60)
                (output / (name + '-compile.log')).write_text(compiled.stdout + compiled.stderr)
                assert compiled.returncode == 0, name + ': compilation is not mutation detection'
                selected = list(command)
                selected[classpath_index] = str(root) + os.pathsep + original_classpath
                selected[main_index + 4] = str(root / 'artifacts')
                selected = [('-Djava.io.tmpdir=' + str(root)) if part.startswith('-Djava.io.tmpdir=') else
                    ('-Djna.tmpdir=' + str(root)) if part.startswith('-Djna.tmpdir=') else part for part in selected]
                run = subprocess.run(selected, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
                (output / (name + '.log')).write_text(run.stdout)
                detection = outcomes.verify_outcome(name, run, mutant, None)
                if not mutant:
                    assert 'producer-failure=PASS mode=' + mode + ' ' in run.stdout
                else:
                    expected = 'native producer handle unfinished' if mode == 'section-null' else 'wrong rejection'
                    assert expected in run.stdout, name + ': wrong behavioral assertion'
                results.append({'name': name, 'mode': mode, 'status': 'DETECTED' if mutant else 'BASELINE_PASS',
                    'detection': detection, 'exitCode': run.returncode,
                    'compileCommand': compile_command, 'command': selected})
    assert source.read_text() == original
    for path, expected in result['protected'].items():
        assert digest(path) == expected
    record = {'status': 'PASS', 'mutantsDetected': len(MUTANTS), 'results': results,
        'seconds': time.monotonic() - start, 'productionSourceSha256': digest(source),
        'baselineResultSha256': digest(baseline / 'result.json'), 'coverageCollected': False,
        'scope': 'Selected native cleanup and result-bound faults only; not a repository-wide mutation score'}
    (output / 'result.json').write_text(json.dumps(record, indent=4) + '\n')
    print('producer-failure-mutations=PASS faults=' + str(len(MUTANTS)))


if __name__ == '__main__':
    main()
