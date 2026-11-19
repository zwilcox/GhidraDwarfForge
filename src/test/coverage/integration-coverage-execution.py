#!/usr/bin/env python3
"""Real JVM/JaCoCo/report round trip and corrupt-execution controls; tiny owned fixtures."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('integration_coverage',
    HERE.parent / 'integration/integration_coverage.py')
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


def run(command, log, *, expected=0):
    result = subprocess.run(list(map(str, command)), stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=90)
    log.write_text(result.stdout)
    if result.returncode != expected:
        raise AssertionError(f'unexpected command status {result.returncode}: {log}\n{result.stdout[-3000:]}')
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('java-home', 'agent', 'jacoco-classpath', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    java = args.java_home.resolve() / ('bin/java.exe' if os.name == 'nt' else 'bin/java')
    javac = java.with_name('javac.exe' if os.name == 'nt' else 'javac')
    classes = root / 'classes'
    classes.mkdir()
    source = root / 'source/ghidradwarfforge'
    source.mkdir(parents=True)
    (source / 'CollectorFixture.java').write_text('''package ghidradwarfforge;
public final class CollectorFixture {
    public static void main(String[] args) {
        if (args[0].equals("a")) System.out.println("branch=a");
        else System.out.println("branch=b");
    }
}
''')
    (source / 'UnloadedFixture.java').write_text('''package ghidradwarfforge;
public final class UnloadedFixture {
    public static int unused() { return 42; }
}
''')
    run([javac, '-g', '-d', classes, *sorted(source.glob('*.java'))], root / 'compile.log')
    jar = root / 'production.jar'
    with ZipFile(jar, 'w') as archive:
        for path in sorted(classes.rglob('*.class')):
            archive.write(path, path.relative_to(classes).as_posix())
    environment = {'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(root / 'collections'),
        'FORGE_INTEGRATION_COVERAGE_AGENT': str(args.agent.resolve())}
    collection = coverage.Collection('real-jvm-control', jar, 'native-java', environment=environment)
    for index, branch in enumerate(('a', 'b')):
        with collection.session([java, '-cp', jar, 'ghidradwarfforge.CollectorFixture', branch], branch) as command:
            text = run(command, root / f'java-{index}.log')
            if text.strip() != 'branch=' + branch:
                raise AssertionError('fixture behavioral oracle failed')
    oracle = root / 'oracle.json'
    coverage.save(oracle, {'status': 'PASS_FIXTURE_BRANCHES'})
    collection.finish(oracle)
    python = os.sys.executable
    base_command = [python, '-B', HERE / 'integration-report.py', '--jar', jar,
        '--fixture-report',
        '--collections', root / 'collections', '--java', java, '--jacoco-classpath', args.jacoco_classpath.resolve(),
        '--sources', source.parent, '--commit', 'fixture-only', '--require-suite', 'real-jvm-control']
    run([*base_command, '--output', root / 'report'], root / 'report.log')
    summary = json.loads((root / 'report/summary.json').read_text())
    layer = summary['layers']['native-java']
    if layer['productionClasses'] != 2 or layer['sessions'] != 2:
        raise AssertionError('dropped class population or execution session')
    unused = layer['sources']['ghidradwarfforge/UnloadedFixture.java']['LINE']
    fixture = layer['sources']['ghidradwarfforge/CollectorFixture.java']['BRANCH']
    if unused['covered'] != 0 or unused['missed'] == 0 or fixture != {'covered': 2, 'missed': 0}:
        raise AssertionError('incorrect union or omitted unloaded production lines')

    classpath = args.jacoco_classpath.read_text().strip()
    originals = {row['file']: (collection.root / row['file']).read_bytes() for row in collection.record['sessions']}
    expected = {'wrong-class': 'mismatched', 'foreign': 'unknown or mismatched',
        'extra-session': 'unexpected or combined', 'no-hits': 'no production execution'}
    for kind, diagnostic in expected.items():
        for index, row in enumerate(collection.record['sessions']):
            execution = collection.root / row['file']
            execution.write_bytes(originals[row['file']])
            run([java, '-cp', classpath, HERE / 'IntegrationExecutionControl.java', execution, execution, kind],
                root / f'{kind}-{index}.log')
            row['sha256'] = coverage.digest(execution)
        # Deliberately update receipt hashes: this must fail bytecode/session
        # validation, not merely the earlier file-integrity check.
        collection._save()
        destination = root / ('rejected-' + kind)
        run([*base_command, '--output', destination], root / (kind + '-report.log'), expected=1)
        if diagnostic not in (destination / 'native-java.log').read_text():
            raise AssertionError('negative control failed for the wrong reason: ' + kind)
    for row in collection.record['sessions']:
        execution = collection.root / row['file']
        execution.write_bytes(originals[row['file']])
        row['sha256'] = coverage.digest(execution)
    collection._save()
    group_spec = importlib.util.spec_from_file_location('grouped_execution_control',
        HERE / 'grouped-coverage-execution.py')
    group_control = importlib.util.module_from_spec(group_spec)
    group_spec.loader.exec_module(group_control)
    group_control.prove(root, java, args.agent.resolve(), args.jacoco_classpath.resolve(), run)
    coverage.save(root / 'result.json', {'status': 'PASS_REAL_INTEGRATION_COVERAGE_CONTROLS',
        'sessions': 2, 'productionClasses': 2, 'negativeControls': list(expected),
        'unloadedClassRetained': True, 'branchesMergedByProbeUnion': True,
        'groupedProbeUnion': 'PASS'})
    print('integration-coverage-execution=PASS controls=4')


if __name__ == '__main__':
    main()
