#!/usr/bin/env python3
"""Real JVM controls for probe union, separate layers and invalid execution rejection."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent


def run(command, log, *, expected=0):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=120)
    text = result.stdout + result.stderr
    log.write_text(text)
    if result.returncode != expected:
        raise AssertionError(f'expected exit {expected}, got {result.returncode}: {log}\n{text[-3000:]}')
    return text


def package(directory, path):
    with ZipFile(path, 'w') as archive:
        for source in sorted(directory.rglob('*.class')):
            archive.write(source, source.relative_to(directory).as_posix())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('java-home', 'agent', 'jacoco-classpath', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    java = args.java_home.resolve() / ('bin/java.exe' if os.name == 'nt' else 'bin/java')
    javac = java.with_name('javac.exe' if os.name == 'nt' else 'javac')
    source = root / 'source/ghidradwarfforge'
    source.mkdir(parents=True)
    (source / 'Branch.java').write_text('''package ghidradwarfforge;
public final class Branch {
    public static int select(boolean first) {
        if (first) return 7;
        return 11;
    }
}
''')
    (source / 'Unloaded.java').write_text('''package ghidradwarfforge;
public final class Unloaded {
    public static int unused() { return 42; }
}
''')
    (source / 'Harness.java').write_text('''package ghidradwarfforge;
public final class Harness {
    public static void main(String[] args) {
        boolean first = args[0].equals("first");
        int result = Branch.select(first);
        if (result != (first ? 7 : 11)) throw new AssertionError("incorrect branch value");
        System.out.println(result);
    }
}
''')
    production, tests = root / 'production', root / 'tests'
    production.mkdir()
    tests.mkdir()
    run([javac, '-g', '-d', production, source / 'Branch.java', source / 'Unloaded.java'], root / 'compile.log')
    run([javac, '-g', '-cp', production, '-d', tests, source / 'Harness.java'], root / 'compile-test.log')
    jar, test_jar = root / 'production.jar', root / 'tests.jar'
    package(production, jar)
    package(tests, test_jar)
    executions = []
    for index, (layer, branch) in enumerate((('javaexec', 'first'), ('native-java', 'second'))):
        session = ('forge-javaexec-' if layer == 'javaexec' else 'forge-integration-') + str(index) * 32
        execution = root / (session + '.exec')
        option = (f'-javaagent:{args.agent.resolve()}=destfile={execution},append=false,'
            f'includes=ghidradwarfforge.*,sessionid={session}' +
            (',excludes=ghidradwarfforge.Harness' if layer == 'native-java' else ''))
        result = run([java, option, '-cp', os.pathsep.join(map(str, (jar, test_jar))),
            'ghidradwarfforge.Harness', branch], root / f'jvm-{index}.log')
        if result.strip() != ('7' if index == 0 else '11'):
            raise AssertionError('real JVM behavior did not match the fixture oracle')
        executions.append((layer, session, execution))
    classpath = args.jacoco_classpath.read_text().strip()

    def report(name, rows, *, jar_override=None, test_override=None, rejection=None):
        manifest = root / (name + '.tsv')
        manifest.write_text(''.join('\t'.join(map(str, row)) + '\n' for row in rows))
        command = [java, '-cp', classpath, HERE / 'ReportCombinedCoverage.java',
            jar_override or jar, test_override or test_jar, manifest, source.parent, root / name]
        text = run(command, root / (name + '.log'), expected=1 if rejection else 0)
        if rejection and rejection not in text:
            raise AssertionError('control failed for the wrong reason: ' + name)

    report('valid', executions)
    for layer, covered, missed in (('javaexec', 1, 1), ('native-java', 1, 1), ('combined', 2, 0)):
        document = ET.parse(root / 'valid' / (layer + '.xml')).getroot()
        names = {node.get('name') for node in document.findall('./package/class')}
        if names != {'ghidradwarfforge/Branch', 'ghidradwarfforge/Unloaded'}:
            raise AssertionError('production population changed or test class entered the denominator')
        branch = document.find(".//sourcefile[@name='Branch.java']/counter[@type='BRANCH']")
        if (int(branch.get('covered')), int(branch.get('missed'))) != (covered, missed):
            raise AssertionError('incorrect union or leaked probe hits between layers: ' + layer)
        unloaded = document.find(".//sourcefile[@name='Unloaded.java']/counter[@type='LINE']")
        if int(unloaded.get('covered')) != 0 or int(unloaded.get('missed')) == 0:
            raise AssertionError('unloaded production source was dropped')

    # Bind a real source diff to the actual JaCoCo line rows above. One decision
    # changed on line 4: one execution must fail the branch gate, the union pass.
    repository = root / 'changed-code-fixture'
    changed_source = repository / 'src/main/java/ghidradwarfforge/Branch.java'
    changed_source.parent.mkdir(parents=True)
    original = (source / 'Branch.java').read_text()
    changed_source.write_text(original.replace('return 7', 'return 3'))

    def git(*arguments):
        return subprocess.check_output(['git', '-c', 'user.name=Coverage fixture',
            '-c', 'user.email=coverage@example.invalid', '-c', 'commit.gpgsign=false',
            '-c', 'core.hooksPath=' + str(repository / 'absent-hooks'), *arguments],
            cwd=repository, text=True).strip()

    git('init', '-q', '--initial-branch=fixture')
    git('add', 'src')
    git('commit', '-qm', 'Before decision change')
    base = git('rev-parse', 'HEAD')
    changed_source.write_text(original)
    git('add', 'src')
    git('commit', '-qm', 'Changed decision')
    commit = git('rev-parse', 'HEAD')
    specification = importlib.util.spec_from_file_location('changed_code', HERE / 'changed-code.py')
    changed = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(changed)
    for layer, accepted in (('javaexec', False), ('native-java', False), ('combined', True)):
        measurement = changed.report(repository, base, commit, root / 'valid' / (layer + '.xml'), changed.TARGETS)
        if (measurement['targetsMet'] != accepted
                or measurement['files']['ghidradwarfforge/Branch.java']['executableLines'] != [4]):
            raise AssertionError('changed-code gate did not match actual decision execution: ' + layer)
        (root / ('changed-' + layer + '.json')).write_text(json.dumps(measurement, indent=4) + '\n')

    controls = {'wrong-class': 'unknown or mismatched class', 'foreign': 'unknown or mismatched class',
        'extra-session': 'unexpected or combined coverage sessions', 'no-hits': 'no production execution',
        'short-probes': 'wrong probe count', 'long-probes': 'wrong probe count'}
    for kind, rejection in controls.items():
        rows = []
        for index, (layer, session, execution) in enumerate(executions):
            altered = root / f'{kind}-{index}.exec'
            run([java, '-cp', classpath, HERE / 'IntegrationExecutionControl.java', execution, altered, kind],
                root / f'{kind}-{index}.log')
            rows.append((layer, session, altered))
        report('reject-' + kind, rows, rejection=rejection)
    report('reject-duplicate', [*executions, executions[0]], rejection='duplicate coverage session')
    report('reject-session-id', [('javaexec', 'forge-javaexec-' + 'f' * 32, executions[0][2]), executions[1]],
        rejection='unexpected or combined coverage sessions')
    collision = root / 'colliding-tests.jar'
    with ZipFile(collision, 'w') as archive:
        archive.write(production / 'ghidradwarfforge/Branch.class', 'ghidradwarfforge/Branch.class')
        archive.write(tests / 'ghidradwarfforge/Harness.class', 'ghidradwarfforge/Harness.class')
    report('reject-test-collision', executions, test_override=collision, rejection='populations overlap')
    renamed = root / 'renamed-class.jar'
    with ZipFile(renamed, 'w') as archive:
        archive.write(production / 'ghidradwarfforge/Branch.class', 'ghidradwarfforge/Disguised.class')
        archive.write(production / 'ghidradwarfforge/Unloaded.class', 'ghidradwarfforge/Unloaded.class')
    report('reject-renamed-class', executions, jar_override=renamed, rejection='class name differs from JAR member')
    # A real integration-labelled execution containing a test helper must fail,
    # even though that helper's exact identity is known for JavaExec sessions.
    session = 'forge-integration-' + 'e' * 32
    leaked = root / 'test-helper-leak.exec'
    option = (f'-javaagent:{args.agent.resolve()}=destfile={leaked},append=false,'
        f'includes=ghidradwarfforge.*,sessionid={session}')
    run([java, option, '-cp', os.pathsep.join(map(str, (jar, test_jar))),
        'ghidradwarfforge.Harness', 'second'], root / 'test-helper-leak-jvm.log')
    report('reject-test-leak', [executions[0], ('native-java', session, leaked)],
        rejection='unknown or mismatched class: ghidradwarfforge/Harness')
    result = {'status': 'PASS_REAL_COMBINED_COVERAGE_CONTROLS', 'productionClasses': 2,
        'testClasses': 1, 'layers': 2, 'sessions': 2, 'negativeControls': [*controls,
            'duplicate', 'session-id', 'test-collision', 'renamed-class', 'test-leak'],
        'unloadedClassRetained': True, 'testClassesExcluded': True,
        'oppositeBranchesCombined': True, 'separateLayersUnchanged': True,
        'changedDecisionGate': True}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
