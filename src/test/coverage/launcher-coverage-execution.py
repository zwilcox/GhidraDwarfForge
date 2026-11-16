#!/usr/bin/env python3
"""Real JVM tests for separate launcher sessions, stdin cancellation and process identity."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('integration_coverage', HERE.parent / 'integration/integration_coverage.py')
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('java-home', 'agent', 'jacoco-classpath', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'posix':
        raise ValueError('this harness tests the Linux launcher contract')
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    java = args.java_home.resolve() / 'bin/java'
    source = root / 'source/ghidradwarfforge'
    source.mkdir(parents=True)
    (source / 'LauncherFixture.java').write_text('''package ghidradwarfforge;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
public final class LauncherFixture {
    public static void main(String[] args) throws Exception {
        if (args[0].equals("preview")) {
            System.out.println("preview=7 " + args[1]);
            return;
        }
        System.out.println("ready=" + ProcessHandle.current().pid());
        System.out.flush();
        if (args[0].equals("wait")) {
            Files.writeString(Path.of(args[1]), "ready");
            Thread.sleep(30000);
            throw new AssertionError("signal never arrived");
        }
        String command = new BufferedReader(new InputStreamReader(System.in)).readLine();
        if (!"cancel".equals(command)) throw new AssertionError("stdin changed");
        System.out.println("cancelled=11 " + args[1]);
        System.exit(130);
    }
}
''')
    (source / 'UnloadedFixture.java').write_text('''package ghidradwarfforge;
public final class UnloadedFixture { public static int unused() { return 42; } }
''')
    classes = root / 'classes'
    classes.mkdir()
    subprocess.run([str(java.with_name('javac')), '-g', '-d', str(classes),
        *map(str, sorted(source.glob('*.java')))], check=True, timeout=45)
    jar = root / 'production.jar'
    with ZipFile(jar, 'w') as archive:
        for path in sorted(classes.rglob('*.class')):
            archive.write(path, path.relative_to(classes).as_posix())
    environment = {'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(root / 'accepted collections'),
        'FORGE_INTEGRATION_COVERAGE_AGENT': str(args.agent.resolve())}
    oracle = root / 'oracle.json'
    coverage.save(oracle, {'status': 'PASS_LAUNCHER_CONTROL'})
    launcher = root / 'launch.sh'
    launcher.write_text('''#!/bin/bash
set -euo pipefail
"$1" -cp "$2" ghidradwarfforge.LauncherFixture preview "$3"
exec "$1" -cp "$2" ghidradwarfforge.LauncherFixture action "$3"
''')
    payload = "spaces λ 'quote' $literal"
    collection = coverage.Collection('launcher-controls', jar, 'native-java', environment=environment)
    with collection.launcher_java(java, 'preview-and-cancel') as wrapper:
        process = subprocess.Popen(['bash', str(launcher), wrapper, str(jar), payload],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate('cancel\n', timeout=30)
            assert process.returncode == 130 and not stderr, (process.returncode, stderr)
            assert stdout.splitlines() == ['preview=7 ' + payload, 'ready=' + str(process.pid), 'cancelled=11 ' + payload]
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
    assert len(collection.record['sessions']) == 2
    marker = root / 'signal-ready'
    with collection.launcher_java(java, 'signal') as wrapper:
        process = subprocess.Popen([wrapper, '-cp', str(jar), 'ghidradwarfforge.LauncherFixture', 'wait', str(marker)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            deadline = time.monotonic() + 15
            while not marker.exists():
                assert process.poll() is None and time.monotonic() < deadline, 'JVM never became ready'
                time.sleep(0.02)
            os.killpg(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode in (143, -signal.SIGTERM) and not stderr
            assert stdout.strip() == 'ready=' + str(process.pid)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
    collection.finish(oracle)
    assert len(coverage.validate_collection(collection.root, jar)['sessions']) == 3
    command = [os.sys.executable, '-B', str(HERE / 'integration-report.py'), '--jar', str(jar),
        '--fixture-report',
        '--collections', environment['FORGE_INTEGRATION_COVERAGE_OUTPUT'], '--output', str(root / 'report'),
        '--java', str(java), '--jacoco-classpath', str(args.jacoco_classpath.resolve()),
        '--sources', str(source.parent), '--commit', 'fixture-only', '--require-suite', 'launcher-controls']
    subprocess.run(command, check=True, timeout=90)
    summary = json.loads((root / 'report/summary.json').read_text())['layers']['native-java']
    assert summary['sessions'] == 3 and summary['productionClasses'] == 2
    assert summary['sources']['ghidradwarfforge/UnloadedFixture.java']['LINE']['covered'] == 0
    assert summary['sources']['ghidradwarfforge/UnloadedFixture.java']['LINE']['missed'] > 0

    rejected = []
    for mutation in ('missing-jvm', 'failed-oracle', 'missing-execution', 'invalid-jvm-option'):
        failure_env = dict(environment, FORGE_INTEGRATION_COVERAGE_OUTPUT=str(root / mutation))
        failed = coverage.Collection('rejected-launcher', jar, 'native-java', environment=failure_env)
        try:
            with failed.launcher_java(java, mutation) as wrapper:
                if mutation != 'missing-jvm':
                    arguments = ['--forge-invalid-option'] if mutation == 'invalid-jvm-option' else [
                        '-cp', str(jar), 'ghidradwarfforge.LauncherFixture', 'preview', payload]
                    observed = subprocess.run([wrapper, *arguments], capture_output=True, text=True, timeout=30)
                    assert observed.returncode == (1 if mutation == 'invalid-jvm-option' else 0)
                    if mutation == 'failed-oracle':
                        raise AssertionError('deliberate behavioral failure')
                    if mutation == 'missing-execution':
                        execution, = failed.root.glob('*.exec')
                        execution.unlink()
            raise AssertionError('invalid launcher measurement accepted')
        except (ValueError, AssertionError) as failure:
            assert str(failure) == 'deliberate behavioral failure' or 'missing or excessive launcher' in str(failure), failure
        try:
            failed.finish(oracle)
            raise AssertionError('failed launcher admitted at finish')
        except ValueError:
            rejected.append(mutation)
    coverage.save(root / 'result.json', {'status': 'PASS_REAL_LAUNCHER_COVERAGE_CONTROLS',
        'sessions': 3, 'productionClasses': 2, 'negativeControls': rejected,
        'stdinCancellationPreserved': True, 'signalAndPidPreserved': True, 'argumentsPreserved': True})
    print('launcher-coverage-execution=PASS controls=4')


if __name__ == '__main__':
    main()
