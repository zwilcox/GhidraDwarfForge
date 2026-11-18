#!/usr/bin/env python3
"""Require behavioral assertions for two selected native location faults."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


MUTANTS = (
    ('missing-stable-relocation',
        'if (operation instanceof AddressOperation address) expected.add(address.address());',
        '// Omit the stable memory relocation from the expected set.',
        'valid fixture memory location was rejected'),
    ('missing-width-refusal',
        'if (addressBytes < Long.BYTES && address.address() >>> (addressBytes * Byte.SIZE) != 0)',
        'if (false)', 'oversized location reached native relocation validation'),
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'output', 'java-home', 'ghidra'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    baseline = args.baseline.resolve(strict=True)
    evidence = json.loads((baseline / 'result.json').read_text())
    assert evidence['status'] == 'PASS_LOCATION_WIDTH_PRODUCER'
    assert evidence['target'] in ('mips32be', 'mips32le', 'arm32') and evidence['mode'] == 'stable'
    assert all(digest(path) == expected for path, expected in evidence['protectedSha256'].items())
    command, = [row['command'] for row in json.loads((baseline / 'commands.json').read_text())
        if row['label'] == 'producer' and row['exit'] == 0]
    command = [part for part in command if not part.startswith('-javaagent:')]
    cp_index = command.index('-cp') + 1
    main_index = command.index('ghidradwarfforge.nativeapi.LocationWidthProducerProbe')
    assert len(command) == main_index + 10
    classpath = command[cp_index]
    source = Path(__file__).resolve().parents[3] / 'src/main/java/ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter.java'
    original = source.read_text()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    outcomes = []
    for label, before, after, expected in (('baseline', '', '', None), *MUTANTS):
        assert not before or original.count(before) == 1
        with tempfile.TemporaryDirectory(prefix=label + '-', dir=output) as temp:
            root = Path(temp)
            changed = root / 'MinimalDwarfSidecarExporter.java'
            changed.write_text(original.replace(before, after) if before else original)
            classes = root / 'classes'
            artifacts = root / 'artifacts'
            artifacts.mkdir()
            compile_path = os.pathsep.join([classpath,
                *map(str, sorted(args.ghidra.resolve().glob('Ghidra/**/lib/*.jar')))])
            compiled = subprocess.run([str(args.java_home.resolve() / 'bin/javac'), '-proc:none',
                '-Xlint:all,-serial,-path', '-Werror', '-cp', compile_path, '-d', str(classes), str(changed)],
                capture_output=True, text=True, timeout=60)
            (output / (label + '-compile.log')).write_text(compiled.stdout + compiled.stderr)
            assert compiled.returncode == 0, 'compilation failure is not mutation detection'
            selected = list(command)
            selected[cp_index] = str(classes) + os.pathsep + classpath
            selected[main_index + 4] = str(artifacts / 'input.dbg')
            executed = subprocess.run(selected, capture_output=True, text=True, timeout=60)
            (output / (label + '-producer.log')).write_text(executed.stdout + executed.stderr)
            if expected is None:
                assert executed.returncode == 0 and 'location-width-producer=PASS' in executed.stdout
            else:
                assert executed.returncode == 1
                assert 'java.lang.AssertionError: ' + expected in executed.stderr
                assert 'Caused by: java.lang.IllegalStateException: producer address relocations do not match' in executed.stderr
            outcomes.append({'name': label, 'status': 'BASELINE_PASS' if expected is None else 'DETECTED',
                'assertion': expected, 'command': selected, 'exit': executed.returncode})
    assert source.read_text() == original
    assert all(digest(path) == expected for path, expected in evidence['protectedSha256'].items())
    result = {'status': 'PASS', 'mutantsDetected': 2, 'coverageCollected': False,
        'productionSourceSha256': digest(source), 'baselineResultSha256': digest(baseline / 'result.json'),
        'results': outcomes, 'scope': 'Two specific native location faults, not a repository mutation score'}
    (output / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print('location-width-mutations=PASS faults=2')


if __name__ == '__main__':
    main()
