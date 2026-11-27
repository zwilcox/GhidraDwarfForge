#!/usr/bin/env python3
"""Isolated packaged producer: class specifications, failed source and alias collisions."""
import argparse
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from integration_coverage import Collection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--module', type=Path, help='Explicit packaged extension; defaults to the Ghidra installation')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    root = Path(__file__).resolve().parents[3]
    harness = root / 'src/test/integration'
    parent = root / 'build/test-results/class-scope-native'
    parent.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(dir=parent))
    print('class-scope-native-results=' + str(case), flush=True)
    commands = []

    def run(label, command, collection=None):
        command = list(map(str, command))
        with collection.session(command, label) if collection else nullcontext(command) as measured:
            commands.append({'label': label, 'argv': command, 'executedCommand': measured})
            (case / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
            result = subprocess.run(measured, text=True, capture_output=True, timeout=120)
            (case / (label + '.log')).write_text(result.stdout)
            (case / (label + '.stderr')).write_text(result.stderr)
            assert result.returncode == 0, (label, result.returncode, result.stderr)
            assert not result.stderr, (label, result.stderr)
            return result.stdout

    source = case / 'input.c'
    source.write_text('int scope_fixture(int value) { volatile int saved = value; return saved + 1; }\n'
        'int main(void) { return scope_fixture(1) != 2; }\n')
    original = case / 'input'
    run('compile', ['gcc', '-O0', '-g', '-gdwarf-5', '-fno-pie', '-no-pie', source, '-o', original])
    original_hash = hashlib.sha256(original.read_bytes()).hexdigest()
    symbols = run('symbols', ['nm', '-S', original])
    address, size, _, _ = next(line.split() for line in symbols.splitlines() if line.endswith(' scope_fixture'))
    assert int(size, 16) > 2
    module = (args.module or ghidra / 'Ghidra/Extensions/GhidraDwarfForge').resolve(strict=True)
    jar = module / 'lib/GhidraDwarfForge.jar'
    coverage = Collection('class-scopes', jar, 'native-java',
        test_classes=('ghidradwarfforge.nativeapi.ClassScopeSmoke',))
    native = module / 'os/linux_x86_64'
    classes = case / 'classes'
    classes.mkdir()
    classpath = os.pathsep.join(map(str, [jar, classes,
        *sorted(p for p in ghidra.rglob('*.jar') if 'Extensions' not in p.parts)]))
    test = root / 'src/test/java/ghidradwarfforge/nativeapi/ClassScopeSmoke.java'
    run('javac', ['javac', '--release', '25', '-proc:none', '-cp', classpath, '-d', classes, test])
    output = case / 'class.dbg'
    run('producer', ['java', '--enable-native-access=ALL-UNNAMED', '-cp', classpath,
        'ghidradwarfforge.nativeapi.ClassScopeSmoke', native / 'libdwarf.so.2.3.2',
        native / 'libdwarfp.so.2.3.2', original, output, '0x' + address, '0x' + size], coverage)
    artifacts = []
    for variant in ['normal', 'failed', 'collision', 'ambiguous', 'unbound-collision']:
        artifact = output if variant == 'normal' else Path(str(output) + '.' + variant)
        for view in ['info', 'abbrev', 'aranges', 'decodedline']:
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        run(variant + '-strict', ['python3', harness / 'check-dwarfdump.py', artifact,
            case / (variant + '-dwarfdump.log'), '--original', original])
        options = ['--failed'] if variant == 'failed' else ['--variant', variant]
        run(variant + '-references', ['python3', harness / 'check-class-scopes.py',
            case / (variant + '-info.log'), '--isolated', *options])
        if variant != 'failed':
            run(variant + '-lookup', ['python3', harness / 'check-class-first-lookup.py',
                original, artifact, '--isolated', '--variant', variant])
        artifacts.append({'variant': variant, 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()})
    assert hashlib.sha256(original.read_bytes()).hexdigest() == original_hash, 'original executable changed'
    acceptance = case / 'acceptance.json'
    acceptance.write_text(json.dumps({'status': 'CLASS_SCOPE_NATIVE_PASS', 'originalSha256': original_hash,
        'jarSha256': hashlib.sha256(jar.read_bytes()).hexdigest(), 'artifacts': artifacts}, indent=4) + '\n')
    oracle = case / 'coverage-oracle.json'
    oracle.write_text(json.dumps({'status': 'PASS_CLASS_SCOPE_NATIVE',
        'acceptanceSha256': hashlib.sha256(acceptance.read_bytes()).hexdigest(),
        'acceptance': json.loads(acceptance.read_text())}, indent=4) + '\n')
    coverage.finish(oracle)
    print('class-scope-native=PASS', flush=True)


if __name__ == '__main__':
    main()
