#!/usr/bin/env python3
"""Bounded Linux/x86-64 installed-exporter sample, separate from unit coverage."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[3]
SESSION = 'forge-headless-coverage-'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_receipt(output, jar):
    output, jar = Path(output), Path(jar)
    record = json.loads((output / 'receipt.json').read_text())
    if record.get('schema') != 1 or record.get('status') != 'PASS':
        raise ValueError('headless coverage session is incomplete')
    if record.get('productionJarSha256') != digest(jar):
        raise ValueError('installed production classes changed since execution')
    expected = {'headless-0.exec', 'headless-1.exec'}
    if set(record.get('execution', {})) != expected:
        raise ValueError('unexpected recorded coverage sessions')
    if {p.name for p in output.glob('*.exec')} != expected:
        raise ValueError('unrecorded or missing coverage sessions')
    for name, checksum in record['execution'].items():
        if not (output / name).is_file() or digest(output / name) != checksum:
            raise ValueError('execution data changed: ' + name)
    return record


def run_logged(command, output, label, timeout=240):
    with (output / (label + '.log')).open('w') as log:
        subprocess.run([str(item) for item in command], stdout=log,
            stderr=subprocess.STDOUT, check=True, timeout=timeout)
    return (output / (label + '.log')).read_text()


def collect(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError('use a new empty coverage output directory')
    ghidra, agent = args.ghidra.resolve(), args.agent.resolve()
    jar = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    # Ghidra 12.0.3 launch.sh splits its VM argument string on whitespace.
    # JaCoCo additionally separates option values with commas. This test-only
    # launcher refuses ambiguous paths rather than changing a user's install.
    for path in (output, agent, Path(tempfile.gettempdir())):
        if re.search(r'[\s,=]', str(path)):
            raise ValueError('coverage launcher requires paths without whitespace, comma or equals')
    record = {'schema': 1, 'status': 'INCOMPLETE', 'productionJarSha256': digest(jar)}
    receipt = output / 'receipt.json'
    receipt.write_text(json.dumps(record, indent=4) + '\n')
    started = time.monotonic()
    fixture, sidecar = output / 'minimal', output / 'minimal.dbg'
    run_logged(['gcc', '-O0', '-g', '-gdwarf-5', '-fno-pie', '-no-pie',
        ROOT / 'src/test/fixtures/minimal.c', '-o', fixture], output, 'compile')
    run_logged(['strip', '--strip-debug', fixture], output, 'strip')
    original = digest(fixture)
    artifacts = []
    with tempfile.TemporaryDirectory(prefix='forge-coverage-') as temporary:
        for index in range(2):
            execution = output / f'headless-{index}.exec'
            vmargs = ' '.join(['-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2',
                '-Djava.awt.headless=true', '-Djava.io.tmpdir=' + temporary,
                f'-javaagent:{agent}=destfile={execution},append=false,'
                f'includes=ghidradwarfforge.*,sessionid={SESSION}{index}'])
            log = run_logged([ghidra / 'support/launch.sh', 'fg', 'jdk',
                'Ghidra-Headless', '2G', vmargs, 'ghidra.app.util.headless.AnalyzeHeadless',
                temporary, 'coverage', '-deleteProject', '-import', fixture,
                '-analysisTimeoutPerFile', '120', '-scriptPath', ROOT / 'ghidra_scripts',
                '-postScript', 'GhidraDwarfForge.java',
                '--libdwarf=' + str(args.consumer.resolve()),
                '--libdwarfp=' + str(args.producer.resolve()), '--output=' + str(sidecar)],
                output, f'headless-{index}')
            if 'GhidraDwarfForge symbol export PASS' not in log or '"status":"FATAL"' in log:
                raise ValueError('headless exporter did not complete successfully')
            if not execution.is_file() or not 0 < execution.stat().st_size < 16 * 1024 * 1024:
                raise ValueError('missing or excessive execution data')
            if digest(fixture) != original:
                raise ValueError('original executable changed')
            artifacts.append([digest(sidecar), digest(str(sidecar) + '.c')])
    if artifacts[0] != artifacts[1]:
        raise ValueError('repeated installed exports are not deterministic')
    llvm = run_logged([args.llvm, '--verify', sidecar], output, 'llvm')
    if 'No errors.' not in llvm:
        raise ValueError('LLVM did not confirm validation')
    run_logged(['readelf', '-h', '-S', '-n',
        '--debug-dump=info,abbrev,aranges,decodedline', sidecar], output, 'readelf')
    run_logged(['readelf', '-h', '-S', '-n', fixture], output, 'original-identity')
    # The repository parser handles libdwarf's exit-zero error reports too.
    run_logged(['python3', ROOT / 'src/test/integration/check-dwarfdump.py',
        sidecar, output / 'dwarfdump-check.txt', '--tool', args.dwarfdump,
        '--original', fixture], output, 'dwarfdump')
    debugger = run_logged(['gdb', '-nx', '-batch', '-ex', 'set debuginfod enabled off',
        '-ex', 'file ' + str(fixture), '-ex', 'set auto-solib-add off',
        '-ex', 'symbol-file ' + str(sidecar), '-ex', 'break recovered_add', '-ex', 'run',
        '-ex', 'list recovered_add', '-ex', 'ptype recovered_add', '-ex', 'next'],
        output, 'gdb', timeout=40)
    if not all(text in debugger for text in ('Breakpoint 1, recovered_add',
            'type = int (int, int)', 'main () at minimal.dbg.c:')):
        raise ValueError('GDB breakpoint/source/type/next oracle failed')
    if digest(jar) != record['productionJarSha256']:
        raise ValueError('installed classes changed during collection')
    record.update(status='PASS', elapsedSeconds=round(time.monotonic() - started, 3),
        inputSha256=original, artifacts=artifacts,
        execution={f'headless-{i}.exec': digest(output / f'headless-{i}.exec') for i in range(2)},
        scope='Linux x86-64 tiny installed headless sample; Java only; separate from unit coverage')
    receipt.write_text(json.dumps(record, indent=4) + '\n')
    validate_receipt(output, jar)
    print('headless-coverage-collection=PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jar', type=Path)
    parser.add_argument('--ghidra', type=Path)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--consumer', type=Path)
    parser.add_argument('--producer', type=Path)
    parser.add_argument('--llvm', default='llvm-dwarfdump')
    parser.add_argument('--dwarfdump', default='dwarfdump')
    args = parser.parse_args()
    if args.validate:
        if args.jar is None:
            parser.error('--validate requires --jar')
        validate_receipt(args.output, args.jar)
    else:
        if any(getattr(args, name) is None for name in ('ghidra', 'agent', 'consumer', 'producer')):
            parser.error('collection requires --ghidra, --agent, --consumer and --producer')
        collect(args)


if __name__ == '__main__':
    main()
