#!/usr/bin/env python3
"""Measure the existing packed-bitfield exporter and debugger oracle."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import tempfile

from integration_coverage import Collection, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('targets', nargs='*', choices=('x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le'))
    parser.add_argument('--results', type=Path)
    args = parser.parse_args()
    harness = Path(__file__).resolve().parent
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    jar = module / 'lib/GhidraDwarfForge.jar'
    parent = args.results or harness.parents[2] / 'build/test-results/bitfield-measured'
    parent.mkdir(parents=True, exist_ok=True)
    for target in args.targets or ('x86_64', 'mips32be'):
        root = Path(tempfile.mkdtemp(prefix=target + '-', dir=parent)).resolve()
        protected = {str(path): digest(path) for path in (jar,
            module / 'ghidra_scripts/GhidraDwarfForge.java', Path(__file__),
            harness / 'bitfield-values-export.sh', harness / 'ghidra_scripts/ApplyBitFieldFixture.java',
            harness.parent / 'fixtures/bitfield-values.c')}
        coverage = Collection('bitfield-values', jar, 'headless')
        with ExitStack() as stack:
            first = stack.enter_context(coverage.launcher_headless(ghidra, 'export'))
            repeat = stack.enter_context(coverage.launcher_headless(ghidra, 'repeat'))
            command = ['bash', str(harness / 'bitfield-values-export.sh'), first, target]
            (root / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
            environment = dict(os.environ, FORGE_BITFIELD_RESULTS=str(root / 'cases'),
                FORGE_BITFIELD_REPEAT_GHIDRA=repeat)
            with (root / 'harness.log').open('w') as log:
                subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT,
                    check=True, timeout=900)
            assert 'bitfield-values-' + target + '=PASS' in (root / 'harness.log').read_text()
            case, = (root / 'cases').glob('run.*/' + target)
            original, sidecar, source = [case / name for name in
                ('bitfield.stripped', 'bitfield.dbg', 'bitfield.dbg.c')]
            assert digest(original) == (case / 'input.sha256').read_text().split()[0]
            assert sidecar.read_bytes() == (case / 'first.dbg').read_bytes()
            assert source.read_bytes() == (case / 'first.dbg.c').read_bytes()
            observations = []
            for name in ('compiler-gdb.txt', 'forge-gdb.txt'):
                log = (case / name).read_text()
                values = [line for line in log.splitlines() if line.startswith(('word={', 'byte={'))]
                assert values == ['word={a=5,b=17}', 'byte={a=5,b=17}']
                assert '$1 = 4' in log and '$2 = 1' in log and 'exited normally' in log
                observations.append({'values': values, 'logSha256': digest(case / name), 'exit': 'normal'})
            strict = json.loads((case / 'dwarfdump.txt.check.json').read_text())
            assert strict['status'] == 'PASS' and strict['uncorroborated_errors'] == 0
            lldb = None
            if os.environ.get('FORGE_LLDB'):
                lldb = json.loads((case / 'lldb-result.json').read_text())
                assert lldb['status'] == 'PASS_LLDB_BITFIELDS' and lldb['target'] == target
            assert protected == {path: digest(Path(path)) for path in protected}
            receipt = {'status': 'PASS_MEASURED_BITFIELDS', 'target': target,
                'protected': protected, 'inputSha256': digest(original),
                'artifactSha256': digest(sidecar), 'sourceSha256': digest(source),
                'deterministic': True, 'gdb': observations, 'lldb': lldb,
                'strictUncorroboratedErrors': strict['uncorroborated_errors']}
            (root / 'result.json').write_text(json.dumps(receipt, indent=4) + '\n')
        coverage.finish(root / 'result.json')
        print('measured-bitfields=PASS ' + target + ' ' + str(root), flush=True)


if __name__ == '__main__':
    main()
