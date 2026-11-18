#!/usr/bin/env python3
"""Measure the existing O32/N32 STORE regression, retaining its complete oracle."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import tempfile

from integration_coverage import Collection, digest


SOURCES = (
    'src/test/integration/mips-truncated-space.py',
    'src/test/integration/mips-truncated-space-export.sh',
    'src/test/integration/mips-truncated-space-check.py',
    'src/test/integration/mips-truncated-space-gdb.py',
    'src/test/integration/dynamic-parameter-storage-check.py',
    'src/test/integration/ghidra_scripts/PrepareMipsTruncatedSpace.java',
    'src/test/integration/qemu-socket.sh',
    'src/test/integration/check-dwarfdump.py',
    'src/test/integration/integration_coverage.py',
    'src/test/coverage/launcher-headless.py',
    'src/test/fixtures/mips-truncated-space.c',
    'src/test/fixtures/mips-truncated-space-start.S',
)


def read(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=('mips32be', 'mips32le'))
    parser.add_argument('--results', type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[3]
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    jar = module / 'lib/GhidraDwarfForge.jar'
    parent = args.results or repository / 'build/test-results/mips-truncated-measured'
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=args.target + '-', dir=parent)).resolve()
    harnesses = {name: digest(repository / name) for name in SOURCES}
    protected = {str(path): digest(path) for path in (jar,
        module / 'ghidra_scripts/GhidraDwarfForge.java',
        module / 'os/linux_x86_64/libdwarf.so.2.3.2',
        module / 'os/linux_x86_64/libdwarfp.so.2.3.2')}
    coverage = Collection('mips-truncated-space', jar, 'headless')
    with ExitStack() as stack:
        environment = dict(os.environ, FORGE_MIPS_TRUNCATED_RESULTS=str(root / 'cases'))
        for abi in ('o32', 'n32'):
            for phase in ('curate', 'inspect'):
                environment['FORGE_MIPS_TRUNCATED_' + abi.upper() + '_' + phase.upper() + '_GHIDRA'] = (
                    stack.enter_context(coverage.launcher_headless(ghidra, abi + '-' + phase)))
        command = ['bash', str(repository / 'src/test/integration/mips-truncated-space-export.sh'),
            str(ghidra), args.target]
        (root / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
        with (root / 'harness.log').open('w') as log:
            subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT,
                check=True, timeout=1200)
        cases = []
        for abi in ('o32', 'n32'):
            case, = (root / 'cases').glob(args.target + '.' + abi + '.*')
            result = read(case / 'result.json')
            assert result['status'] == 'PASS' and result['target'] == args.target and result['abi'] == abi
            assert read(case / 'protected-before.json') == read(case / 'protected-after.json')
            for leaf in ('abi.dbg', 'abi.dbg.c'):
                assert (case / leaf).read_bytes() == (case / ('first.' + leaf)).read_bytes()
            assert 'No errors.' in (case / 'llvm.stdout').read_text()
            assert not (case / 'llvm.stderr').read_bytes()
            strict = result['strict']
            assert strict['status'] == 'PASS' and strict['exit_status'] == 0
            assert strict['reported_errors'] == strict['uncorroborated_errors'] == 0
            gdb = []
            for variant, observation in zip(('compiler', 'forge'), result['gdb']):
                assert observation['status'] == 'PASS' and observation['variant'] == variant
                assert observation['exitCodes'] == [0]
                assert (case / (variant + '.qemu.status')).read_text() == 'exit=0\n'
                assert not (case / (variant + '.qemu.stderr')).read_bytes()
                assert observation == read(case / (variant + '-gdb.json'))
                gdb.append({'variant': variant, 'status': observation['status'],
                    'exitCodes': observation['exitCodes'],
                    'globalsAfterReturn': [row['globalsAfterReturn'] for row in observation['functions']],
                    'observationsSha256': digest(case / (variant + '-gdb.json'))})
            cases.append({'abi': abi, 'resultSha256': digest(case / 'result.json'),
                'inputSha256': digest(case / 'abi.stripped'), 'outputSha256': digest(case / 'abi.dbg'),
                'sourceSha256': digest(case / 'abi.dbg.c'), 'gdb': gdb,
                'validators': ['readelf', 'llvm', 'strict'], 'strictErrors': 0,
                'deterministic': True, 'inputPreserved': True})
        assert harnesses == {name: digest(repository / name) for name in SOURCES}
        assert protected == {name: digest(Path(name)) for name in protected}
        receipt = {'status': 'PASS_MIPS_TRUNCATED_SPACE', 'target': args.target,
            'scope': 'Freestanding ET_EXEC integer STORE contrast only; no broad ABI profile claim',
            'productionJarSha256': digest(jar), 'harnessSha256': harnesses,
            'protected': protected, 'cases': cases}
        (root / 'result.json').write_text(json.dumps(receipt, indent=4) + '\n')
    coverage.finish(root / 'result.json')
    print('measured-mips-truncated-space=PASS ' + str(root), flush=True)


if __name__ == '__main__':
    main()
