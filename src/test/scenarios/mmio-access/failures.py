#!/usr/bin/env python3
"""Run installed MMIO cancellation/late-failure controls without saving the project."""
import argparse
import json
import os
from pathlib import Path
import sys

from forge import digest, run, snapshot, REPOSITORY

sys.path.insert(0, str(REPOSITORY / 'src/test/integration'))
from integration_coverage import Collection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra', 'project', 'original', 'sidecar', 'results'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--raw-firmware', action='store_true', help='Use the Cortex-M raw fixture and four-output generation')
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    ghidra, project, original, sidecar = (getattr(args, n).resolve(strict=True)
        for n in ('ghidra', 'project', 'original', 'sidecar'))
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    saved = snapshot(project)
    protected_paths = [original, sidecar, Path(str(sidecar) + '.c'), Path(str(sidecar) + '.mmio.json')]
    if args.raw_firmware:
        protected_paths.append(Path(str(sidecar) + '.firmware.json'))
    protected = {str(p): digest(p) for p in protected_paths}
    # Raw firmware has its own parent collection and acceptance contract.
    # This collection measures the existing ELF MMIO control process only.
    measured = Collection('mmio-failure-controls', module / 'lib/GhidraDwarfForge.jar', 'headless',
        environment={} if args.raw_firmware else os.environ)
    sources = ['src/test/scenarios/mmio-access/' + name for name in ('failures.py', 'forge.py', 'layout.py')]
    sources += ['src/test/integration/integration_coverage.py', 'ghidra_scripts/GhidraDwarfForge.java',
        'src/test/integration/ghidra_scripts/RunMmioControls.java',
        'src/test/integration/ghidra_scripts/CheckMmioFailures.java']
    harnesses = {name: digest(REPOSITORY / name) for name in sources}
    inputs = [*protected_paths, *[p for p in module.rglob('*') if p.is_file()],
        *[REPOSITORY / name for name in sources]]
    before = {str(p): digest(p) for p in inputs}
    host = root / 'host'
    host.mkdir()
    command = [str(ghidra / 'support/analyzeHeadless'), str(host), 'Controls', '-noanalysis',
        '-scriptPath', str(REPOSITORY / 'src/test/integration/ghidra_scripts'),
        '-postScript', 'RunMmioControls.java', str(project), 'CortexM' if args.raw_firmware else 'Mmio', '/' + original.name,
        str(original), str(sidecar), str(module), str(root / 'controls'), *(['raw'] if args.raw_firmware else [])]
    with measured.session(command, 'failure-controls', headless=True) as selected:
        run(selected, root / 'controls.log', timeout=300)
    log = (root / 'controls.log').read_text()
    checks = 22 if args.raw_firmware else 16
    assert 'mmio-failure-controls=PASS checks=' + str(checks) in log and 'REPORT SCRIPT ERROR' not in log, log[-2000:]
    assert snapshot(project) == saved, 'failure controls changed saved project'
    assert all(digest(Path(p)) == value for p, value in protected.items()), 'failure controls changed original generation'
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_MMIO_FAILURE_CONTROLS', 'checks': checks,
        'preservedSha256': protected, 'savedProjectSha256': saved}, indent=4) + '\n')
    after = {name: digest(Path(name)) for name in before}
    assert before == after, 'MMIO controls changed protected harness/module inputs'
    if measured.enabled:
        header = original.read_bytes()[:20]
        assert header[:4] == b'\x7fELF' and header[5] in (1, 2)
        machine = int.from_bytes(header[18:20], 'little' if header[5] == 1 else 'big')
        target = {(2, 1, 62): 'x86_64', (1, 1, 8): 'mips32le', (1, 2, 8): 'mips32be'}[(header[4], header[5], machine)]
        base_export = json.loads((original.parent.parent / 'result.json').read_text())['profiles'][target]
        strict = json.loads((original.parent / 'dwarfdump.log.check.json').read_text())
        assert strict['status'] == 'PASS' and 'No errors.' in (original.parent / 'llvm.log').read_text()
        evidence = {'status': 'PASS_MMIO_FAILURE_MEASUREMENT', 'target': target, 'rawFirmware': False,
            'checks': checks, 'baseExport': base_export, 'strict': strict,
            'harnessSha256': harnesses, 'protectedBefore': before, 'protectedAfter': after,
            'projectBefore': saved, 'projectAfter': snapshot(project),
            'artifactPaths': dict(zip(('input', 'sidecar', 'source', 'profile'), map(str, protected_paths))),
            'logSha256': digest(root / 'controls.log'), 'controls': snapshot(root / 'controls'),
            'scope': 'ELF MMIO cancellation/failure and unchanged validated generation; no device access claim'}
        oracle = root / 'coverage-oracle.json'
        oracle.write_text(json.dumps(evidence, indent=4) + '\n')
        measured.finish(oracle)
    print('mmio-failure-controls=PASS')


if __name__ == '__main__':
    main()
