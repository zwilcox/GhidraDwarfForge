#!/usr/bin/env python3
"""Run installed MMIO cancellation/late-failure controls without saving the project."""
import argparse
import json
from pathlib import Path

from forge import digest, run, snapshot, REPOSITORY


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
    host = root / 'host'
    host.mkdir()
    run([str(ghidra / 'support/analyzeHeadless'), str(host), 'Controls', '-noanalysis',
        '-scriptPath', str(REPOSITORY / 'src/test/integration/ghidra_scripts'),
        '-postScript', 'RunMmioControls.java', str(project), 'CortexM' if args.raw_firmware else 'Mmio', '/' + original.name,
        str(original), str(sidecar), str(module), str(root / 'controls'), *(['raw'] if args.raw_firmware else [])],
        root / 'controls.log', timeout=300)
    log = (root / 'controls.log').read_text()
    checks = 22 if args.raw_firmware else 16
    assert 'mmio-failure-controls=PASS checks=' + str(checks) in log and 'REPORT SCRIPT ERROR' not in log, log[-2000:]
    assert snapshot(project) == saved, 'failure controls changed saved project'
    assert all(digest(Path(p)) == value for p, value in protected.items()), 'failure controls changed original generation'
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_MMIO_FAILURE_CONTROLS', 'checks': checks,
        'preservedSha256': protected, 'savedProjectSha256': saved}, indent=4) + '\n')
    print('mmio-failure-controls=PASS')


if __name__ == '__main__':
    main()
