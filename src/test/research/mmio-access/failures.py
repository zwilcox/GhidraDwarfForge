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
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    ghidra, project, original, sidecar = (getattr(args, n).resolve(strict=True)
        for n in ('ghidra', 'project', 'original', 'sidecar'))
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    saved = snapshot(project)
    protected = {str(p): digest(p) for p in (original, sidecar, Path(str(sidecar) + '.c'), Path(str(sidecar) + '.mmio.json'))}
    host = root / 'host'
    host.mkdir()
    run([str(ghidra / 'support/analyzeHeadless'), str(host), 'Controls', '-noanalysis',
        '-scriptPath', str(REPOSITORY / 'src/test/integration/ghidra_scripts'),
        '-postScript', 'RunMmioControls.java', str(project), 'Mmio', '/' + original.name,
        str(original), str(sidecar), str(module), str(root / 'controls')], root / 'controls.log', timeout=300)
    log = (root / 'controls.log').read_text()
    assert 'mmio-failure-controls=PASS checks=16' in log and 'REPORT SCRIPT ERROR' not in log, log[-2000:]
    assert snapshot(project) == saved, 'failure controls changed saved project'
    assert all(digest(Path(p)) == value for p, value in protected.items()), 'failure controls changed original generation'
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_MMIO_FAILURE_CONTROLS', 'checks': 16,
        'preservedSha256': protected, 'savedProjectSha256': saved}, indent=4) + '\n')
    print('mmio-failure-controls=PASS')


if __name__ == '__main__':
    main()
