#!/usr/bin/env python3
"""Run the compiler reference and installed Cortex-M exporter acceptance harness."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(label, arguments, marker):
        argv = [sys.executable, *map(str, arguments)]
        commands.append({'label': label, 'argv': argv})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as output:
            subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, check=True, timeout=900)
        if marker is None:
            return None
        selected, = [line.removeprefix(marker) for line in (root / (label + '.log')).read_text().splitlines()
            if line.startswith(marker)]
        return Path(selected)

    case = run('reference', [HERE / 'cortex-m-reference.py', '--results', root / 'reference'],
        'cortex-m-reference-results=')
    exported = run('export', [HERE / 'cortex-m-export.py', case, '--ghidra', args.ghidra],
        'cortex-m-export-results=')
    result = json.loads((exported / 'result.json').read_text())
    assert result['status'] == 'PASS_CURATED_CORTEX_EXPORT_RUNTIME'
    run('controls', [HERE / 'cortex-m-controls.py', case, exported / 'firmware.dbg', root / 'controls'], None)
    controls = json.loads((root / 'controls/result.json').read_text())
    assert controls['status'] == 'PASS' and len(controls['controls']) == 6
    raw_cases = {}
    shifted = run('shifted-ram-reference', [HERE / 'cortex-m-reference.py',
        '--results', root / 'shifted-reference', '--ram-origin', '0x20001000'],
        'cortex-m-reference-results=')
    for label, reference in (('base', case), ('shifted-ram', shifted)):
        raw = root / ('raw-' + label)
        run('raw-' + label, [HERE / 'raw-firmware-export.py', '--case', reference,
            '--ghidra', args.ghidra, '--results', raw,
            *(['--separate-ram-input'] if label == 'shifted-ram' else [])], None)
        raw_result = json.loads((raw / 'result.json').read_text())
        assert raw_result['status'] == 'PASS_RAW_FIRMWARE_EXPORT_RUNTIME'
        assert raw_result['failureControls'] == (21 if label == 'shifted-ram' else 20)
        assert raw_result['addresses']['functions'] == 8
        raw_cases[label] = raw_result
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'reference': str(case),
        'export': str(exported), 'checks': result, 'controls': controls, 'rawFirmware': raw_cases}, indent=4) + '\n')
    print('cortex-m-suite=PASS ' + str(root))


if __name__ == '__main__':
    main()
