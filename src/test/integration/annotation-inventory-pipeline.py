#!/usr/bin/env python3
"""Build, curate and independently reopen the packaged annotation inventory fixture."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=['x86_64', 'aarch64', 'mips32be', 'mips32le'])
    parser.add_argument('--results', type=Path)
    parser.add_argument('--consumer', type=Path)
    parser.add_argument('--producer', type=Path)
    args = parser.parse_args()
    if bool(args.consumer) != bool(args.producer):
        parser.error('--consumer and --producer must be supplied together')
    harness = Path(__file__).resolve().parent
    parent = (args.results or harness.parents[2] / 'build/test-results/annotation-inventory').resolve()
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=args.target + '-', dir=parent))
    print('annotation-inventory-pipeline-results=' + str(root), flush=True)
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=900)

    role = 'pie' if args.target == 'aarch64' else 'exec'
    run('reference', ['python3', harness / 'analyst-annotations-reference.py', args.target,
        '--role', role, '--results', root])
    case, = root.glob(args.target + '-' + role + '-*')
    run('prepare', ['python3', harness / 'analyst-annotations-prepare.py', args.ghidra, case])
    curation, = case.glob('curation-*')
    run('inventory', ['python3', harness / 'annotation-inventory.py', args.ghidra, curation])
    inventory, = curation.glob('inventory-*')
    result = json.loads((inventory / 'result.json').read_text())
    assert result['status'] == 'PASS_PACKAGED_ANNOTATION_INVENTORY'
    placement = None
    default_export = None
    if args.consumer:
        run('placement', ['python3', harness / 'annotation-placement.py', args.ghidra, curation,
            args.consumer.resolve(strict=True), args.producer.resolve(strict=True)])
        placement, = curation.glob('placement-*')
        assert json.loads((placement / 'result.json').read_text())['status'] == 'PASS_SAVED_COMMENT_PLACEMENT'
        run('default-export', ['python3', harness / 'annotation-default-export.py', args.ghidra, curation,
            args.consumer.resolve(strict=True), args.producer.resolve(strict=True),
            '--placement-control', placement])
        default_export, = curation.glob('default-export-*')
        assert json.loads((default_export / 'result.json').read_text())['status'] == 'PASS_INSTALLED_DEFAULT_COMMENTS'
    (root / 'result.json').write_text(json.dumps({'status': result['status'], 'target': args.target,
        'role': role, 'case': str(case), 'curation': str(curation), 'inventory': str(inventory),
        'placement': str(placement) if placement else None,
        'defaultExport': str(default_export) if default_export else None}, indent=4) + '\n')
    print('annotation-inventory-pipeline=PASS ' + args.target + ' ' + role)


if __name__ == '__main__':
    main()
