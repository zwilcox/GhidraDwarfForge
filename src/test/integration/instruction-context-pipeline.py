#!/usr/bin/env python3
"""Exercise packaged instruction reads and native diagnostic source composition."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra', 'fixture', 'results'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    args.results.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='pipeline-', dir=args.results)).resolve()
    print(root, flush=True)
    harness = Path(__file__).resolve().parent
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'phase': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)

    run('instructions', ['python3', harness / 'instruction-context.py', args.ghidra, args.fixture, root])
    case, = root.glob('context-*')
    reader = json.loads((case / 'result.json').read_text())
    assert reader['status'] == 'PASS_PACKAGED_INSTRUCTION_CONTEXT'
    run('source', ['python3', harness / 'source-context.py', args.ghidra, case, root])
    source, = root.glob('source-context-*')
    assert json.loads((source / 'result.json').read_text())['status'] == 'PASS_NATIVE_SOURCE_CONTEXT_COMPONENT'
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_INSTRUCTION_SOURCE_CONTEXT_PIPELINE',
        'language': reader['observations']['language'], 'instructionCase': str(case), 'sourceCase': str(source),
        'scope': 'Native components only; exporter validator/GDB checks run in the annotation pipeline.'}, indent=4) + '\n')
    print('instruction-context-pipeline=PASS')


if __name__ == '__main__':
    main()
