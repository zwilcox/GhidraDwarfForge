#!/usr/bin/env python3
"""Validate actual Script Manager unwind choices with independent compiler/GDB evidence."""
import argparse
import json
import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'compiler-unwind-export.py'))
run, digest, metadata, decode, check_description, comparable, boundaries = (
    helpers[name] for name in ('run', 'digest', 'metadata', 'decode', 'check_description', 'comparable', 'boundaries'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('work', type=Path)
    parser.add_argument('reference', type=Path)
    parser.add_argument('--target', required=True, choices=('x86_64', 'aarch64'))
    parser.add_argument('--dwarfdump', required=True)
    args = parser.parse_args()
    original = args.work / 'readonly/fixture'
    protected = {str(p): digest(p) for p in [original, args.reference]}
    runtime = {'FORGE_CFI_SHARED': os.environ.get('GHIDRA_GUI_UNWIND_SHARED', '0'),
               'FORGE_CFI_DRIVER': os.environ.get('GHIDRA_GUI_UNWIND_DRIVER', '')}
    baseline = boundaries(args.target, args.reference, original, args.work / 'compiler-boundaries', runtime)
    prefix = args.work / 'compiler-return'
    run(['bash', SCRIPTS / 'synthetic-cfi-reference-gdb.sh', args.target, 'compiler', args.reference, original, prefix],
        args.work / 'compiler-return-command.log', runtime)
    returns = json.loads(Path(str(prefix) + '.json').read_text())
    outcomes = []
    for mode in ('off', 'strict', 'conditioned-no-pointers', 'conditioned-fixed'):
        case = args.work / mode
        artifact = case / 'output/fixture.dbg'
        evidence = None if mode == 'off' else json.loads(Path(str(artifact) + '.unwind.json').read_text())
        section = [s for s in metadata(artifact)['sections'] if s['name'] == '.debug_frame']
        if evidence is not None and evidence['hasPlan']:
            frame, = section
            raw = artifact.read_bytes()[frame['offset']:frame['offset'] + frame['size']]
            check_description(Path(str(artifact) + '.unwind.json'), artifact, original, decode(raw, 8, 'little'))
            env = {**runtime, 'FORGE_CFI_FIXED_POINTERS': json.dumps(evidence['stackSeparation']['fixedPointers'])}
            observed = boundaries(args.target, artifact, original, case / 'boundaries', env)
            # Pointer observations are an additional oracle for the fixed mode.
            reference = boundaries(args.target, args.reference, original, case / 'compiler-boundaries', env)
            assert observed == reference
            prefix = case / 'returns'
            run(['bash', SCRIPTS / 'synthetic-cfi-reference-gdb.sh', args.target, 'compiler', artifact, original, prefix],
                case / 'returns-command.log', runtime)
            assert comparable(json.loads(Path(str(prefix) + '.json').read_text())) == comparable(returns)
        else:
            assert not section
        text = run(['readelf', '-h', '-S', '--debug-dump=frames,info,abbrev,aranges,decodedline', artifact], case / 'gnu.log')
        assert 'warning:' not in text.lower() and 'error:' not in text.lower()
        run(['llvm-dwarfdump', '--verify', artifact], case / 'llvm.log')
        run([sys.executable, SCRIPTS / 'check-dwarfdump.py', artifact, case / 'strict.log',
            '--tool', args.dwarfdump, '--original', original], case / 'strict-command.log')
        outcomes.append({'mode': mode, 'sidecarSha256': digest(artifact), 'hasPlan': bool(section)})
    assert protected == {p: digest(Path(p)) for p in protected}
    (args.work / 'unwind-result.json').write_text(json.dumps({'status': 'PASS_GUI_UNWIND', 'cases': outcomes,
        'protectedSha256': protected}, indent=4) + '\n')
    print('gui-unwind-structural-and-gdb=PASS')


if __name__ == '__main__':
    main()
