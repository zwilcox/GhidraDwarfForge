#!/usr/bin/env python3
"""Independently validate transported PowerShell exports with Linux GDB."""
import argparse
import json
from pathlib import Path
import runpy
import shutil
import sys
import zlib

SCRIPTS = Path(__file__).resolve().parent
helpers = runpy.run_path(str(SCRIPTS / 'compiler-unwind-export.py'))
run, digest, metadata, decode, check_description, boundaries, comparable = (
    helpers[name] for name in ('run', 'digest', 'metadata', 'decode', 'check_description', 'boundaries', 'comparable'))


def snapshot(root):
    return {str(path.relative_to(root)): digest(path) for path in root.rglob('*') if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('incoming', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--producer-host', choices=('Windows', 'Linux'), required=True)
    parser.add_argument('--dwarfdump', required=True)
    args = parser.parse_args()
    incoming = args.incoming.resolve()
    prior = json.loads((incoming / 'result.json').read_text())
    assert prior['status'] == 'PASS_POWERSHELL_UNWIND_EXPORT' and prior['host'] == args.producer_host
    assert prior['packagedNatives']
    before = snapshot(incoming)
    assert prior['originalSha256'] == before['without-cfi'] and prior['referenceSha256'] == before['reference']
    assert all(before[name] == value for name, value in prior['generationSha256'].items())
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    transported = work / 'transported'; shutil.copytree(incoming, transported)
    assert before == snapshot(transported)
    original, reference = transported / 'without-cfi', transported / 'reference'
    original.chmod(0o755)
    runtime = {'FORGE_CFI_SHARED': '0'}
    baseline = boundaries('x86_64', reference, original, work / 'compiler-boundaries', runtime)
    prefix = work / 'compiler-return'
    run(['bash', SCRIPTS / 'synthetic-cfi-reference-gdb.sh', 'x86_64', 'compiler', reference, original, prefix],
        work / 'compiler-return-command.log', runtime)
    returns = json.loads(Path(str(prefix) + '.json').read_text())
    results = []
    for item in prior['artifacts']:
        mode = item['mode']; artifact = transported / (mode + '.dbg')
        assert digest(artifact) == item['sidecarSha256']
        text = run(['readelf', '-h', '-S', '--debug-dump=frames,info,abbrev,aranges,decodedline', artifact], work / (mode + '-gnu.log'))
        assert 'warning:' not in text.lower() and 'error:' not in text.lower()
        run(['llvm-dwarfdump', '--verify', artifact], work / (mode + '-llvm.log'))
        run([sys.executable, SCRIPTS / 'check-dwarfdump.py', artifact, work / (mode + '-strict.log'),
            '--tool', args.dwarfdump, '--original', original], work / (mode + '-strict-command.log'))
        if mode in ('conditioned', 'compressed'):
            frame, = [s for s in metadata(artifact)['sections'] if s['name'] == '.debug_frame']
            raw = artifact.read_bytes()[frame['offset']:frame['offset'] + frame['size']]
            if mode == 'compressed': raw = zlib.decompress(raw[24:])
            check_description(Path(str(artifact) + '.unwind.json'), artifact, original, decode(raw, 8, 'little'))
            assert boundaries('x86_64', artifact, original, work / (mode + '-boundaries'), runtime) == baseline
            prefix = work / (mode + '-return')
            run(['bash', SCRIPTS / 'synthetic-cfi-reference-gdb.sh', 'x86_64', 'compiler', artifact, original, prefix],
                work / (mode + '-return-command.log'), runtime)
            assert comparable(json.loads(Path(str(prefix) + '.json').read_text())) == comparable(returns)
        results.append({'mode': mode, 'sidecarSha256': digest(artifact)})
    assert {item['mode'] for item in results} == {'off', 'strict', 'conditioned', 'compressed'}
    assert before == snapshot(incoming) == snapshot(transported)
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_POWERSHELL_UNWIND_GDB',
        'producerHost': args.producer_host, 'gdbSessions': 6, 'artifacts': results,
        'boundarySnapshots': len(baseline['trace']), 'transportedSha256': before,
        'loaderScope': 'Companion bytes preserved; direct symbol loading after host transfer. No companion relocation claim.'}, indent=4) + '\n')
    print('powershell-unwind-gdb=PASS producer=' + args.producer_host)


if __name__ == '__main__':
    main()
