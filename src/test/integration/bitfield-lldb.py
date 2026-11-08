#!/usr/bin/env python3
"""Compare compiler and production bitfield layouts/values in pinned LLDB."""
import argparse
import hashlib
import json
from pathlib import Path
import lldb_consumer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    parser.add_argument('--target', required=True, choices=('x86_64', 'aarch64'))
    parser.add_argument('--lldb', default='lldb-18')
    args = parser.parse_args()
    case = args.case.resolve()
    original, reference, sidecar = (case / name for name in ('bitfield.stripped', 'bitfield.reference', 'bitfield.dbg'))
    paths = [original, reference, sidecar, Path(str(sidecar) + '.c')]
    protected = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    versions = lldb_consumer.versions(args.lldb, args.target)
    rows = []
    for mode, symbols in [('compiler', reference), ('forge', sidecar)]:
        output = case / ('lldb-' + mode)
        observation = output / 'observations.json'
        before = ['breakpoint set --name inspect_flags --skip-prologue false']
        after = ['script exec(open(' + repr(str(Path(__file__).with_name('bitfield-lldb-observe.py').resolve())) + ').read())',
            'target variable word_value byte_value', 'continue',
            "script assert lldb.process.GetState() == lldb.eStateExited and lldb.process.GetExitStatus() == 0; print('FORGE_LLDB_EXIT_PASS')"]
        transcript = lldb_consumer.run(original, symbols, output, args.lldb, args.target, before, after,
            {'FORGE_LLDB_OBSERVATION': str(observation)})
        assert 'FORGE_LLDB_BITFIELDS_PASS' in transcript and 'FORGE_LLDB_EXIT_PASS' in transcript
        rows.append({'mode': mode, 'observations': json.loads(observation.read_text())})
    assert rows[0]['observations'] == rows[1]['observations'] and len(rows[0]['observations']) == 2
    assert protected == {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in protected}
    (case / 'lldb-result.json').write_text(json.dumps({'status': 'PASS_LLDB_BITFIELDS',
        'target': args.target, 'versions': versions, 'cases': rows, 'protectedSha256': protected}, indent=4) + '\n')
    print('lldb-bitfields=PASS ' + args.target)


if __name__ == '__main__':
    main()
