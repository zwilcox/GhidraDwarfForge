#!/usr/bin/env python3
"""Check split-value storage transitions with independent LLDB/GDB consumers."""
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
    original, reference, sidecar = (case / name for name in ('local.input', 'local.reference', 'local.dbg'))
    names = ['local.input', 'local.reference', 'local.dbg', 'local.dbg.c', 'labels.json',
        'compiler-gdb.json', 'forge-gdb.json', 'compiler-storage.json', 'locations.json', 'result.json']
    protected = {name: hashlib.sha256((case / name).read_bytes()).hexdigest() for name in names}
    assert json.loads((case / 'result.json').read_text())['status'] == 'PASS'
    versions = lldb_consumer.versions(args.lldb, args.target)
    rows = []
    for mode, symbols in [('compiler', reference), ('forge', sidecar)]:
        output = case / ('lldb-flow-' + mode)
        observation = output / 'observations.json'
        config = {'case': str(case), 'mode': mode, 'target': args.target, 'observations': str(observation)}
        config_path = case / ('lldb-flow-' + mode + '.json')
        config_path.write_text(json.dumps(config, indent=4) + '\n')
        before = ['breakpoint set --name pieces_registers --skip-prologue false --one-shot true']
        after = ['script exec(open(' + repr(str(Path(__file__).with_name('composite-value-flow-lldb-observe.py').resolve())) + ').read())']
        transcript = lldb_consumer.run(original, symbols, output, args.lldb, args.target, before, after,
            {'FORGE_LLDB_FLOW_CONFIG': str(config_path)})
        assert 'FORGE_LLDB_FLOW_PASS' in transcript
        points = json.loads(observation.read_text())
        rows.append({'mode': mode, 'points': len(points),
            'available': sum(point.get('available', False) for point in points),
            'unavailable': sum('unavailable' in point for point in points)})
    assert rows[0]['points'] == rows[1]['points'] > 500
    assert rows[1]['available'] > 0 and rows[1]['unavailable'] > 0
    assert protected == {name: hashlib.sha256((case / name).read_bytes()).hexdigest() for name in names}
    (case / 'lldb-flow-result.json').write_text(json.dumps({'status': 'PASS_LLDB_FLOW',
        'target': args.target, 'versions': versions, 'cases': rows, 'protectedSha256': protected}, indent=4) + '\n')
    print('lldb-composite-value-flow=PASS ' + args.target)


if __name__ == '__main__':
    main()
