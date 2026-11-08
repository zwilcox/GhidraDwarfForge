#!/usr/bin/env python3
"""Compare full AArch64 vector lifetimes with compiler and GDB observations."""
import argparse
import hashlib
import json
from pathlib import Path
import lldb_consumer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--lldb', default='lldb-18')
    parser.add_argument('--check-sve-limitation', action='store_true',
        help='also require the pinned LLDB/QEMU default-SVE missing-Neon failure in both producers')
    args = parser.parse_args()
    case, root = args.case.resolve(), args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    names = ['abi.input', 'abi.reference', 'abi.dbg', 'abi.dbg.c', 'metadata.json',
        'vector-locations.json', 'compiler-observations.json', 'forge-observations.json',
        'compiler-returns.json', 'forge-returns.json']
    protected = {name: hashlib.sha256((case / name).read_bytes()).hexdigest() for name in names}
    assert json.loads((case / 'result.json').read_text())['status'] == 'PASS'
    metadata = json.loads((case / 'metadata.json').read_text())
    assert metadata['qemuCpu'] == 'cortex-a53'
    versions = lldb_consumer.versions(args.lldb, 'aarch64')
    results = []
    controls = []
    if args.check_sve_limitation:
        for mode in ('compiler', 'forge'):
            output = root / ('sve-control-' + mode)
            config = root / ('sve-control-' + mode + '.json')
            config.write_text(json.dumps({'case': str(case), 'mode': mode, 'transportControl': True,
                'observations': str(output / 'observations.json')}, indent=4) + '\n')
            transcript = lldb_consumer.run(case / 'abi.input',
                case / ('abi.reference' if mode == 'compiler' else 'abi.dbg'), output,
                args.lldb, 'aarch64',
                ['breakpoint set --name vector_plain --skip-prologue false --one-shot true'],
                ['script exec(open(' + repr(str(Path(__file__).with_name('aarch64-vector-lldb-observe.py').resolve())) + ').read())'],
                {'FORGE_LLDB_VECTOR_CONFIG': str(config)})
            assert 'FORGE_LLDB_VECTOR_TRANSPORT_CONTROL_PASS' in transcript
            controls.append({'mode': mode, 'observations': json.loads((output / 'observations.json').read_text())})
    for mode in ('compiler', 'forge'):
        output = root / mode
        config = root / (mode + '.json')
        config.write_text(json.dumps({'case': str(case), 'mode': mode,
            'observations': str(output / 'observations.json')}, indent=4) + '\n')
        before = ['breakpoint set --name ' + name + ' --skip-prologue false --one-shot true'
            for name in metadata['symbols']]
        after = ['script exec(open(' + repr(str(Path(__file__).with_name('aarch64-vector-lldb-observe.py').resolve())) + ').read())']
        transcript = lldb_consumer.run(case / 'abi.input',
            case / ('abi.reference' if mode == 'compiler' else 'abi.dbg'), output,
            args.lldb, 'aarch64', before, after, {'FORGE_LLDB_VECTOR_CONFIG': str(config)},
            qemu_cpu=metadata['qemuCpu'])
        assert 'FORGE_LLDB_VECTOR_PASS' in transcript
        rows = json.loads((output / 'observations.json').read_text())
        oracle = json.loads((case / (mode + '-observations.json')).read_text())
        assert len(rows) == len(oracle)
        for actual, expected in zip(rows, oracle):
            for key in ('name', 'offset', 'lanes'):
                assert actual[key] == expected[key], (key, actual, expected)
        results.append({'mode': mode, 'points': len(rows),
            'unavailable': sum(row['lanes'] == [None] * 4 for row in rows),
            'memory': sum(row.get('rawLocation', {}).get('kind') == 'memory' for row in rows)})
        assert protected == {name: hashlib.sha256((case / name).read_bytes()).hexdigest() for name in names}
    assert results[1]['unavailable'] > 0 and results[1]['memory'] > 0
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_LLDB_VECTOR',
        'versions': versions, 'metadata': metadata, 'cases': results,
        'sveControls': controls, 'protectedSha256': protected}, indent=4) + '\n')
    print('lldb-aarch64-vector=PASS')


if __name__ == '__main__':
    main()
