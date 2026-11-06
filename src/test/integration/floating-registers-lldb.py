#!/usr/bin/env python3
"""Compare compiler/Forge scalar FP arguments and lifetime boundaries with LLDB."""
import argparse
import hashlib
import json
from pathlib import Path
import lldb_consumer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', required=True, choices=('x86_64', 'aarch64'))
    parser.add_argument('--lldb', default='lldb-18')
    parser.add_argument('--sample', choices=('baseline', 'rebased', 'repeat'))
    args = parser.parse_args()
    case, root = args.case.resolve(), args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    original, reference, sidecar = case / 'floating.stripped', case / 'floating.reference', case / 'artifacts/floating.dbg'
    source = Path(str(sidecar) + '.c')
    if args.sample:
        sidecar = case / args.sample / 'floating.dbg'
    protected = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (original, reference, sidecar, source, case / 'labels.txt')}
    labels = {name: int(address, 16) for name, address in (line.split() for line in (case / 'labels.txt').read_text().splitlines())}
    versions = lldb_consumer.versions(args.lldb, args.target)
    # LLDB 18 lacks the Neon-from-SVE register fallback fixed by llvm/llvm-project#108365.
    # Select an explicit ordinary Neon transport and retain default-SVE refusal evidence separately.
    cpu = 'cortex-a53' if args.target == 'aarch64' else None
    results = []
    for mode in ('compiler', 'forge'):
        output = root / mode
        config = root / (mode + '.json')
        config.write_text(json.dumps({'mode': mode, 'target': args.target, 'labels': labels,
            'source': str(source), 'observations': str(output / 'observations.json')}, indent=4) + '\n')
        before = ['breakpoint set --name ' + name + ' --skip-prologue false --one-shot true'
            for name in ('fp_float', 'fp_double', 'fp_clobbered')]
        after = ['script exec(open(' + repr(str(Path(__file__).with_name('floating-registers-lldb-observe.py').resolve())) + ').read())']
        transcript = lldb_consumer.run(original, reference if mode == 'compiler' else sidecar, output,
            args.lldb, args.target, before, after, {'FORGE_LLDB_FP_CONFIG': str(config)}, qemu_cpu=cpu)
        assert 'FORGE_LLDB_FLOATING_PASS' in transcript
        rows = json.loads((output / 'observations.json').read_text())
        assert len(rows) == 10
        results.append({'mode': mode, 'observations': rows})
        assert protected == {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in protected}
    for compiler, forge in zip(results[0]['observations'], results[1]['observations']):
        for key in ('function', 'marker', 'linkPc'):
            assert compiler[key] == forge[key]
        if compiler['marker'] != 'fp_clobber_after':
            assert compiler['values'] == forge['values']
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_LLDB_FLOATING', 'target': args.target,
        'versions': versions, 'sample': args.sample, 'qemuCpu': cpu, 'cases': results, 'protectedSha256': protected}, indent=4) + '\n')
    print('lldb-floating-registers=PASS ' + args.target)


if __name__ == '__main__':
    main()
