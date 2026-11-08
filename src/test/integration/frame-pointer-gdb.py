#!/usr/bin/env python3
"""Check actual frame-pointer caller values at every executed compiler boundary."""
import argparse
import json
from pathlib import Path
import runpy

SCRIPTS = Path(__file__).resolve().parent
helpers = runpy.run_path(str(SCRIPTS / 'compiler-unwind-export.py'))
boundaries, digest = (helpers[name] for name in ('boundaries', 'digest'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('compiler_cases', type=Path)
    parser.add_argument('production_cases', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    compiler_record = json.loads((args.compiler_cases / 'result.json').read_text())
    production_record = json.loads((args.production_cases / 'result.json').read_text())
    assert compiler_record['status'] == 'PASS_CONDITIONED_COMPILER_EXPORT'
    assert production_record['status'] == 'PASS_PRODUCTION_UNWIND'
    results = []
    for item in compiler_record['cases']:
        assert item['framePointer'] == 'keep' and item['role'] == 'exec'
        target = item['target']
        compiler = args.compiler_cases.resolve() / (target + '-exec') / 'compiler'
        exported = args.production_cases.resolve() / (target + '-exec')
        case = work / target; case.mkdir()
        reference, original = compiler / 'reference', compiler / 'without-cfi'
        variants = [exported / (mode + '.dbg') for mode in ('conditioned', 'compressed')]
        protected = {str(path): digest(path) for path in [reference, original, *variants]}
        assert all(protected[str(path)] == compiler_record['protectedSha256'][str(path)] for path in [reference, original])
        production, = [entry for entry in production_record['cases'] if entry['target'] == target and entry['role'] == 'exec']
        for variant in variants:
            record, = [entry for entry in production['artifacts'] if entry['mode'] == variant.stem]
            assert digest(variant) == record['sha256']
        env = {'FORGE_CFI_SHARED': '0', 'FORGE_CFI_FRAME_POINTER_VALUES': '1'}
        baseline = boundaries(target, reference, original, case / 'reference', env)
        for index, variant in enumerate(variants):
            assert boundaries(target, variant, original, case / variant.stem, env) == baseline
        # Require actual nonzero anchored values in recursive caller frames,
        # not just equality of an uninitialized or omitted frame pointer.
        recursive = [row for stack in baseline['trace'] for row in stack if row['name'] == 'cfi_recursive']
        assert recursive and all('framePointer' in row for row in recursive)
        assert len({row['framePointer'] for row in recursive if row['framePointer'] != 'zero'}) >= 4
        assert protected == {name: digest(Path(name)) for name in protected}
        results.append({'target': target, 'role': 'exec', 'snapshots': len(baseline['trace']),
            'recursiveFramePointerValues': sorted({str(row['framePointer']) for row in recursive}),
            'gdbSessions': 3, 'protectedSha256': protected})
        print(target + ' frame-pointer caller values PASS', flush=True)
    assert results
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_FRAME_POINTER_VALUES', 'cases': results}, indent=4) + '\n')


if __name__ == '__main__':
    main()
