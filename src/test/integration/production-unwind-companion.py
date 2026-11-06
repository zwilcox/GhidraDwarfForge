#!/usr/bin/env python3
"""Compare direct and companion-loaded recovery without preloading Forge symbols."""
import argparse
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'compiler-unwind-export.py'))
run, digest, boundaries, comparable = (helpers[n] for n in ('run', 'digest', 'boundaries', 'comparable'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('production_cases', type=Path)
    parser.add_argument('compiler_cases', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    prior = json.loads((args.production_cases / 'result.json').read_text())
    assert prior['status'] == 'PASS_PRODUCTION_UNWIND'
    results = []
    for item in prior['cases']:
        target, role = item['target'], item['role']
        case = work / (target + '-' + role); case.mkdir()
        artifact = args.production_cases.resolve() / case.name / 'compressed.dbg'
        compiler = args.compiler_cases.resolve() / case.name / 'compiler'
        original = compiler / 'without-cfi'
        evidence = json.loads(Path(str(artifact) + '.unwind.json').read_text())
        protected = {str(p): digest(p) for p in [original, compiler / 'reference', artifact,
            Path(str(artifact) + '.c'), Path(str(artifact) + '.unwind.json'), Path(str(artifact) + '.gdb.py')]}
        env = {'FORGE_CFI_SHARED': '1' if role == 'shared' else '0', 'FORGE_CFI_DRIVER': str(compiler / 'driver'),
            'FORGE_CFI_FIXED_POINTERS': json.dumps(evidence['stackSeparation']['fixedPointers'])}
        baseline = boundaries(target, compiler / 'reference', original, case / 'reference', env)
        loaded = boundaries(target, artifact, original, case / 'loaded', {**env, 'FORGE_CFI_COMPANION': '1'})
        assert loaded == baseline
        prefix = case / 'returns'
        run(['bash', SCRIPTS / 'synthetic-cfi-reference-gdb.sh', target, 'compiler', artifact, original, prefix],
            case / 'returns-command.log', {**env, 'FORGE_CFI_COMPANION': '1'})
        assert comparable(json.loads(Path(str(prefix) + '.json').read_text())) == comparable(json.loads((compiler / 'compiler.json').read_text()))
        for prefix in ('loaded', 'returns'):
            assert 'unwind-companion=PASS' in (case / (prefix + '.log')).read_text()
        assert protected == {p: digest(Path(p)) for p in protected}
        results.append({'target': target, 'role': role, 'snapshots': len(loaded['trace']), 'gdbSessions': 3,
            'protectedSha256': protected})
        print(target, role, 'unwind companion PASS', flush=True)
    assert results
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_UNWIND_COMPANION', 'cases': results}, indent=4) + '\n')


if __name__ == '__main__':
    main()
