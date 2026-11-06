#!/usr/bin/env python3
"""Normal-export cancellation, curated constants/comments and rebase controls."""
import argparse
import json
from pathlib import Path
import re
import runpy
import sys

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'compiler-unwind-export.py'))
run, digest, metadata, decode, check_description, comparable = (
    helpers[name] for name in ('run', 'digest', 'metadata', 'decode', 'check_description', 'comparable'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('compiler_cases', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--libdwarf', required=True, type=Path)
    parser.add_argument('--libdwarfp', required=True, type=Path)
    parser.add_argument('--dwarfdump', required=True)
    args = parser.parse_args()
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    prior = json.loads((args.compiler_cases / 'result.json').read_text())
    assert prior['status'] == 'PASS_CONDITIONED_COMPILER_EXPORT'
    outcomes = []
    for item in prior['cases']:
        target, role = item['target'], item['role']
        case = work / (target + '-' + role); case.mkdir()
        compiler = args.compiler_cases.resolve() / case.name / 'compiler'
        original = compiler / 'without-cfi'
        before = digest(original); assert before == prior['protectedSha256'][str(original)]
        outputs = case / 'outputs'; outputs.mkdir()
        project = case / 'project'; project.mkdir()
        text = run([args.ghidra.resolve() / 'support/analyzeHeadless', project, 'ProductionControls', '-import', original,
            '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript', 'ProductionUnwindControls.java',
            args.libdwarf.resolve(), args.libdwarfp.resolve(), outputs, item['externalCondition']], case / 'export.log')
        assert 'production-unwind-controls=PASS controls=8 exports=3' in text
        assert text.count('production-unwind-control=PASS ') == 8
        assert text.count('GhidraDwarfForge symbol export PASS') == 3
        baseline = None
        reference_result = json.loads((compiler / 'compiler.json').read_text())
        env = {'FORGE_CFI_SHARED': '1' if role == 'shared' else '0', 'FORGE_CFI_DRIVER': str(compiler / 'driver')}
        for variant in ('curated', 'rebased'):
            artifact = outputs / (variant + '.dbg')
            section, = [s for s in metadata(artifact)['sections'] if s['name'] == '.debug_frame']
            raw = artifact.read_bytes()[section['offset']:section['offset'] + section['size']]
            frames = decode(raw, 8, 'little'); assert len(frames) == 4
            if baseline is None: baseline = raw
            assert raw == baseline
            check_description(Path(str(artifact) + '.unwind.json'), artifact, original, frames)
            source = Path(str(artifact) + '.c').read_text()
            assert 'UNWIND_ANALYST_NOTE' in source and 'UNWIND_TEST_DEPTH' in source
            text = run(['readelf', '-h', '-S', '--debug-dump=frames,info,abbrev,aranges,decodedline', artifact], case / (variant + '-gnu.log'))
            assert 'warning:' not in text.lower() and 'error:' not in text.lower()
            assert 'UNWIND_TEST_DEPTH' in text
            run(['llvm-dwarfdump', '--verify', artifact], case / (variant + '-llvm.log'))
            run([sys.executable, SCRIPTS / 'check-dwarfdump.py', artifact, case / (variant + '-strict.log'),
                '--tool', args.dwarfdump, '--original', original], case / (variant + '-strict-command.log'))
            prefix = case / ('gdb-' + variant)
            run(['bash', SCRIPTS / 'synthetic-cfi-reference-gdb.sh', target, 'compiler', artifact, original, prefix],
                case / (variant + '-gdb-command.log'), env)
            assert comparable(json.loads(Path(str(prefix) + '.json').read_text())) == comparable(reference_result)
            debugger = 'gdb' if target == 'x86_64' else 'gdb-multiarch'
            # Operand and stored widths need not imply one unambiguous direct
            # equate type. Use the advertised typed lookup names, independently
            # requiring every retained variant to evaluate to the seeded value.
            names = sorted(set(re.findall(r'Lookup (forge_equate_UNWIND_TEST_DEPTH_\w+) \[', source)))
            assert len(names) >= 2
            line = next(i for i, text in enumerate(source.splitlines(), 1) if 'UNWIND_ANALYST_NOTE' in text)
            command = [debugger, '-q', '-nx', '-batch', '-ex', 'set auto-solib-add off',
                '-ex', 'file ' + str(original), '-ex', 'symbol-file ' + str(artifact),
                '-ex', 'list cfi_outer', '-ex', 'list ' + json.dumps(str(artifact) + '.c') + ':' + str(line)]
            for name in names: command += ['-ex', 'print ' + name]
            lookup = run(command, case / (variant + '-lookup.log'))
            assert len(re.findall(r'\$\d+ = 3\b', lookup)) == len(names), lookup
            assert 'No such file' not in lookup and 'UNWIND_ANALYST_NOTE' in lookup
        assert digest(original) == before
        outcomes.append({'target': target, 'role': role, 'exports': 3, 'controls': 8, 'gdbSessions': 4,
            'originalSha256': before, 'frameSha256': __import__('hashlib').sha256(baseline).hexdigest()})
        print(target, role, 'production controls PASS', flush=True)
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_PRODUCTION_UNWIND_CONTROLS', 'cases': outcomes}, indent=4) + '\n')


if __name__ == '__main__':
    main()
