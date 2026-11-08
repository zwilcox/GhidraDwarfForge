#!/usr/bin/env python3
"""Exercise normal wrappers and exported reports against the retained compiler oracle."""
import argparse
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'compiler-unwind-export.py'))
run, digest, metadata, decode, check_description, boundaries, comparable = (
    helpers[name] for name in ('run', 'digest', 'metadata', 'decode', 'check_description', 'boundaries', 'comparable'))


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
    protected = {str(p.resolve()): digest(p) for p in (args.libdwarf, args.libdwarfp,
        args.ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar')}
    for item in prior['cases']:
        target, role = item['target'], item['role']
        case = work / (target + '-' + role); case.mkdir()
        compiler = args.compiler_cases.resolve() / case.name / 'compiler'
        original, reference = compiler / 'without-cfi', compiler / 'reference'
        for path in [original, reference] + ([compiler / 'driver'] if role == 'shared' else []):
            assert digest(path) == prior['protectedSha256'][str(path)]
            protected[str(path)] = digest(path)
        common = [ROOT / 'support/ghidra-dwarf-forge-headless', '--ghidra-dir=' + str(args.ghidra.resolve()),
            '--import=' + str(original), '--libdwarf=' + str(args.libdwarf.resolve()), '--libdwarfp=' + str(args.libdwarfp.resolve())]
        variants = []
        for mode in ('off', 'strict', 'conditioned', 'compressed'):
            artifact = case / (mode + '.dbg')
            options = ['--synthesize-unwind=' + ('conditioned' if mode == 'compressed' else mode)]
            if mode in ('conditioned', 'compressed'):
                options += ['--unwind-stack-separation=' + item['externalCondition']]
                if role == 'shared': options += ['--unwind-relocated-pointers=fixed']
            if mode == 'compressed': options += ['--compress-debug-sections=zlib', '--gdb-loader']
            command = common + ['--output=' + str(artifact), *options]
            text = run(command, case / (mode + '-export.log'))
            reports = re.findall(r'GhidraDwarfForge report: (\{.*\})', text)
            assert len(reports) == 1
            report = json.loads(reports[0]); assert report['status'] in ('SUCCESS', 'PARTIAL')
            assert report['artifacts']['outputSha256'] == digest(artifact)
            assert report['artifacts']['sourceSha256'] == digest(Path(str(artifact) + '.c'))
            assert report['validation']['status'] == 'NOT_RUN' and report['coverage']['summary']['functions'] == ('4' if role == 'shared' else '5')
            evidence_path = Path(str(artifact) + '.unwind.json')
            frame_sections = [s for s in metadata(artifact)['sections'] if s['name'] == '.debug_frame']
            if mode == 'off':
                assert not evidence_path.exists() and not frame_sections
            elif mode == 'strict':
                evidence = json.loads(evidence_path.read_text())
                assert not evidence['hasPlan'] and evidence['refusedRoots'] and not frame_sections
                assert evidence['sidecarSha256'] == digest(artifact) and evidence['stackSeparation'] is None
            else:
                section, = frame_sections
                raw = artifact.read_bytes()[section['offset']:section['offset'] + section['size']]
                if mode == 'compressed': raw = zlib.decompress(raw[24:])
                frames = decode(raw, 8, 'little'); assert len(frames) == 4
                check_description(evidence_path, artifact, original, frames)
                evidence = json.loads(evidence_path.read_text())
                assert evidence['stackSeparation']['status'] == 'EXTERNAL_CONDITION_NOT_PROVED'
                assert evidence['stackSeparation']['fixedPointers'] == item['fixedPointers']
                assert any('explicit external conditions' in d for d in report['diagnostics'])
            text = run(['readelf', '-h', '-S', '--debug-dump=frames,info,abbrev,aranges,decodedline', artifact], case / (mode + '-gnu.log'))
            assert 'warning:' not in text.lower() and 'error:' not in text.lower()
            run(['llvm-dwarfdump', '--verify', artifact], case / (mode + '-llvm.log'))
            run([sys.executable, SCRIPTS / 'check-dwarfdump.py', artifact, case / (mode + '-strict.log'),
                '--tool', args.dwarfdump, '--original', original], case / (mode + '-strict-command.log'))
            variants.append({'mode': mode, 'sha256': digest(artifact)})
        artifact = case / 'compressed.dbg'
        generation = [artifact, Path(str(artifact) + '.c'), Path(str(artifact) + '.unwind.json'), Path(str(artifact) + '.gdb.py')]
        before = {str(p): digest(p) for p in generation}
        run(command, case / 'deterministic-repeat.log')
        assert before == {str(p): digest(p) for p in generation}
        invalid = common + ['--output=' + str(artifact), '--synthesize-unwind=conditioned', '--unwind-stack-separation=200:100']
        with (case / 'invalid-options.log').open('w') as stream:
            result = subprocess.run(list(map(str, invalid)), stdout=stream, stderr=subprocess.STDOUT, timeout=360)
        assert result.returncode == 10
        assert before == {str(p): digest(p) for p in generation}
        assert not list(case.glob('.forge-*'))
        env = {'FORGE_CFI_SHARED': '1' if role == 'shared' else '0', 'FORGE_CFI_DRIVER': str(compiler / 'driver'),
               'FORGE_CFI_FIXED_POINTERS': json.dumps(item['fixedPointers'])}
        reference_boundaries = boundaries(target, reference, original, case / 'boundaries-reference', env)
        reference_result = json.loads((compiler / 'compiler.json').read_text())
        for mode in ('conditioned', 'compressed'):
            artifact = case / (mode + '.dbg')
            observed = boundaries(target, artifact, original, case / ('boundaries-' + mode), env)
            assert observed == reference_boundaries
            prefix = case / ('gdb-' + mode)
            run(['bash', SCRIPTS / 'synthetic-cfi-reference-gdb.sh', target, 'compiler', artifact, original, prefix],
                case / ('gdb-' + mode + '-command.log'), env)
            assert comparable(json.loads(Path(str(prefix) + '.json').read_text())) == comparable(reference_result)
        outcomes.append({'target': target, 'role': role, 'exports': 5, 'invalidOptionControls': 1,
            'gdbSessions': 5, 'boundarySnapshots': len(reference_boundaries['trace']), 'artifacts': variants})
        print(target, role, 'production unwind PASS', flush=True)
    assert protected == {p: digest(Path(p)) for p in protected}
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_PRODUCTION_UNWIND', 'cases': outcomes,
        'protectedSha256': protected}, indent=4) + '\n')


if __name__ == '__main__':
    main()
