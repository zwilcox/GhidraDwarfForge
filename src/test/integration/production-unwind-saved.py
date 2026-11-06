#!/usr/bin/env python3
"""Normal read-only saved-project exports preserve inherited CFI across rebasing."""
import argparse
import json
from pathlib import Path
import re
import runpy
import shutil
import sys
import zlib

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'unwind-export.py'))
run, digest, metadata, normalized, decode, check_description = (helpers[n] for n in ('run', 'digest', 'metadata', 'normalized', 'decode', 'check_unwind_description'))


def snapshot(root):
    return {str(p.relative_to(root)): digest(p) for p in root.rglob('*') if p.is_file() and not p.name.endswith('.lock')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('native_cases', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--target', choices=('all', 'x86_64', 'aarch64'), default='all')
    parser.add_argument('--roles', nargs='+', choices=('exec', 'pie', 'shared'), default=('exec', 'pie', 'shared'))
    args = parser.parse_args()
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    prior = json.loads((args.native_cases / 'result.json').read_text())
    assert prior['status'] == 'PASS_NATIVE_FRAME_EXPORT'
    module = args.ghidra.resolve() / 'Ghidra/Extensions/GhidraDwarfForge'
    wrapper = module / 'support/ghidra-dwarf-forge-headless'
    results = []
    for item in prior['cases']:
        target, role, family = (item[k] for k in ('target', 'role', 'family'))
        if (args.target != 'all' and target != args.target) or role not in args.roles: continue
        source = args.native_cases.resolve() / (target + '-' + role)
        case = work / source.name; case.mkdir()
        original = case / 'original'; shutil.copy2(source / 'original', original)
        reference = source / 'reference'
        protected = {str(p): digest(p) for p in [original, reference, source / 'original', module / 'lib/GhidraDwarfForge.jar']}
        assert digest(original) == item['inputHashes'][str(source / 'original')]
        project = case / 'project'; project.mkdir()
        setup = run([args.ghidra.resolve() / 'support/analyzeHeadless', project, 'SavedUnwind', '-import', original,
            '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript', 'SavedUnwindProgram.java', 'setup', case / 'prepared.json'], case / 'setup.log')
        assert 'saved-unwind-program=setup PASS' in setup
        read_command = [args.ghidra.resolve() / 'support/analyzeHeadless', project, 'SavedUnwind', '-readOnly', '-noanalysis', '-process', 'original',
            '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript', 'SavedUnwindProgram.java', 'read']
        run(read_command + [case / 'warm.json'], case / 'warm.log')
        before_project = snapshot(project)
        (case / 'project-before.json').write_text(json.dumps(before_project, indent=4) + '\n')
        expected_frame = (source / 'none.frame').read_bytes()
        prefix = (source / 'assembler-prefix.frame').read_bytes() if item.get('originalEncoding') else b''
        assert expected_frame.startswith(prefix)
        suffix = bytearray(expected_frame[len(prefix):])
        position = 4 + int.from_bytes(suffix[:4], 'little')
        while position < len(suffix):
            length = int.from_bytes(suffix[position:position + 4], 'little')
            assert int.from_bytes(suffix[position + 4:position + 8], 'little') == len(prefix)
            suffix[position + 4:position + 8] = b'\0' * 4
            position += 4 + length
        assert position == len(suffix)
        expected_generated = decode(suffix, 8, 'little')
        saved = json.loads((case / 'warm.json').read_text())
        expected_delta = (int(saved['imageBaseOffset'], 16) - int(saved['originalImageBase'], 16)) % (1 << 64)
        reference_prefix = case / 'gdb-reference'
        env = {'FORGE_FRAME_PROFILE': family, 'FORGE_FRAME_SHARED': '1' if role == 'shared' else '0',
               'FORGE_FRAME_DRIVER': str(source / 'driver')}
        run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, 'reference', reference, original, reference_prefix], case / 'gdb-reference-command.log', env)
        reference_result = json.loads(Path(str(reference_prefix) + '.json').read_text())
        artifacts = []
        for compression in ('none', 'zlib'):
            artifact = case / (compression + '.dbg')
            command = [wrapper, '--ghidra-dir=' + str(args.ghidra.resolve()), '--project-dir=' + str(project),
                '--project-name=SavedUnwind', '--program=original', '--input=' + str(original), '--output=' + str(artifact),
                '--synthesize-unwind=strict', '--compress-debug-sections=' + compression]
            text = run(command, case / (compression + '-export.log'))
            report, = re.findall(r'GhidraDwarfForge report: (\{.*\})', text)
            report = json.loads(report)
            assert report['status'] in ('SUCCESS', 'PARTIAL') and '.debug_frame' in report['sections']
            evidence = json.loads(Path(str(artifact) + '.unwind.json').read_text())
            assert evidence['hasPlan'] and evidence['stackSeparation'] is None
            assert int(evidence['databaseRebaseDelta'], 16) == expected_delta
            check_description(Path(str(artifact) + '.unwind.json'), artifact, original, expected_generated)
            assert evidence['inputSha256'] == digest(original) and evidence['sidecarSha256'] == digest(artifact)
            assert evidence['sourceSha256'] == digest(Path(str(artifact) + '.c'))
            sections = metadata(artifact)['sections']
            frame, = [s for s in sections if s['name'] == '.debug_frame']
            raw = artifact.read_bytes()[frame['offset']:frame['offset'] + frame['size']]
            if compression == 'zlib': raw = zlib.decompress(raw[24:])
            assert raw == expected_frame, 'normal saved export changed inherited or recovered frame records'
            for old in metadata(original)['sections']:
                if old['name'] not in ('.debug_frame', '.zdebug_frame', '.eh_frame', '.eh_frame_hdr'): continue
                name = '.forge.stale' + old['name'] if old['name'] in ('.debug_frame', '.zdebug_frame') else old['name']
                retained, = [s for s in sections if s['name'] == name]
                assert all(retained[k] == old[k] for k in ('type', 'flags', 'address', 'offset', 'size'))
                assert artifact.read_bytes()[retained['offset']:retained['offset'] + retained['size']] == original.read_bytes()[old['offset']:old['offset'] + old['size']]
            generation = [artifact, Path(str(artifact) + '.c'), Path(str(artifact) + '.unwind.json')]
            hashes = {str(p): digest(p) for p in generation}
            run(command, case / (compression + '-repeat.log'))
            assert hashes == {p: digest(Path(p)) for p in hashes}
            assert before_project == snapshot(project), 'read-only wrapper changed saved project files'
            assert 'SAVED_UNWIND_ANALYST_COMMENT' in generation[1].read_text()
            text = run(['readelf', '-h', '-S', '--debug-dump=frames,info,abbrev,aranges,decodedline', artifact], case / (compression + '-gnu.log'))
            assert 'warning:' not in text.lower() and 'error:' not in text.lower()
            run(['llvm-dwarfdump', '--verify', artifact], case / (compression + '-llvm.log'))
            run([sys.executable, SCRIPTS / 'check-dwarfdump.py', artifact, case / (compression + '-strict.log'),
                '--tool', args.dwarfdump, '--original', original], case / (compression + '-strict-command.log'))
            prefix = case / ('gdb-' + compression)
            run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, compression, artifact, original, prefix], case / ('gdb-' + compression + '-command.log'), env)
            assert normalized(json.loads(Path(str(prefix) + '.json').read_text())) == normalized(reference_result)
            log = Path(str(prefix) + '.log').read_text()
            assert re.search(r'level=0,type=NORMAL_FRAME,unwinder="dwarf2"', log)
            artifacts.append({'compression': compression, 'sha256': digest(artifact)})
        run(read_command + [case / 'after.json'], case / 'after.log')
        assert json.loads((case / 'after.json').read_text()) == json.loads((case / 'warm.json').read_text())
        assert before_project == snapshot(project)
        assert protected == {p: digest(Path(p)) for p in protected}
        results.append({'target': target, 'role': role, 'family': family, 'originalEncoding': item.get('originalEncoding'),
            'originalRuntime': item.get('originalRuntime', False), 'exports': 4, 'gdbSessions': 3, 'artifacts': artifacts,
            'protectedSha256': protected, 'projectSnapshotSha256': digest(case / 'project-before.json')})
        print(target, role, family, 'saved production coexistence PASS', flush=True)
    assert results
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_SAVED_PRODUCTION_UNWIND', 'cases': results}, indent=4) + '\n')


if __name__ == '__main__':
    main()
