#!/usr/bin/env python3
"""Reject partial instruction ownership through normal export of saved split bodies."""
import argparse
import json
from pathlib import Path
import re
import runpy
import shutil

SCRIPTS = Path(__file__).resolve().parent
helpers = runpy.run_path(str(SCRIPTS / 'discontiguous-unwind.py'))
run, digest, metadata, decode, validate, snapshot = (
    helpers[name] for name in ('run', 'digest', 'metadata', 'decode', 'validate', 'snapshot'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('positive_cases', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--dwarfdump', required=True)
    args = parser.parse_args()
    prior = json.loads((args.positive_cases / 'result.json').read_text())
    assert prior['status'] == 'PASS_DISCONTIGUOUS_UNWIND'
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    ghidra = args.ghidra.resolve()
    wrapper = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/support/ghidra-dwarf-forge-headless'
    results = []
    for item in prior['cases']:
        target, role = item['target'], item['role']
        source = args.positive_cases.resolve() / (target + '-' + role)
        case = work / source.name; case.mkdir()
        original = source / 'original'
        protected = snapshot(source)
        project = case / 'project'; shutil.copytree(source / 'project', project)
        common = [ghidra / 'support/analyzeHeadless', project, 'SplitBody', '-noanalysis', '-process', 'original',
            '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript', 'PrepareDiscontiguousUnwind.java']
        text = run(common + ['partial', case / 'partial.json'], case / 'partial.log')
        assert 'discontiguous-program=partial PASS' in text
        read = common[:3] + ['-readOnly'] + common[3:] + ['read']
        run(read + [case / 'before.json'], case / 'warm.log')
        before = snapshot(project)
        artifact = case / 'partial.dbg'
        command = [wrapper, '--ghidra-dir=' + str(ghidra), '--project-dir=' + str(project),
            '--project-name=SplitBody', '--program=original', '--input=' + str(original), '--output=' + str(artifact),
            '--synthesize-unwind=strict']
        text = run(command, case / 'export.log')
        report, = re.findall(r'GhidraDwarfForge report: (\{.*\})', text)
        assert json.loads(report)['status'] in ('SUCCESS', 'PARTIAL')
        evidence = json.loads(Path(str(artifact) + '.unwind.json').read_text())
        entry = int(json.loads((case / 'before.json').read_text())['entry'], 16)
        refusal, = [r for r in evidence['refusedRoots'] if int(r['function']['offset'], 16) == entry]
        assert 'partial' in refusal['reason'] or 'instruction' in refusal['reason'], refusal
        assert all(int(r['offset'], 16) != entry for r in evidence['verifiedFunctions'])
        original_entry = (entry - int(evidence['databaseRebaseDelta'], 16)) % (1 << 64)
        split = [pair for pair in item['artifacts'][0]['spans'] if pair[0] >= original_entry]
        assert len(split) == 2
        frame, = [s for s in metadata(artifact)['sections'] if s['name'] == '.debug_frame']
        raw = artifact.read_bytes()[frame['offset']:frame['offset'] + frame['size']]
        frames = decode(raw, 8, 'little')
        assert frames and all(f['address'] + f['size'] <= original_entry or f['address'] >= split[-1][1] for f in frames)
        validate(artifact, original, case / 'partial', args.dwarfdump)
        files = [Path(str(artifact) + suffix) for suffix in ('', '.c', '.unwind.json')]
        hashes = {path.name: digest(path) for path in files}
        run(command, case / 'repeat.log')
        assert hashes == {path.name: digest(path) for path in files}
        run(read + [case / 'after.json'], case / 'read.log')
        assert (case / 'before.json').read_bytes() == (case / 'after.json').read_bytes()
        assert before == snapshot(project)
        prefix = case / 'gdb'
        run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, 'partial', artifact, original, prefix], case / 'gdb-command.log',
            {'FORGE_FRAME_GDB_SCRIPT': str(SCRIPTS / 'discontiguous-refusal-gdb.py'), 'FORGE_FRAME_SHARED': '0'})
        selected = re.findall(r'level=0,type=NORMAL_FRAME,unwinder="([^"]+)"', Path(str(prefix) + '.log').read_text())
        assert selected and 'dwarf2' not in selected, selected
        assert json.loads(Path(str(prefix) + '.json').read_text())['status'] == 'PASS_REFUSED_FRAME_RUNTIME'
        assert protected == snapshot(source)
        results.append({'target': target, 'role': role, 'exports': 2, 'gdbSessions': 1, 'refusal': refusal,
            'fallbackUnwinders': sorted(set(selected)), 'generationSha256': hashes, 'protectedSha256': protected})
        print(target, role, 'partial discontiguous refusal PASS', flush=True)
    assert results
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_DISCONTIGUOUS_REFUSALS', 'cases': results}, indent=4) + '\n')


if __name__ == '__main__':
    main()
