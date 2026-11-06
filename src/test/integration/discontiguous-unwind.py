#!/usr/bin/env python3
"""Validate split-body strict exports across real runtime gaps and database rebases."""
import argparse
import json
from pathlib import Path
import re
import runpy
import sys
import zlib

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'unwind-export.py'))
run, digest, metadata, normalized, decode, check_description = (
    helpers[name] for name in ('run', 'digest', 'metadata', 'normalized', 'decode', 'check_unwind_description'))
image = runpy.run_path(str(SCRIPTS / 'synthetic-cfi-reference.py'))['image']


def snapshot(root):
    return {str(path.relative_to(root)): digest(path) for path in root.rglob('*')
            if path.is_file() and not path.name.endswith('.lock')}


def validate(path, original, prefix, checker):
    text = run(['readelf', '-h', '-S', '--debug-dump=frames,info,abbrev,aranges,decodedline', path], Path(str(prefix) + '-gnu.log'))
    assert 'warning:' not in text.lower() and 'error:' not in text.lower()
    run(['llvm-dwarfdump', '--verify', path], Path(str(prefix) + '-llvm.log'))
    run([sys.executable, SCRIPTS / 'check-dwarfdump.py', path, Path(str(prefix) + '-strict.log'),
        '--tool', checker, '--original', original], Path(str(prefix) + '-strict-command.log'))


def require_gap_unwinders(observed, transcript, symbols):
    bias = observed['checkpointAddress'] - symbols['cf_checkpoint']
    stacks = [stack for stack in observed['trace'] if stack[0]['pc'] - bias in (symbols['cf_gap_jump'], symbols['cf_gap_after'])]
    blocks = re.findall(r'(?ms)^FORGE_GAP_BEGIN\n(.*?)^FORGE_GAP_END\n', transcript)
    assert len(stacks) == len(blocks) == 8
    for stack, block in zip(stacks, blocks):
        selected = set(map(int, re.findall(r'level=(\d+),type=NORMAL_FRAME,unwinder="dwarf2"', block)))
        assert set(range(len(stack) - 1)) <= selected, (len(stack), selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--target', choices=('all', 'x86_64', 'aarch64'), default='all')
    parser.add_argument('--roles', nargs='+', choices=('exec', 'pie'), default=('exec', 'pie'))
    args = parser.parse_args()
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    ghidra = args.ghidra.resolve()
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    wrapper = module / 'support/ghidra-dwarf-forge-headless'
    results = []
    for target in ('x86_64', 'aarch64'):
        if args.target not in ('all', target): continue
        for role in args.roles:
            case = work / (target + '-' + role); case.mkdir()
            source = ROOT / 'src/test/fixtures' / ('cfi-encoder-' + target + '.S')
            text = source.read_text()
            anchor = '    mov $0x5100,%r12' if target == 'x86_64' else '    mov x19,#0x5100'
            jump = '    jmp cf_gap_after' if target == 'x86_64' else '    b cf_gap_after'
            insertion = '    .globl cf_gap_jump,cf_gap_first,cf_gap_after,cf_body_end\ncf_gap_jump:\n' + jump + '\ncf_gap_first:\n    .fill 16,1,0\ncf_gap_after:\n'
            assert text.count(anchor) == 1
            text = text.replace(anchor, insertion + anchor)
            text = text.replace('    .size cf_recurse,.-cf_recurse', 'cf_body_end:\n    .size cf_recurse,.-cf_recurse')
            generated = case / 'fixture.S'; generated.write_text(text)
            tool = '' if target == 'x86_64' else 'aarch64-linux-gnu-'
            flags = ['-static', '-no-pie'] if role == 'exec' else ['-fPIE', '-static-pie']
            reference, original = case / 'reference', case / 'original'
            for name in ('reference', 'reference-repeat'):
                run([tool + 'gcc', '-g', '-gdwarf-5', '-nostdlib', *flags, '-Wl,--build-id=none', generated, '-o', case / name], case / (name + '-build.log'))
            assert reference.read_bytes() == (case / 'reference-repeat').read_bytes()
            run([tool + 'objcopy', '--strip-debug', reference, original], case / 'strip.log')
            assert image(reference)[1:] == image(original)[1:]
            assert not any(s['name'] in ('.debug_frame', '.eh_frame') and s['size'] for s in metadata(original)['sections'])
            protected = {str(path): digest(path) for path in (source, generated, original, reference, module / 'lib/GhidraDwarfForge.jar')}
            symbols = {}
            for line in run(['readelf', '-Ws', original], case / 'symbols.log').splitlines():
                fields = line.split()
                if len(fields) == 8 and fields[7].startswith('cf_'):
                    symbols[fields[7]] = int(fields[1], 16)
            first, after, entry, end = (symbols[name] for name in ('cf_gap_first', 'cf_gap_after', 'cf_recurse', 'cf_body_end'))
            assert after - first == 16 and entry < first < after < end
            validate(reference, original, case / 'reference', args.dwarfdump)
            runtime = {'FORGE_FRAME_GAPS': '1', 'FORGE_FRAME_PROFILE': 'encoder', 'FORGE_FRAME_SHARED': '0'}
            oracles = {}
            for mode in ('reference', 'absent', 'disabled'):
                prefix = case / ('gdb-' + mode)
                run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, mode,
                    original if mode == 'absent' else reference, original, prefix], case / (mode + '-gdb-command.log'), runtime)
                oracles[mode] = json.loads(Path(str(prefix) + '.json').read_text())
                assert oracles[mode]['shapeEvidence']['gapCrossings'] == 4
                if mode == 'reference': require_gap_unwinders(oracles[mode], Path(str(prefix) + '.log').read_text(), symbols)
                else: assert 'unwinder="dwarf2"' not in Path(str(prefix) + '.log').read_text()
            project = case / 'project'; project.mkdir()
            command = [ghidra / 'support/analyzeHeadless', project, 'SplitBody']
            setup = run(command + ['-import', original, '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript',
                'PrepareDiscontiguousUnwind.java', 'prepare', case / 'prepared.json'], case / 'prepare.log')
            assert 'discontiguous-program=prepare PASS' in setup
            assert json.loads((case / 'prepared.json').read_text())['rangeCount'] == 2
            read = command + ['-readOnly', '-noanalysis', '-process', 'original', '-scriptPath', SCRIPTS / 'ghidra_scripts',
                '-postScript', 'PrepareDiscontiguousUnwind.java', 'read']
            artifacts = []; baseline_raw = None
            for state in ('initial', 'rebased'):
                if state == 'rebased':
                    run(command + ['-noanalysis', '-process', 'original', '-scriptPath', SCRIPTS / 'ghidra_scripts',
                        '-postScript', 'PrepareDiscontiguousUnwind.java', 'rebase', case / 'rebased.json'], case / 'rebase.log')
                run(read + [case / (state + '-before.json')], case / (state + '-warm.log'))
                before = snapshot(project)
                for compression in ('none', 'zlib'):
                    name = state + '-' + compression
                    artifact = case / (name + '.dbg')
                    export = [wrapper, '--ghidra-dir=' + str(ghidra), '--project-dir=' + str(project),
                        '--project-name=SplitBody', '--program=original', '--input=' + str(original), '--output=' + str(artifact),
                        '--synthesize-unwind=strict', '--compress-debug-sections=' + compression]
                    transcript = run(export, case / (name + '-export.log'))
                    report, = re.findall(r'GhidraDwarfForge report: (\{.*\})', transcript)
                    assert json.loads(report)['status'] in ('SUCCESS', 'PARTIAL')
                    section, = [s for s in metadata(artifact)['sections'] if s['name'] == '.debug_frame']
                    raw = artifact.read_bytes()[section['offset']:section['offset'] + section['size']]
                    if compression == 'zlib': raw = zlib.decompress(raw[24:])
                    frames = decode(raw, 8, 'little')
                    check_description(Path(str(artifact) + '.unwind.json'), artifact, original, frames)
                    spans = [(f['address'], f['address'] + f['size']) for f in frames]
                    assert (entry, first) in spans and (after, end) in spans
                    assert all(stop <= first or start >= after for start, stop in spans)
                    if baseline_raw is None: baseline_raw = raw
                    assert raw == baseline_raw
                    evidence = json.loads(Path(str(artifact) + '.unwind.json').read_text())
                    assert evidence['hasPlan'] and evidence['stackSeparation'] is None
                    assert not any(first <= int(item['address'], 16) < after for item in evidence['observations'])
                    generation = [Path(str(artifact) + suffix) for suffix in ('', '.c', '.unwind.json')]
                    hashes = {str(path): digest(path) for path in generation}
                    run(export, case / (name + '-repeat.log'))
                    assert hashes == {path: digest(Path(path)) for path in hashes}
                    assert before == snapshot(project)
                    assert 'DISCONTIGUOUS_UNWIND_ANALYST_COMMENT' in generation[1].read_text()
                    validate(artifact, original, case / name, args.dwarfdump)
                    prefix = case / ('gdb-' + name)
                    run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, name, artifact, original, prefix], case / (name + '-gdb-command.log'), runtime)
                    observed = json.loads(Path(str(prefix) + '.json').read_text())
                    assert normalized(observed) == normalized(oracles['reference'])
                    require_gap_unwinders(observed, Path(str(prefix) + '.log').read_text(), symbols)
                    artifacts.append({'state': state, 'compression': compression, 'sha256': digest(artifact), 'spans': spans})
                run(read + [case / (state + '-after.json')], case / (state + '-read.log'))
                assert (case / (state + '-after.json')).read_bytes() == (case / (state + '-before.json')).read_bytes()
                assert before == snapshot(project)
            assert protected == {path: digest(Path(path)) for path in protected}
            results.append({'target': target, 'role': role, 'exports': 8, 'gdbSessions': 7, 'gap': [first, after],
                'artifacts': artifacts, 'protectedSha256': protected})
            print(target, role, 'discontiguous unwind PASS', flush=True)
    assert results
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_DISCONTIGUOUS_UNWIND', 'cases': results}, indent=4) + '\n')


if __name__ == '__main__':
    main()
