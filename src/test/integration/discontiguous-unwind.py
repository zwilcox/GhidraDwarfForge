#!/usr/bin/env python3
"""Validate split-body strict exports across real runtime gaps and database rebases."""
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


def require_source_diagnostics(transcript, reference, target):
    def warnings(text):
        return {re.sub(r'0x[0-9a-f]+', '<address>', line) for line in text.splitlines()
            if line.lower().startswith('warning:')}
    observed = warnings(transcript)
    known = {'warning: BFD: warning: system-supplied DSO at <address> has a corrupt string table index'}
    assert observed <= (known if target == 'aarch64' else set()), 'unexpected source debugger warning'
    assert observed <= warnings(reference), 'source warning lacks compiler-reference corroboration'
    assert not any(message in transcript for message in ('Python Exception', 'Error occurred in Python', 'Traceback'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--target', choices=('all', 'x86_64', 'aarch64'), default='all')
    parser.add_argument('--roles', nargs='+', choices=('exec', 'pie'), default=('exec', 'pie'))
    parser.add_argument('--source-lines', type=int, help='compare complete single/multi source semantics and source gap stepping')
    parser.add_argument('--java', type=Path, help='explicit Java runtime with private script caches')
    parser.add_argument('--gap-position', choices=('prologue', 'body'), default='prologue',
        help='retain the original unmapped prologue gap or cross into a mapped conditional')
    args = parser.parse_args()
    if args.source_lines is not None and not 1 <= args.source_lines <= 2147483647:
        parser.error('--source-lines must be in 1..2147483647')
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    ghidra = args.ghidra.resolve()
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    wrapper = module / 'support/ghidra-dwarf-forge-headless'
    headless = [ghidra / 'support/analyzeHeadless']
    if args.java:
        java = args.java.resolve(strict=True)
        vmargs = subprocess.check_output([java, '-cp', ghidra / 'support/LaunchSupport.jar',
            'LaunchSupport', ghidra, '-vmargs'], text=True).splitlines()
        for name in ('java-home', 'java-tmp'):
            (work / name).mkdir()
        headless = [java, *vmargs, '-Duser.home=' + str(work / 'java-home'),
            '-Djava.io.tmpdir=' + str(work / 'java-tmp'), '-Xmx2G', '-XX:ParallelGCThreads=2',
            '-XX:CICompilerCount=2', '-Djava.awt.headless=true', '-showversion', '-cp',
            ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar', 'ghidra.Ghidra',
            'ghidra.app.util.headless.AnalyzeHeadless']
    results = []
    for target in ('x86_64', 'aarch64'):
        if args.target not in ('all', target): continue
        for role in args.roles:
            case = work / (target + '-' + role); case.mkdir()
            source = ROOT / 'src/test/fixtures' / ('cfi-encoder-' + target + '.S')
            text = source.read_text()
            anchor = '    mov $0x5100,%r12' if target == 'x86_64' else '    mov x19,#0x5100'
            if args.gap_position == 'body':
                anchor = '    test %rdi,%rdi' if target == 'x86_64' else '    cbz x0,.Lbase'
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
            protected = {str(path): digest(path) for path in (source, generated, original, reference,
                Path(__file__), SCRIPTS / 'multifile-gap-gdb.py', SCRIPTS / 'check-multifile-semantics.py',
                SCRIPTS / 'ghidra_scripts/PrepareDiscontiguousUnwind.java', module / 'lib/GhidraDwarfForge.jar')}
            symbols = {}
            for line in run(['readelf', '-Ws', original], case / 'symbols.log').splitlines():
                fields = line.split()
                if len(fields) == 8 and fields[7].startswith('cf_'):
                    symbols[fields[7]] = int(fields[1], 16)
            first, after, entry, end = (symbols[name] for name in ('cf_gap_first', 'cf_gap_after', 'cf_recurse', 'cf_body_end'))
            assert after - first == 16 and entry < first < after < end
            validate(reference, original, case / 'reference', args.dwarfdump)
            runtime = {'FORGE_FRAME_GAPS': '1', 'FORGE_FRAME_PROFILE': 'encoder', 'FORGE_FRAME_SHARED': '0',
                'FORGE_GAP_POSITION': args.gap_position}
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
            command = [*headless, project, 'SplitBody']
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
                    if args.java:
                        export = command + ['-process', 'original', '-readOnly', '-noanalysis',
                            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--input=' + str(original),
                            '--output=' + str(artifact), '--synthesize-unwind=strict', '--compress-debug-sections=' + compression]
                    baseline = None
                    if args.source_lines is not None:
                        baseline = case / 'single' / artifact.name
                        baseline.parent.mkdir(exist_ok=True)
                        baseline_command = [('--output=' + str(baseline)) if part == '--output=' + str(artifact) else part
                            for part in export]
                        baseline_text = run(baseline_command, case / (name + '-single-export.log'))
                        assert 'GhidraDwarfForge symbol export PASS' in baseline_text
                        validate(baseline, original, case / (name + '-single'), args.dwarfdump)
                        export += ['--source-lines=' + str(args.source_lines)]
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
                    logical_source = generation[1].read_text()
                    if baseline is not None:
                        manifest_name, = [line.removeprefix(' * Manifest: ') for line in logical_source.splitlines()
                            if line.startswith(' * Manifest: ')]
                        manifest_path = artifact.parent / manifest_name
                        manifest = json.loads(manifest_path.read_text())
                        parts = [artifact.parent / row['name'] for row in manifest['parts']]
                        generation += [manifest_path, *parts]
                        logical_source = ''.join(part.read_text() for part in parts)
                        run([sys.executable, SCRIPTS / 'check-multifile-semantics.py', original, baseline,
                            artifact, case / (name + '-semantics')], case / (name + '-semantics.log'))
                    hashes = {str(path): digest(path) for path in generation}
                    run(export, case / (name + '-repeat.log'))
                    assert hashes == {path: digest(Path(path)) for path in hashes}
                    assert before == snapshot(project)
                    assert 'DISCONTIGUOUS_UNWIND_ANALYST_COMMENT' in logical_source
                    validate(artifact, original, case / name, args.dwarfdump)
                    prefix = case / ('gdb-' + name)
                    run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, name, artifact, original, prefix], case / (name + '-gdb-command.log'), runtime)
                    observed = json.loads(Path(str(prefix) + '.json').read_text())
                    assert normalized(observed) == normalized(oracles['reference'])
                    require_gap_unwinders(observed, Path(str(prefix) + '.log').read_text(), symbols)
                    source_observations = []
                    if baseline is not None:
                        for variant, selected in [('single', baseline), ('multi', artifact)]:
                            prefix = case / (name + '-' + variant + '-source-gap')
                            run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, name, selected, original, prefix],
                                case / (name + '-' + variant + '-source-gap-command.log'),
                                {**runtime, 'FORGE_FRAME_GDB_SCRIPT': str(SCRIPTS / 'multifile-gap-gdb.py')})
                            source_result = json.loads(Path(str(prefix) + '.json').read_text())
                            assert source_result['status'] == 'PASS_MULTIFILE_GAP_SOURCE'
                            require_source_diagnostics(Path(str(prefix) + '.log').read_text(),
                                (case / 'gdb-reference.log').read_text(), target)
                            source_observations.append(source_result)
                    artifacts.append({'state': state, 'compression': compression, 'sha256': digest(artifact),
                        'spans': spans, 'sourceObservations': source_observations, 'generationSha256': hashes})
                run(read + [case / (state + '-after.json')], case / (state + '-read.log'))
                assert (case / (state + '-after.json')).read_bytes() == (case / (state + '-before.json')).read_bytes()
                assert before == snapshot(project)
            assert protected == {path: digest(Path(path)) for path in protected}
            results.append({'target': target, 'role': role, 'exports': 12 if args.source_lines else 8,
                'gapPosition': args.gap_position,
                'gdbSessions': 15 if args.source_lines else 7, 'sourceLines': args.source_lines, 'gap': [first, after],
                'artifacts': artifacts, 'protectedSha256': protected})
            print(target, role, 'discontiguous unwind PASS', flush=True)
    assert results
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_DISCONTIGUOUS_UNWIND', 'cases': results}, indent=4) + '\n')


if __name__ == '__main__':
    main()
