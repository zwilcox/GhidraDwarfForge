#!/usr/bin/env python3
"""Compare explicitly conditioned real exports with unchanged compiler/GDB references."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import runpy
import sys
import zlib

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'unwind-export.py'))
run, digest, metadata, decode, check_description = (
    helpers[name] for name in ('run', 'digest', 'metadata', 'decode', 'check_unwind_description'))


def comparable(record):
    result = copy.deepcopy({key: record[key] for key in ('frames', 'instructionTrace', 'complete', 'exitcode')})
    for stack in [result['frames'], *result['instructionTrace']]:
        for frame in stack:
            frame['pc'] -= record['checkpointAddress']
    return result


def boundaries(target, symbols, original, prefix):
    run(['bash', SCRIPTS / 'synthetic-cfi-reference-gdb.sh', target, 'compiler', symbols, original, prefix],
        Path(str(prefix) + '-command.log'), {'FORGE_CFI_ALL_BOUNDARIES': '1'})
    data = json.loads(Path(str(prefix) + '.json').read_text())
    log = Path(str(prefix) + '.log').read_text()
    blocks = re.findall(r'(?ms)^FORGE_BOUNDARY_BEGIN (\d+)\n(.*?)^FORGE_BOUNDARY_END \1\n', log)
    assert len(blocks) == len(data['trace']) and data['maxDepth'] == 8
    for index, (recorded, block) in enumerate(blocks):
        assert int(recorded) == index
        selected = set(map(int, re.findall(r'level=(\d+),type=NORMAL_FRAME,unwinder="dwarf2",pc=0x[0-9a-f]+', block)))
        assert set(range(len(data['trace'][index]) - 1)) <= selected, (target, index, selected)
    assert 'Traceback' not in log
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', choices=('x86_64', 'aarch64', 'all'), default='all')
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--libdwarf', required=True, type=Path)
    parser.add_argument('--libdwarfp', required=True, type=Path)
    parser.add_argument('--dwarfdump', required=True)
    args = parser.parse_args()
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    protected = {str(path.resolve()): digest(path) for path in (
        args.libdwarf, args.libdwarfp,
        args.ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar',
        ROOT / 'src/test/fixtures/synthetic-cfi.c',
        SCRIPTS / 'synthetic-cfi-reference-gdb.py',
        SCRIPTS / 'synthetic-cfi-reference-gdb.sh',
        SCRIPTS / 'compiler-cfi-boundaries-gdb.py',
        SCRIPTS / 'ghidra_scripts/ExportRecoveredFrames.java',
        SCRIPTS / 'ghidra_scripts/RecoveredFrameExportControls.java')}
    results = []
    for target in ('x86_64', 'aarch64'):
        if args.target not in ('all', target):
            continue
        case = work / target; case.mkdir()
        reference_dir = case / 'compiler'
        run([sys.executable, SCRIPTS / 'synthetic-cfi-reference.py', target, reference_dir,
            '--dwarfdump', args.dwarfdump], case / 'reference.log')
        reference_result = json.loads((reference_dir / 'result.json').read_text())
        assert reference_result['status'] == 'PASS_COMPILER_REFERENCE'
        original = reference_dir / 'without-cfi'
        reference = reference_dir / 'reference'
        protected.update({str(p): digest(p) for p in (original, reference)})
        boundary_reference = boundaries(target, reference, original, case / 'boundaries-reference')
        symbols = run(['readelf', '-sW', original], case / 'symbols.log')
        candidates = re.findall(r'(?m)^\s*\d+:\s*([0-9a-f]+)\s+(\d+)\s+OBJECT\s+GLOBAL\s+DEFAULT\s+\d+\s+cfi_sink$', symbols)
        assert len(candidates) == 1, candidates
        first, size = int(candidates[0][0], 16), int(candidates[0][1])
        assert size == 8
        last = first + size - 1
        # Symbol location supplies only the range. Disjointness from the live
        # stack is an explicitly external test condition, not an ELF inference.
        condition = f'{first:x}:{last:x}'
        project = case / 'project'; project.mkdir()
        outputs = case / 'outputs'; outputs.mkdir()
        text = run([args.ghidra.resolve() / 'support/analyzeHeadless', project, 'CompilerFrames',
            '-import', original, '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript',
            'RecoveredFrameExportControls.java', args.libdwarf.resolve(), args.libdwarfp.resolve(),
            outputs, 'none', condition], case / 'export.log')
        assert 'native-frame-export-controls=PASS successful=9 controls=4' in text
        assert text.count('native-frame-export=PASS ') == 9
        assert text.count('native-frame-staging-control=PASS ') == 4
        assert re.findall(r'native-frame-export=PASS frames=(\d+)', text) == ['4'] * 9
        deltas = list(map(int, re.findall(r'native-frame-export=PASS .* delta=(\d+)', text)))
        assert deltas == [deltas[0]] * 4 + [deltas[0] + 0x400000] * 5
        artifacts = []
        baseline = None
        for variant in ('none', 'zlib', 'before-rebase-none', 'before-rebase-zlib'):
            artifact = outputs / (variant + '.dbg')
            section, = [s for s in metadata(artifact)['sections'] if s['name'] == '.debug_frame']
            raw = artifact.read_bytes()[section['offset']:section['offset'] + section['size']]
            if variant.endswith('zlib'):
                assert section['flags'] & 0x800 and int.from_bytes(raw[:4], 'little') == 1
                size = int.from_bytes(raw[8:16], 'little')
                raw = zlib.decompress(raw[24:]); assert len(raw) == size
            else:
                assert not section['flags'] & 0x800
            frames = decode(raw, 8, 'little')
            assert len(frames) == 4
            if baseline is None: baseline = frames
            assert frames == baseline, 'rebase/compression changed generated frame rules'
            (case / (variant + '.frame')).write_bytes(raw)
            description_path = Path(str(artifact) + '.unwind.json')
            description = check_description(description_path, artifact, original, frames)
            evidence = json.loads(description_path.read_text())
            separation = evidence['stackSeparation']
            assert separation == {
                'status': 'EXTERNAL_CONDITION_NOT_PROVED',
                'basis': 'Explicit test assumption: this ELF range never overlaps live stack storage of this call group or its callers',
                'addressDomain': 'original ELF virtual address; apply runtime image load bias',
                'ranges': [{'first': hex(first), 'last': hex(last)}]}, separation
            assert evidence['memoryPolicy'].startswith('explicitly conditioned ')
            assert len(evidence['verifiedFunctions']) == 4
            assert int(evidence['databaseRebaseDelta'], 16) == deltas[0 if variant.startswith('before-') else -1]
            text = run(['readelf', '-h', '-S', '-n', '--debug-dump=info,abbrev,aranges,decodedline,frames', artifact],
                case / (variant + '-gnu.log'))
            assert 'warning:' not in text.lower() and 'error:' not in text.lower()
            run(['llvm-dwarfdump', '--verify', artifact], case / (variant + '-llvm.log'))
            run([sys.executable, SCRIPTS / 'check-dwarfdump.py', artifact, case / (variant + '-strict.log'),
                '--tool', args.dwarfdump, '--original', original], case / (variant + '-strict-command.log'))
            prefix = case / ('gdb-' + variant)
            # Use the unchanged compiler oracle and complete positive assertions.
            run(['bash', SCRIPTS / 'synthetic-cfi-reference-gdb.sh', target, 'compiler', artifact, original, prefix],
                case / ('gdb-' + variant + '-command.log'))
            observed = json.loads(Path(str(prefix) + '.json').read_text())
            assert comparable(observed) == comparable(reference_result['modes']['compiler']), (target, variant)
            log = Path(str(prefix) + '.log').read_text()
            selected = sorted(set(int(level) for level in re.findall(
                r'level=(\d+),type=NORMAL_FRAME,unwinder="dwarf2",pc=0x[0-9a-f]+', log)))
            assert set(range(7)) <= set(selected), (target, variant, selected)
            warnings = [line for line in log.splitlines() if 'warning:' in line.lower()]
            expected_warnings = reference_result['runtimeWarnings']['compiler']
            # Saved pre-rebase sidecars point at a source path updated by reruns.
            warnings = [line for line in warnings if not (variant.startswith('before-') and
                line == 'warning: Source file is more recent than executable.')]
            # QEMU's synthetic DSO address is allowed to vary, but no new warning.
            normalize = lambda lines: [re.sub(r'0x[0-9a-f]+', '<address>', line) for line in lines]
            assert normalize(warnings) == normalize(expected_warnings), warnings
            assert 'Traceback' not in log
            boundary_prefix = case / ('boundaries-' + variant)
            boundary_result = boundaries(target, artifact, original, boundary_prefix)
            assert boundary_result == boundary_reference, (target, variant, 'instruction boundary mismatch')
            boundary_warnings = [line for line in Path(str(boundary_prefix) + '.log').read_text().splitlines()
                if 'warning:' in line.lower()]
            boundary_warnings = [line for line in boundary_warnings if not (variant.startswith('before-') and
                line == 'warning: Source file is more recent than executable.')]
            assert normalize(boundary_warnings) == normalize(expected_warnings), boundary_warnings
            artifacts.append({'variant': variant, 'sha256': digest(artifact), 'evidence': description,
                'selectedDwarfLevels': selected, 'traceSnapshots': len(observed['instructionTrace']),
                'boundarySnapshots': len(boundary_result['trace']),
                'boundaryResultSha256': digest(Path(str(boundary_prefix) + '.json')),
                'gdbResultSha256': digest(Path(str(prefix) + '.json'))})
        disabled = case / 'gdb-disabled'
        run(['bash', SCRIPTS / 'synthetic-cfi-reference-gdb.sh', target, 'disabled', outputs / 'none.dbg', original, disabled],
            case / 'gdb-disabled-command.log')
        assert 'unwinder="dwarf2"' not in Path(str(disabled) + '.log').read_text()
        assert protected == {path: digest(Path(path)) for path in protected}
        results.append({'target': target, 'externalCondition': condition, 'exports': 9, 'failureControls': 4,
            'gdbSessions': 13, 'artifacts': artifacts, 'compilerReferenceResultSha256': digest(reference_dir / 'result.json')})
    report = {'status': 'PASS_CONDITIONED_COMPILER_EXPORT', 'cases': results, 'protectedSha256': protected,
        'scope': 'Explicit test condition; executed ordinary instruction-path compiler equivalence; no universal separation proof or CLI/GUI enablement'}
    (work / 'result.json').write_text(json.dumps(report, indent=4) + '\n')
    print('compiler-unwind-export=PASS cases=' + str(len(results)))


if __name__ == '__main__':
    main()
