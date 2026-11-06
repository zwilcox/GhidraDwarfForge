#!/usr/bin/env python3
"""Reject incomplete conditions, preemptible calls and unqualified pointer storage."""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import sys

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'unwind-export.py'))
run, digest = (helpers[key] for key in ('run', 'digest'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--libdwarf', required=True, type=Path)
    parser.add_argument('--libdwarfp', required=True, type=Path)
    parser.add_argument('--target', choices=('x86_64', 'aarch64', 'all'), default='all')
    args = parser.parse_args()
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'src/test/fixtures/synthetic-cfi.c'
    protected = {str(p.resolve()): digest(p) for p in (source, args.libdwarf, args.libdwarfp,
        args.ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar',
        SCRIPTS / 'ghidra_scripts/ExportRecoveredFrames.java', SCRIPTS / 'ghidra_scripts/RecoveredPointerRefusals.java')}
    results = []
    for target in ('x86_64', 'aarch64'):
        if args.target not in ('all', target): continue
        compiler = ('' if target == 'x86_64' else 'aarch64-linux-gnu-') + 'gcc'
        for role in ('bound', 'interposable', 'no-relro'):
            if role == 'no-relro' and target != 'aarch64': continue
            case = work / (target + '-' + role); case.mkdir()
            original = case / 'original'
            flags = ['-O1', '-fomit-frame-pointer', '-fno-optimize-sibling-calls',
                '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-nostdlib', '-fPIC', '-shared', '-Wl,--build-id=none']
            if role != 'interposable': flags += ['-Wl,-Bsymbolic']
            if role == 'no-relro': flags += ['-Wl,-z,norelro']
            run([compiler, *flags, source, '-o', original], case / 'build.log')
            before = digest(original)
            text = run(['readelf', '-sW', '-lW', '-rW', original], case / 'elf.log')
            matches = sorted(set(re.findall(r'(?m)^\s*\d+:\s*([0-9a-f]+)\s+8\s+OBJECT\s+GLOBAL\s+DEFAULT\s+\d+\s+cfi_sink$', text)))
            assert len(matches) == 1
            first = int(matches[0], 16); condition = f'{first:x}:{first+7:x}'
            extra = 'none' if role == 'bound' and target == 'x86_64' else (
                'omit-pointers' if role == 'bound' else 'unqualified-pointers')
            project = case / 'project'; project.mkdir()
            outputs = case / 'outputs'; outputs.mkdir()
            text = run([args.ghidra.resolve() / 'support/analyzeHeadless', project, 'PointerRefusals', '-import', original,
                '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript', 'RecoveredPointerRefusals.java',
                args.libdwarf.resolve(), args.libdwarfp.resolve(), outputs, condition, extra], case / 'export.log')
            count = 2 if extra == 'none' else 3
            assert f'pointer-refusal-controls=PASS count={count}' in text and text.count('pointer-refusal=PASS ') == count
            assert digest(original) == before and 'native-frame-export=PASS' not in text
            for name in ('previous.dbg', 'previous.dbg.c', 'previous.dbg.unwind.json'):
                assert (outputs / name).read_bytes() == b'previous complete generation\n'
            results.append({'target': target, 'role': role, 'refusals': count, 'originalSha256': before,
                'logSha256': digest(case / 'export.log')})
    assert protected == {p: digest(Path(p)) for p in protected}
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_POINTER_REFUSALS', 'cases': results,
        'protectedSha256': protected}, indent=4) + '\n')
    print('compiler-pointer-refusals=PASS cases=' + str(len(results)))


if __name__ == '__main__':
    main()
