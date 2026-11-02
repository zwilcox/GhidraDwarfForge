#!/usr/bin/env python3
"""Libc-backed i386 scalar/vector/aggregate and explicit convention export contract."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import struct
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('support', source.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--role', choices=('exec', 'sectionless', 'pie', 'pie-rebased'), default='exec')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/i386-abi-matrix'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.role + '.', dir=root))
    print(case, flush=True)
    commands = []

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        commands.append({'label': name, 'command': list(map(str, command))})
        write('commands.json', commands)
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name == 'gdb':
            output = (case / (name + '.log')).read_text()
            errors = (case / (name + '.stderr')).read_text()
            expected = {'vector_add', 'sse_parameters', 'register_parameters', 'stdcall_parameters',
                'fastcall_parameters', 'thiscall_parameters'} if name == 'forge-gdb' else set()
            pattern = r"(?m)^warning: Function '([a-z_]+)' does not follow the target calling convention, cannot determine its returned value\.\n"
            found = re.findall(pattern, output + errors)
            assert len(found) == len(expected) and set(found) == expected, (name, found)
            cleaned = re.sub(pattern, '', output)
            clean_errors = re.sub(pattern, '', errors)
            assert not clean_errors.strip() and not re.search(r'(?im)\b(?:warning|error):', cleaned), name
        elif Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/i386-abi-matrix.c'
    protected = [fixture, Path(__file__).resolve(), source / 'i386-abi-matrix-gdb.py',
        source / 'i386-abi-matrix-controls.py', source / 'i386-abi-matrix-negative.py',
        source / 'ghidra_scripts/PrepareI386AbiMatrix.java',
        source / 'ghidra_scripts/AbiDecompilerFailureExport.java', source / 'ghidra_scripts/CancelDuringElfCopy.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    reference, binary = case / 'profile.reference', case / 'profile.input'
    flags = ['-fno-pie', '-no-pie'] if args.role in ('exec', 'sectionless') else ['-fPIE', '-pie']
    compiler = shlex.split(os.environ.get('I386_CC', 'gcc -m32'))
    run('compile', [*compiler, '-O1', '-g', '-gdwarf-5', '-fno-builtin', '-msse2', '-mfpmath=sse',
        '-Wall', '-Wextra', '-Werror', *flags, '-Wl,--build-id=sha1', fixture, '-o', reference])
    run('compiler-runtime', [reference])
    run('strip', ['objcopy', '--strip-all', reference, binary])
    if args.role == 'sectionless':
        (case / 'profile.sectioned').write_bytes(binary.read_bytes())
        before[str(case / 'profile.sectioned')] = support.digest(case / 'profile.sectioned')
        raw = bytearray(binary.read_bytes())
        assert raw[:6] == b'\x7fELF\x01\x01'
        struct.pack_into('<I', raw, 32, 0)
        struct.pack_into('<3H', raw, 46, 0, 0, 0)
        binary.write_bytes(raw)
    run('stripped-runtime', [binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    run('symbols', ['nm', '-n', reference])
    names = ('scalar_float', 'scalar_double', 'scalar_extended', 'vector_add', 'pair_return', 'mixed_return',
        'sse_parameters', 'register_parameters', 'stdcall_parameters', 'fastcall_parameters', 'thiscall_parameters')
    symbols = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in names:
            assert fields[2] not in symbols
            symbols[fields[2]] = int(fields[0], 16)
    assert len(symbols) == 11
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(symbols[name]) + '\n' for name in names))
    os.environ.update(I386_CASE=str(case), I386_VARIANT='compiler')
    run('compiler-gdb', ['gdb', '-q', '-nx', '-batch', '-x', source / 'i386-abi-matrix-gdb.py'])
    assert json.loads((case / 'compiler-gdb.json').read_text())['status'] == 'PASS'
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'I386', '-import', binary,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareI386AbiMatrix.java', 'curate', case / 'labels.txt', case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    original_model = json.loads((case / 'import.json').read_text())
    assert Path(unquote(urlsplit(original_model['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    if args.role == 'pie-rebased':
        assert original_model['delta'] >= 0x2000000
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    hashes = None
    for phase in ('first', 'repeat'):
        run(phase, [ghidra / 'support/analyzeHeadless', project, 'I386', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareI386AbiMatrix.java', 'observe', case / 'labels.txt', case / (phase + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'profile.dbg')], timeout=240)
        assert 'GhidraDwarfForge symbol export PASS' in (case / (phase + '.log')).read_text()
        assert json.loads((case / (phase + '.json')).read_text()) == original_model
        current = [support.digest(case / name) for name in ('profile.dbg', 'profile.dbg.c')]
        if hashes is not None:
            assert hashes == current
        hashes = current
    for variant, artifact in [('compiler', reference), ('forge', case / 'profile.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact, case / (variant + '-strict.txt'),
            '--original', case / 'profile.sectioned' if variant == 'compiler' and args.role == 'sectionless' else binary,
            *(['--frame-reference', case / 'profile.sectioned'] if variant == 'forge' and args.role == 'sectionless' else [])])
    os.environ['I386_VARIANT'] = 'forge'
    run('forge-gdb', ['gdb', '-q', '-nx', '-batch', '-x', source / 'i386-abi-matrix-gdb.py'])
    runtime = json.loads((case / 'forge-gdb.json').read_text())
    assert runtime['status'] == 'PASS' and len(runtime['rows']) == 11
    assert all(support.digest(Path(p)) == value for p, value in before.items())
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changed = sorted(p for p in project_before.keys() | project_after.keys() if project_before.get(p) != project_after.get(p))
    assert set(changed) <= {'I386.rep/idata/~index.bak', 'I386.rep/idata/~journal.bak'}, changed
    result = {'status': 'CONTROLS_PENDING', 'role': args.role, 'artifactHashes': hashes, 'runtime': runtime,
        'persistentProgramUnchanged': True, 'projectHousekeepingChanges': changed, 'originalsUnchanged': True}
    write('result.json', result)
    run('negative-controls', ['python3', source / 'i386-abi-matrix-negative.py', case], timeout=240)
    run('failure-controls', ['python3', source / 'i386-abi-matrix-controls.py', ghidra, case], timeout=600)
    assert all(support.digest(Path(p)) == value for p, value in before.items())
    result['status'] = 'PASS'
    write('result.json', result)


if __name__ == '__main__':
    main()
