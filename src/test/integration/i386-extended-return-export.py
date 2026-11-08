#!/usr/bin/env python3
"""Real libc i386 scalar arguments/returns with stripped, PIE and rebased exports."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
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
    parser.add_argument('--target', choices=('i386', 'x86_64'), default='i386',
        help='x86_64 is a global-layout and ordinary float/double regression only')
    parser.add_argument('--role', choices=('exec', 'sectionless', 'pie', 'pie-rebased'), default='exec')
    args = parser.parse_args()
    if args.target == 'x86_64' and args.role != 'exec':
        parser.error('the cross-target layout regression selects x86_64 exec')
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/i386-extended-return'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '-' + args.role + '.', dir=root))
    print(case, flush=True)
    commands = []

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        commands.append({'label': name, 'command': list(map(str, command))})
        write('commands.json', commands)
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/i386-extended-return.c'
    protected = [fixture, Path(__file__).resolve(), source / 'i386-extended-return-gdb.py',
        source / 'ghidra_scripts/PrepareI386ExtendedReturn.java',
        source / 'ghidra_scripts/CheckI386SourceView.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    reference, binary = case / 'profile.reference', case / 'profile.input'
    flags = ['-fno-pie', '-no-pie'] if args.role in ('exec', 'sectionless') else ['-fPIE', '-pie']
    compiler = shlex.split(os.environ.get('I386_CC', 'gcc -m32') if args.target == 'i386'
        else os.environ.get('X86_64_CC', 'gcc'))
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
    names = ('scalar_float', 'scalar_double', 'scalar_extended', 'source_helper',
        'extended_global', 'extended_array', 'extended_record')
    symbols = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in names:
            assert fields[2] not in symbols
            symbols[fields[2]] = int(fields[0], 16)
    assert len(symbols) == 7
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(symbols[name]) + '\n' for name in names))
    os.environ.update(I386_CASE=str(case), I386_VARIANT='compiler', I386_TARGET=args.target)
    run('compiler-gdb', ['gdb', '-q', '-nx', '-batch', '-x', source / 'i386-extended-return-gdb.py'])
    assert json.loads((case / 'compiler-gdb.json').read_text())['status'] == 'PASS'
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'I386', '-import', binary,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareI386ExtendedReturn.java', 'curate', case / 'labels.txt', case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    original_model = json.loads((case / 'import.json').read_text())
    assert Path(unquote(urlsplit(original_model['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    if args.role == 'pie-rebased':
        assert original_model['delta'] >= 0x2000000
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    if args.target == 'i386':
        run('source-controls', [ghidra / 'support/analyzeHeadless', project, 'I386', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'CheckI386SourceView.java', case / 'source-controls.json'], timeout=240)
        assert json.loads((case / 'source-controls.json').read_text())['status'] == 'PASS'
    hashes = None
    for phase in ('first', 'repeat'):
        run(phase, [ghidra / 'support/analyzeHeadless', project, 'I386', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareI386ExtendedReturn.java', 'observe', case / 'labels.txt', case / (phase + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'profile.dbg')], timeout=240)
        log = (case / (phase + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in log
        if args.target == 'i386':
            assert 'Corrected computed extended floating-return parameter allocation for scalar_extended' in log
            assert 'Applied validated allocation to read-only decompiler input for scalar_extended' in log
            assert 'Applied validated allocation to read-only decompiler input for source_helper' in log
            assert 'Corrected computed floating-return storage for analyst call override at' in log
            code = (case / 'profile.dbg.c').read_text()
            assert 'longdouble scalar_extended(longdouble a,longdouble b)' in code
            assert 'longdouble source_helper(longdouble value)' in code
            assert '__return_storage_ptr__' not in code
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
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict.txt'),
            '--original', case / 'profile.sectioned' if variant == 'compiler' and args.role == 'sectionless' else binary,
            *(['--frame-reference', case / 'profile.sectioned'] if args.role == 'sectionless' and variant == 'forge' else [])])
    info = (case / 'forge-info.log').read_text()
    if args.target == 'i386':
        assert '__return_storage_ptr__' not in info.split('scalar_extended', 1)[1].split('DW_TAG_subprogram', 1)[0]
    os.environ['I386_VARIANT'] = 'forge'
    run('forge-gdb', ['gdb', '-q', '-nx', '-batch', '-x', source / 'i386-extended-return-gdb.py'])
    runtime = json.loads((case / 'forge-gdb.json').read_text())
    assert runtime['status'] == 'PASS' and len(runtime['rows']) == (3 if args.target == 'i386' else 2)
    assert all(support.digest(Path(p)) == value for p, value in before.items())
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changed = sorted(p for p in project_before.keys() | project_after.keys()
        if project_before.get(p) != project_after.get(p))
    # Ghidra removes these index/journal backups on the first read-only reopen.
    # Compare all persistent program files and record the exact housekeeping changes.
    assert set(changed) <= {'I386.rep/idata/~index.bak', 'I386.rep/idata/~journal.bak'}, changed
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role, 'artifactHashes': hashes,
        'runtime': runtime, 'persistentProgramUnchanged': True, 'projectHousekeepingChanges': changed,
        'originalsUnchanged': True})


if __name__ == '__main__':
    main()
