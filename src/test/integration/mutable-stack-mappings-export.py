#!/usr/bin/env python3
"""Validate saved stack identities through explicit assignments, saves and reloads."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import re
import struct
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('support', source.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=('x86_64', 'aarch64'))
    parser.add_argument('--width', type=int, choices=(32, 64), required=True)
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    parser.add_argument('--previous-ghidra', type=Path)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/mutable-stack-mappings'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=f'{args.target}.{args.width}.{args.role}.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/mutable-stack-mappings.c'
    files = [fixture, Path(__file__), source / 'mutable-stack-mappings-gdb.py',
        source / 'mutable-stack-mappings-gdb.sh', source / 'check-mutable-stack-mappings.py',
        source / 'ghidra_scripts/PrepareMutableStackMappings.java', source / 'ghidra_scripts/RebaseFixtureProgram.java']
    files += [p for p in module.rglob('*') if p.is_file()]
    protected = {str(p): support.digest(p) for p in files}
    write('protected-before.json', protected)
    cc, objcopy = ('gcc', 'objcopy') if args.target == 'x86_64' else ('aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-objcopy')
    reference, binary = case / 'local.reference', case / 'local.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    if args.target == 'x86_64':
        flags.append('-fcf-protection=none')
    run('compile', [cc, '-O2', '-g3', '-gdwarf-5', '-gno-variable-location-views', '-fno-stack-protector',
        '-fno-ipa-icf', f'-DFORGE_STACK_LOCAL_BITS={args.width}', *flags, '-Wl,--build-id=sha1', fixture, '-o', reference])
    run('strip', [objcopy, '--strip-all', reference, binary])
    protected.update({str(p): support.digest(p) for p in (reference, binary)})
    write('protected-before.json', protected)
    run('symbols', ['readelf', '-sW', reference])
    names = ['mutable_saved', 'mutable_unsaved', 'mutable_branch', 'mutable_loop', 'mutable_conflict']
    symbols, functions = {}, {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and (fields[7].startswith('mutable_') or fields[7] in ('effect_sink', 'backup_sink', 'path_choice', 'navigation_control')):
            assert fields[7] not in symbols
            symbols[fields[7]] = int(fields[1], 16)
            if fields[3] == 'FUNC':
                functions[fields[7]] = {'entry': int(fields[1], 16), 'end': int(fields[1], 16) + int(fields[2])}
    assert set(functions) == {*names, 'navigation_control'}
    for name in names:
        row = functions[name]
        row.update({marker: symbols[name + '_' + marker] for marker in ('before', 'live', 'load', 'loaded', 'update', 'updated', 'changed', 'save', 'saved', 'kill', 'killed', 'reload', 'reloaded', 'lost')})
        keys = ['entry', 'before', 'live', 'load', 'loaded', 'update', 'updated', 'changed', 'save', 'saved', 'kill', 'killed', 'reload', 'reloaded', 'lost', 'end']
        assert all(row[a] < row[b] for a, b in zip(keys, keys[1:])), row
        row['availableEnd'] = row['killed'] if name == 'mutable_unsaved' else row['lost']
    initial = -1985229329 if args.width == 32 else -81985529216486895
    labels = {'functions': functions, 'order': ['mutable_saved', 'mutable_unsaved', 'mutable_branch', 'mutable_branch', 'mutable_loop', 'mutable_loop', 'mutable_conflict'], 'width': args.width // 8, 'initial': initial,
        'effect_sink': symbols['effect_sink'], 'backup_sink': symbols['backup_sink'], 'path_choice': symbols['path_choice']}
    write('labels.json', labels)
    os.environ['LOCAL_VARIANTS'] = 'compiler'
    run('compiler-driver', ['bash', source / 'mutable-stack-mappings-gdb.sh', repository, case, args.target], timeout=240)
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Effects', '-import', binary, '-loader', 'ElfLoader',
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareMutableStackMappings.java', case / 'labels.json', case / 'compiler-storage.json', case / 'prepared.json'], timeout=240)
    assert 'mutable-stack-mappings-preparation=PASS' in (case / 'import.log').read_text()
    if args.role == 'pie-rebased':
        assert ' by 0x2000000' in (case / 'import.log').read_text()
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.append(('previous', args.previous_ghidra.resolve(strict=True)))
    artifacts = []
    for variant, installation in variants:
        output = case / ('previous.dbg' if variant == 'previous' else 'local.dbg')
        run(variant, [installation / 'support/analyzeHeadless', project, 'Effects', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareMutableStackMappings.java', case / 'labels.json', case / 'compiler-storage.json', case / (variant + '.json'), 'observe',
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], timeout=240)
        log = (case / (variant + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in log
        origin, = re.findall(r'mutable-stack-mappings-origin=(\S+)', log)
        assert Path(unquote(urlsplit(origin).path)).resolve() == (installation / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar').resolve()
        java_version, = re.findall(r'mutable-stack-mappings-java=(\S+)', log)
        assert int(java_version.split('.')[0]) >= 21
        assert json.loads((case / (variant + '.json')).read_text()) == json.loads((case / 'prepared.json').read_text())
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert report['failure'] is None and not report['failedFunctions']
        write(variant + '-report.json', report)
        if variant == 'fixed':
            for suffix in ('', '.c'):
                shutil.copyfile(Path(str(output) + suffix), case / ('first.dbg' + suffix))
        if variant == 'repeat':
            for suffix in ('', '.c'):
                assert Path(str(output) + suffix).read_bytes() == (case / ('first.dbg' + suffix)).read_bytes()
        else:
            artifacts.append((variant, output))
    for variant, artifact in [('compiler', reference), *artifacts]:
        for dump in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + dump, ['readelf', '--debug-dump=' + dump, artifact])
        for view, flag in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + view, ['readelf', flag, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        if variant != 'compiler':
            target_data, sidecar_data = binary.read_bytes(), artifact.read_bytes()
            assert target_data[:24] == sidecar_data[:24] and target_data[48:52] == sidecar_data[48:52]
            assert struct.unpack_from('<Q', sidecar_data, 32)[0] == 0 and struct.unpack_from('<HH', sidecar_data, 54) == (0, 0)
            original_id, = re.findall(r'Build ID: ([0-9a-f]+)', (case / 'compiler-notes.log').read_text())
            assert re.findall(r'Build ID: ([0-9a-f]+)', (case / (variant + '-notes.log')).read_text()) == [original_id]
            run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact,
                case / (variant + '-strict-checks.log'), '--original', binary])
    run('locations', ['python3', source / 'check-mutable-stack-mappings.py', case, args.target])
    os.environ['LOCAL_VARIANTS'] = 'forge previous' if args.previous_ghidra else 'forge'
    run('gdb-driver', ['bash', source / 'mutable-stack-mappings-gdb.sh', repository, case, args.target], timeout=240)
    after = {name: support.digest(Path(name)) for name in protected}
    write('protected-after.json', after)
    assert protected == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in project_before.keys() | project_after.keys() if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Effects.rep/idata/~index.bak', 'Effects.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'target': args.target, 'width': args.width, 'role': args.role,
        'jarSha256': support.digest(module / 'lib/GhidraDwarfForge.jar'), 'projectBackupChanges': changes,
        'artifactSha256': [support.digest(case / name) for name in ('local.dbg', 'local.dbg.c')],
        'previousPackageCompared': bool(args.previous_ghidra)})
    print('mutable-stack-mappings-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
