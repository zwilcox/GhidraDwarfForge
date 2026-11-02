#!/usr/bin/env python3
"""Reproduce natural ARM aggregate coverage; unresolved Forge observations fail.

This driver deliberately retains the strict full-availability research oracle.
It is not yet a passing pipeline lane or a broad aggregate-support claim.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree(path):
    return {str(p.relative_to(path)): digest(p) for p in path.rglob('*') if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--order', choices=('little', 'big'), required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--gdb', type=Path, required=True)
    parser.add_argument('--gdb-data', type=Path, required=True)
    parser.add_argument('--results-root', type=Path, default=repository / 'build/test-results/arm-stack-aggregates')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    output = args.results_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.order + '.', dir=output))
    print(case, flush=True)
    facts = load('aggregate_elf', source / 'arm-thumb-mode-check.py')
    vdso = load('aggregate_vdso', source / 'arm-pcs-call-reference.py')
    compiler = os.environ.get('ARM32_CC', 'arm-linux-gnueabihf-gcc')
    objcopy = os.environ.get('ARM32_OBJCOPY', 'arm-linux-gnueabihf-objcopy')
    fixture = repository / 'src/test/fixtures/arm-stack-aggregates.c'
    startup = repository / 'src/test/fixtures/arm-pcs-start.S'
    protected = [Path(__file__), fixture, startup, source / 'arm-stack-aggregates-gdb.py',
        source / 'arm-stack-aggregates-reference.py', source / 'arm-pcs-profile-runtime.sh',
        source / 'qemu-socket.sh', source / 'arm-thumb-mode-check.py', source / 'arm-pcs-call-reference.py',
        source / 'check-dwarfdump.py', source / 'ghidra_scripts/PrepareArmStackAggregates.java',
        Path(shutil.which(compiler)), Path(shutil.which(objcopy)), args.qemu, args.gdb]
    protected += [p for root in (module, args.gdb_data) for p in root.rglob('*') if p.is_file()]
    before = {str(p.resolve()): digest(p) for p in protected}
    commands = []
    java = subprocess.run([str(Path(os.environ['JAVA_HOME']) / 'bin/java'), '-Xshare:off', '-version'],
        capture_output=True, check=True)
    assert not java.stdout

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(label, command, environment=None):
        command = list(map(str, command))
        row = {'label': label, 'command': command, 'environment': environment or {}}
        commands.append(row)
        write('commands.json', commands)
        with (case / (label + '.log')).open('wb') as log, (case / (label + '.err')).open('wb') as err:
            result = subprocess.run(command, stdout=log, stderr=err, timeout=240,
                env={**os.environ, **(environment or {})})
        row['exit'] = result.returncode
        write('commands.json', commands)
        stderr = (case / (label + '.err')).read_bytes()
        if Path(command[0]).name == 'analyzeHeadless':
            assert stderr == java.stderr, (label, 'unexpected headless stderr')
            assert not re.search(r'(?m)^ERROR (?!GhidraDwarfForge.java> GhidraDwarfForge: )',
                (case / (label + '.log')).read_text()), label
        else:
            assert not stderr, (label, 'unexpected stderr')
        assert result.returncode == 0, (case, label, result.returncode)
        return result.returncode

    write('profile.json', {'order': args.order, 'role': 'exec', 'ghidra': str(ghidra),
        'qemu': str(args.qemu.resolve()), 'gdb': str(args.gdb.resolve()), 'gdbData': str(args.gdb_data.resolve()),
        'compilerReferenceCalibration': 'exact live-carrier windows', 'forgeOracle': 'strict full availability'})
    flags = ['-marm', '-march=armv7-a', '-mfpu=vfpv3-d16', '-mfloat-abi=hard', '-O1',
        '-g3', '-gdwarf-5', '-gno-variable-location-views', '-fno-omit-frame-pointer',
        '-fno-inline', '-fno-ipa-sra', '-fno-ipa-cp', '-nostdlib', '-nostartfiles', '-static',
        '-fno-pie', '-no-pie', '-Wl,--build-id=none', '-Wl,-e,_start',
        *(['-mbig-endian', '-Wl,--be8'] if args.order == 'big' else [])]
    run('startup', [compiler, *flags, '-c', startup, '-o', case / 'start.o'])
    command = [compiler, *flags, case / 'start.o', fixture]
    run('compile', [*command, '-o', case / 'calls.reference'])
    run('rebuild', [*command, '-o', case / 'calls.repeat'])
    assert (case / 'calls.reference').read_bytes() == (case / 'calls.repeat').read_bytes()
    run('strip', [objcopy, '--strip-all', case / 'calls.reference', case / 'calls.input'])
    original = facts.elf(case / 'calls.input', allow_big_endian=True)
    compiler_elf = facts.elf(case / 'calls.reference', allow_big_endian=True)
    assert not original['symbols'], 'fixture must be completely stripped'
    kinds = ('pair', 'aligned', 'packed', 'bytes', 'words', 'mixed', 'floats')
    names = [pcs + '_' + kind for pcs in ('base', 'vfp') for kind in kinds]
    required = names + [name + '_observe' for name in names] + [prefix + kind
        for prefix in ('input_', 'seen_') for kind in kinds]
    labels, inventory = {}, {}
    for name in required:
        symbol, = [row for row in compiler_elf['symbols'] if row['name'] == name]
        labels[name] = symbol['raw']
        if name in names:
            assert symbol['info'] & 15 == 2 and symbol['size'] > 0 and symbol['raw'] % 4 == 0
            section = compiler_elf['sections'][symbol['section']]
            offset = symbol['raw'] - section['row'][3]
            code = section['data'][offset:offset + symbol['size']]
            assert len(code) == symbol['size'] and len(code) % 4 == 0
            inventory[name] = {'entry': symbol['raw'], 'size': symbol['size'], 'code': code.hex()}
    for name in names:
        observe = labels[name + '_observe']
        assert labels[name] < observe < labels[name] + inventory[name]['size'] and observe % 4 == 0
        inventory[name]['observeOffset'] = observe - labels[name]
    write('instruction-inventory.json', inventory)
    write('labels.json', labels)
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(address) + '\n' for name, address in labels.items()))
    for leaf in ('calls.input', 'calls.reference'):
        before[str(case / leaf)] = digest(case / leaf)
    write('protected-before.json', before)
    runtime = ['bash', source / 'arm-pcs-profile-runtime.sh', case]
    runtime_tail = [args.qemu, args.gdb, args.gdb_data, source / 'arm-stack-aggregates-gdb.py']
    run('compiler-runtime', [*runtime, 'compiler', *runtime_tail], {'FORGE_STACK_REFERENCE_CALIBRATION': '1'})
    project = case / 'project'
    project.mkdir()
    headless = ghidra / 'support/analyzeHeadless'
    run('import', [headless, project, 'Stack', '-import', case / 'calls.input', '-loader', 'ElfLoader'])
    run('curate', [headless, project, 'Stack', '-process', 'calls.input', '-noanalysis',
        '-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareArmStackAggregates.java',
        'curate', case / 'labels.txt', case / 'curate.json'])
    project_before = tree(project)
    write('project-before.json', project_before)
    for phase in ('first', 'repeat'):
        run(phase, [headless, project, 'Stack', '-process', 'calls.input', '-noanalysis', '-readOnly',
            '-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareArmStackAggregates.java',
            'inspect', case / 'labels.txt', case / (phase + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'calls.dbg')])
        assert 'GhidraDwarfForge symbol export PASS' in (case / (phase + '.log')).read_text()
        if phase == 'first':
            for leaf in ('calls.dbg', 'calls.dbg.c'):
                shutil.copy2(case / leaf, case / ('first-' + leaf))
    observation = json.loads((case / 'first.json').read_text())
    assert observation == json.loads((case / 'curate.json').read_text()) == json.loads((case / 'repeat.json').read_text())
    origin = urlsplit(observation['origin'])
    assert origin.scheme == 'file' and Path(unquote(origin.path)) == module / 'lib/GhidraDwarfForge.jar'
    for leaf in ('calls.dbg', 'calls.dbg.c'):
        assert (case / leaf).read_bytes() == (case / ('first-' + leaf)).read_bytes()
    for variant in ('reference', 'dbg'):
        for view, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n'), ('info', '--debug-dump=info'),
                ('abbrev', '--debug-dump=abbrev'), ('aranges', '--debug-dump=aranges'),
                ('line', '--debug-dump=decodedline'), ('loc', '--debug-dump=loc')]:
            run(variant + '-' + view, ['readelf', option, case / ('calls.' + variant)])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', case / ('calls.' + variant)])
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', case / ('calls.' + variant),
            case / (variant + '-strict.txt'), '--original', case / 'calls.input'])
    exported = facts.elf(case / 'calls.dbg', allow_big_endian=True)
    assert exported['data'][:16] == original['data'][:16]
    assert exported['header'][:4] == original['header'][:4] and exported['header'][6] == original['header'][6]
    assert exported['header'][4] == exported['header'][9] == 0
    assert facts.section(exported, '.text')['data'] == facts.section(original, '.text')['data']
    # Defer the final mismatch assertion until QEMU exit, diagnostics and all
    # preservation checks are collected. The driver still fails below.
    run('forge-runtime', [*runtime, 'forge', *runtime_tail], {'FORGE_STACK_REPORT_ONLY': '1'})
    results = {}
    for variant in ('compiler', 'forge'):
        result = json.loads((case / (variant + '-gdb.json')).read_text())
        assert len(result['entry']) == 14 and {row['name'] for row in result['entry']} == set(names)
        assert result['status'] in ('PASS', 'FORGE_MISMATCH'), result.get('error')
        for name in names:
            offsets = [row['offset'] for row in result['observations'] if row['name'] == name]
            assert offsets == list(range(0, inventory[name]['observeOffset'] + 1, 4)), name
        if variant == 'forge':
            assert not result['referenceWindows'] and not result['referenceMismatches']
        warnings = (case / (variant + '.stderr')).read_text().splitlines()
        assert len(warnings) <= 1
        for warning in warnings:
            assert warning == 'Failed to read a valid object file image from memory.' or re.fullmatch(
                r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', warning)
            vdso.corroborate_unmapped_vdso_sections(result)
        assert not (case / (variant + '.qemu.stderr')).read_bytes()
        assert (case / (variant + '.qemu.status')).read_text() == 'exit=0\n'
        results[variant] = result
    project_after = tree(project)
    assert project_before == project_after
    write('project-after.json', project_after)
    assert before == {path: digest(Path(path)) for path in before}
    write('result.json', {'status': results['forge']['status'], 'order': args.order,
        'compilerObservations': len(results['compiler']['observations']),
        'forgeObservations': len(results['forge']['observations']),
        'referenceMismatchesRetained': len(results['compiler']['referenceMismatches']),
        'unavailable': sum('error' in row for row in results['forge']['mismatches']),
        'incorrect': [row for row in results['forge']['mismatches'] if 'actual' in row],
        'deterministic': True, 'protectedFilesUnchanged': True, 'savedProjectUnchanged': True})
    assert results['forge']['status'] == 'PASS', 'unresolved aggregate observations: ' + str(case)
    print('PASS_ARM_STACK_AGGREGATES', flush=True)


if __name__ == '__main__':
    main()
