#!/usr/bin/env python3
"""Real packaged immutable HFA lifetimes, independent compiler/raw references and preservation."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--order', choices=('little', 'big'), required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--gdb', type=Path, required=True)
    parser.add_argument('--gdb-data', type=Path, required=True)
    controls = load('hfa_controls', source / 'arm_hfa_control_oracle.py')
    parser.add_argument('--control', choices=tuple(controls.CONTROL_IDS))
    parser.add_argument('--storage', choices=('hfa', 'base', 'mixed'), default='hfa')
    args = parser.parse_args()
    if args.storage != 'hfa' and not args.control:
        parser.error('--storage requires --control')
    module = args.ghidra.resolve(strict=True) / 'Ghidra/Extensions/GhidraDwarfForge'
    output = repository / 'build/test-results/arm-hfa-lifetimes'
    output.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.order + '.' + args.storage + '.' + (args.control + '.' if args.control else ''), dir=output))
    print(case, flush=True)
    facts = load('hfa_elf', source / 'arm-thumb-mode-check.py')
    reference = load('hfa_reference', source / 'arm-pcs-call-reference.py')
    compiler = os.environ.get('ARM32_CC', 'arm-linux-gnueabihf-gcc')
    objcopy = os.environ.get('ARM32_OBJCOPY', 'arm-linux-gnueabihf-objcopy')
    protected = [Path(__file__), source / 'arm-hfa-lifetimes-gdb.py', source / 'arm-pcs-profile-runtime.sh',
        source / 'qemu-socket.sh', source / 'arm-thumb-mode-check.py', source / 'arm-pcs-call-reference.py',
        source / 'check-dwarfdump.py', source / 'ghidra_scripts/PrepareArmHfaLifetimes.java',
        repository / 'src/test/fixtures/arm-hfa-lifetimes.c', repository / 'src/test/fixtures/arm-pcs-start.S',
        Path(shutil.which(compiler)), Path(shutil.which(objcopy)), args.qemu, args.gdb]
    protected += [p for root in (module, args.gdb_data) for p in root.rglob('*') if p.is_file()]
    if args.control:
        protected += [source / 'arm-hfa-controls-gdb.py', source / 'arm_hfa_control_oracle.py',
            source / 'ghidra_scripts/PrepareArmHfaControls.java',
            repository / 'src/test/fixtures/arm-hfa-controls.c', repository / 'src/test/fixtures/arm-hfa-controls.S']
    else:
        protected.append(source / 'arm_hfa_control_oracle.py')
    before = {str(p): digest(p) for p in protected}
    runtime_script = source / ('arm-hfa-controls-gdb.py' if args.control else 'arm-hfa-lifetimes-gdb.py')
    prepare_script = 'PrepareArmHfaControls.java' if args.control else 'PrepareArmHfaLifetimes.java'
    commands = []
    java = subprocess.run([str(Path(os.environ['JAVA_HOME']) / 'bin/java'), '-Xshare:off', '-version'],
        capture_output=True, check=True)
    assert not java.stdout

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'command': command})
        write('commands.json', commands)
        with (case / (label + '.log')).open('wb') as log, (case / (label + '.err')).open('wb') as err:
            result = subprocess.run(command, stdout=log, stderr=err, timeout=180)
        assert result.returncode == 0, (case, label, result.returncode)
        stderr = (case / (label + '.err')).read_bytes()
        if Path(command[0]).name == 'analyzeHeadless':
            assert stderr == java.stderr, (label, 'unexpected headless stderr')
            assert not re.search(r'(?m)^ERROR (?!GhidraDwarfForge.java> GhidraDwarfForge: )',
                (case / (label + '.log')).read_text()), label
        else:
            assert not stderr, (label, 'unexpected stderr')

    write('profile.json', {'order': args.order, 'control': args.control, 'storage': args.storage})
    flags = ['-marm', '-march=armv7-a', '-mfpu=vfpv3-d16', '-mfloat-abi=hard', '-O0', '-g3', '-gdwarf-5',
        '-fno-omit-frame-pointer', '-nostdlib', '-nostartfiles', '-static', '-fno-pie', '-no-pie',
        '-Wl,--build-id=none', '-Wl,-e,_start', *(['-mbig-endian', '-Wl,--be8'] if args.order == 'big' else [])]
    run('startup', [compiler, *flags, '-c', repository / 'src/test/fixtures/arm-pcs-start.S', '-o', case / 'start.o'])
    objects = [case / 'start.o']
    if args.control:
        flags += ['-DFORGE_HFA_CONTROL=' + str(controls.CONTROL_IDS[args.control]),
            '-DFORGE_HFA_ALIAS=' + str(int(args.control == 'unknown-alias')),
            '-DFORGE_CORE_STORAGE=' + str(int(args.storage != 'hfa')),
            '-DFORGE_BASE_PCS=' + str(int(args.storage == 'base')),
            '-DFORGE_MIXED=' + str(int(args.storage == 'mixed'))]
        run('control-assembly', [compiler, *flags, '-c', repository / 'src/test/fixtures/arm-hfa-controls.S',
            '-o', case / 'control.o'])
        objects.append(case / 'control.o')
    fixture = 'arm-hfa-controls.c' if args.control else 'arm-hfa-lifetimes.c'
    command = [compiler, *flags, *objects, repository / 'src/test/fixtures' / fixture]
    run('compile', [*command, '-o', case / 'calls.reference'])
    run('rebuild', [*command, '-o', case / 'calls.repeat'])
    assert (case / 'calls.reference').read_bytes() == (case / 'calls.repeat').read_bytes()
    run('strip', [objcopy, '--strip-all', case / 'calls.reference', case / 'calls.input'])
    original = facts.elf(case / 'calls.input', allow_big_endian=True)
    compiler_elf = facts.elf(case / 'calls.reference', allow_big_endian=True)
    expected_words = {
        'sum_floats': 'e52db004 e28db000 e24dd00c eeb07a40 eef07a60 ed0b7a03 ed4b7a02 ed1b7a03 ed5b7a02 ee777a27 eeb00a67 e28bd000 e49db004 e12fff1e',
        'sum_doubles': 'e52db004 e28db000 e24dd014 eeb06b40 eeb07b41 ed0b6b05 ed0b7b03 ed1b6b05 ed1b7b03 ee367b07 eeb00b47 e28bd000 e49db004 e12fff1e'}
    if args.control:
        expected_words = {'hfa_control': ' '.join(controls.instruction_words(args.control, args.storage))}
    labels = {}
    for name, words in expected_words.items():
        symbol, = [row for row in compiler_elf['symbols'] if row['name'] == name]
        section = compiler_elf['sections'][symbol['section']]
        offset = symbol['raw'] - section['row'][3]
        expected_bytes = b''.join(int(word, 16).to_bytes(4, 'little') for word in words.split())
        assert symbol['size'] == 56 and section['data'][offset:offset + 56] == expected_bytes, name
        labels[name] = symbol['raw']
    if args.control:
        for name in ('control_input', 'control_guard'):
            symbol, = [row for row in compiler_elf['symbols'] if row['name'] == name]
            labels[name] = symbol['raw']
    write('labels.json', labels)
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(address) + '\n' for name, address in labels.items()))
    for leaf in ('calls.input', 'calls.reference'):
        before[str(case / leaf)] = digest(case / leaf)
    write('protected-before.json', before)
    run('compiler-runtime', ['bash', source / 'arm-pcs-profile-runtime.sh', case, 'compiler', args.qemu,
        args.gdb, args.gdb_data, runtime_script])
    (case / 'project').mkdir()
    headless = args.ghidra / 'support/analyzeHeadless'
    run('import', [headless, case / 'project', 'Hfa', '-import', case / 'calls.input', '-loader', 'ElfLoader'])
    for phase in ('curate', 'inspect'):
        run(phase, [headless, case / 'project', 'Hfa', '-process', 'calls.input', '-noanalysis',
            *(['-readOnly'] if phase == 'inspect' else []), '-scriptPath', source / 'ghidra_scripts',
            '-postScript', prepare_script, phase, case / 'labels.txt', case / (phase + '.json'),
            *([args.storage] if args.control else []),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'calls.dbg')])
        assert 'GhidraDwarfForge symbol export PASS' in (case / (phase + '.log')).read_text()
        if phase == 'curate':
            for leaf in ('calls.dbg', 'calls.dbg.c'):
                shutil.copy2(case / leaf, case / ('first-' + leaf))
            project_before = {str(p.relative_to(case / 'project')): digest(p)
                for p in (case / 'project').rglob('*') if p.is_file()}
            write('project-before.json', project_before)
    assert json.loads((case / 'curate.json').read_text()) == json.loads((case / 'inspect.json').read_text())
    observation = json.loads((case / 'inspect.json').read_text())
    origin = urlsplit(observation['origin'])
    assert origin.scheme == 'file' and Path(unquote(origin.path)) == module / 'lib/GhidraDwarfForge.jar'
    project_after = {str(p.relative_to(case / 'project')): digest(p)
        for p in (case / 'project').rglob('*') if p.is_file()}
    assert {p for p in project_before.keys() | project_after.keys()
        if project_before.get(p) != project_after.get(p)} <= {'Hfa.rep/idata/~index.bak', 'Hfa.rep/idata/~journal.bak'}
    write('project-after.json', project_after)
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
    run('forge-runtime', ['bash', source / 'arm-pcs-profile-runtime.sh', case, 'forge', args.qemu,
        args.gdb, args.gdb_data, runtime_script])
    results = {}
    for variant in ('compiler', 'forge'):
        result = json.loads((case / (variant + '-gdb.json')).read_text())
        if args.control:
            assert result['status'] == 'PASS_HFA_CONTROLS' and len(result['observations']) == 14
            gap = controls.GAP_START[args.control]
            unavailable = 0 if gap is None else (56 - gap) // 4
            assert sum('unavailable' in row for row in result['observations']) == (unavailable if variant == 'forge' else 0)
            assert sum('typed' in row for row in result['observations']) == (14 - unavailable if variant == 'forge' else 0)
            assert all('typedInput' in row for row in result['observations'])
        else:
            assert result['status'] == 'PASS_HFA_LIFETIMES' and len(result['observations']) == 28
            assert sum('typed' in row for row in result['observations']) == (28 if variant == 'forge' else 10)
        warnings = (case / (variant + '.stderr')).read_text().splitlines()
        assert len(warnings) <= 1
        for warning in warnings:
            assert warning == 'Failed to read a valid object file image from memory.' or re.fullmatch(
                r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', warning)
            reference.corroborate_unmapped_vdso_sections(result)
        assert (case / (variant + '.qemu.status')).read_text() == 'exit=0\n'
        assert not (case / (variant + '.qemu.stderr')).read_bytes()
        results[variant] = result
    assert before == {path: digest(Path(path)) for path in before}
    write('result.json', {'status': 'PASS_HFA_CONTROLS' if args.control else 'PASS_HFA_LIFETIMES',
        'order': args.order, 'control': args.control, 'storage': args.storage,
        'forgeTypedInstructions': 14 - unavailable if args.control else 28,
        'unavailableInstructions': unavailable if args.control else 0,
        'compilerTypedInstructions': 0 if args.control else 10,
        'rawInstructionsPerSymbolFile': 14 if args.control else 28,
        'deterministic': True, 'protectedFilesUnchanged': True})
    print('PASS_HFA_CONTROLS' if args.control else 'PASS_HFA_LIFETIMES', flush=True)


if __name__ == '__main__':
    main()
