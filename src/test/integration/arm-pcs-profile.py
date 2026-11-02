#!/usr/bin/env python3
"""Packaged ARM scalar PCS export: LE/BE8, base/VFP, wide and exhausted arguments."""
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


facts = load('pcs_elf', source / 'arm-thumb-mode-check.py')
reference = load('pcs_reference', source / 'arm-pcs-call-reference.py')
dies = load('pcs_dies', source / 'arm-dynamic-pcs-check.py')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--gdb', type=Path, required=True)
    parser.add_argument('--gdb-data', type=Path, required=True)
    parser.add_argument('--qemu-arm', required=True)
    parser.add_argument('--qemu-armeb', required=True)
    parser.add_argument('--order', choices=('little', 'big'), required=True)
    parser.add_argument('--pcs', choices=('softfp', 'hard'), required=True)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    output = repository / 'build/test-results/arm-pcs-profile'
    output.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.order + '.' + args.pcs + '.', dir=output))
    print(case, flush=True)
    compiler = os.environ.get('ARM32_CC', 'arm-linux-gnueabihf-gcc')
    objcopy = os.environ.get('ARM32_OBJCOPY', 'arm-linux-gnueabihf-objcopy')
    emulator = args.qemu_armeb if args.order == 'big' else args.qemu_arm
    protected = [Path(__file__), source / 'arm-pcs-profile-gdb.py', source / 'arm-pcs-profile-runtime.sh',
        source / 'ghidra_scripts/PrepareArmPcsProfile.java', source / 'qemu-socket.sh',
        source / 'arm-thumb-mode-check.py', source / 'arm-dynamic-pcs-check.py',
        source / 'arm-pcs-call-reference.py', source / 'check-dwarfdump.py',
        repository / 'src/test/fixtures/arm-pcs-profile.c', repository / 'src/test/fixtures/arm-pcs-start.S',
        args.gdb.resolve(strict=True)]
    protected += [Path(shutil.which(tool)).resolve(strict=True) for tool in (compiler, objcopy, emulator)]
    protected += [p for base in (module, args.gdb_data) for p in base.rglob('*') if p.is_file()]
    before = {str(p): digest(p) for p in protected}
    commands = []
    java_version = subprocess.run([str(Path(os.environ['JAVA_HOME']) / 'bin/java'), '-Xshare:off', '-version'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    assert not java_version.stdout
    (case / 'java-version.stderr').write_bytes(java_version.stderr)

    def write(name, data):
        (case / name).write_text(json.dumps(data, indent=4) + '\n')

    def run(label, command, timeout=180):
        command = list(map(str, command))
        commands.append({'label': label, 'command': command})
        write('commands.json', commands)
        with (case / (label + '.log')).open('wb') as log, (case / (label + '.err')).open('wb') as err:
            process = subprocess.run(command, stdout=log, stderr=err, timeout=timeout)
        assert process.returncode == 0, (case, label, process.returncode)
        stderr = (case / (label + '.err')).read_bytes()
        if Path(command[0]).name == 'analyzeHeadless':
            assert stderr == java_version.stderr, (label, 'unexpected headless stderr')
            assert not re.search(r'(?m)^ERROR (?!GhidraDwarfForge.java> GhidraDwarfForge: )',
                (case / (label + '.log')).read_text()), label
        else:
            assert not stderr, (label, 'unexpected stderr')

    write('profile.json', {'order': args.order, 'pcs': args.pcs})
    run('compile', [compiler, '-marm', '-march=armv7-a', '-mfpu=vfpv3-d16', '-mfloat-abi=' + args.pcs,
        '-O0', '-g3', '-gdwarf-5', '-fno-omit-frame-pointer', '-nostdlib', '-nostartfiles', '-static',
        '-fno-pie', '-no-pie', '-Wl,--build-id=none', '-Wl,-e,_start',
        *(['-mbig-endian', '-Wl,--be8'] if args.order == 'big' else []),
        repository / 'src/test/fixtures/arm-pcs-start.S', repository / 'src/test/fixtures/arm-pcs-profile.c',
        '-o', case / 'calls.reference'])
    run('strip', [objcopy, '--strip-all', case / 'calls.reference', case / 'calls.input'])
    before.update({str(p): digest(p) for p in (case / 'calls.reference', case / 'calls.input')})
    write('protected-before.json', before)
    original = facts.elf(case / 'calls.input', allow_big_endian=True)
    compiler_elf = facts.elf(case / 'calls.reference', allow_big_endian=True)
    names = [pcs + '_' + kind for pcs in ('base', 'vfp') for kind in ('float', 'double', 'wide', 'many')]
    labels = names + [name + '_pointer' for name in names] + ['seen_float', 'seen_double', 'seen_wide', 'calls', 'marker']
    entries = {}
    for name in labels:
        symbol, = [row for row in compiler_elf['symbols'] if row['name'] == name]
        entries[name] = symbol['raw']
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(address) + '\n' for name, address in entries.items()))
    (case / 'project').mkdir()
    run('import', [ghidra / 'support/analyzeHeadless', case / 'project', 'Pcs', '-import', case / 'calls.input',
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120'])
    assert 'REPORT: Import succeeded' in (case / 'import.log').read_text()
    for phase in ('curate', 'inspect'):
        run(phase, [ghidra / 'support/analyzeHeadless', case / 'project', 'Pcs', '-process', 'calls.input',
            '-noanalysis', *(['-readOnly'] if phase == 'inspect' else []),
            '-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareArmPcsProfile.java', phase,
            case / 'labels.txt', case / (phase + '.json'), '-postScript', 'GhidraDwarfForge.java', '--packaged-natives',
            '--output=' + str(case / 'calls.dbg')])
        log = (case / (phase + '.log')).read_text()
        assert 'arm-pcs-profile-preparation=PASS' in log and 'GhidraDwarfForge symbol export PASS' in log
        if phase == 'curate':
            for leaf in ('calls.dbg', 'calls.dbg.c'):
                shutil.copyfile(case / leaf, case / ('first-' + leaf))
            program_before = {str(p.relative_to(case / 'project')): digest(p)
                for p in (case / 'project').rglob('*') if p.is_file()}
            write('program-before.json', program_before)
    assert json.loads((case / 'curate.json').read_text()) == json.loads((case / 'inspect.json').read_text())
    reports = [facts.transcript(case / (phase + '.log'), 'GhidraDwarfForge report: ') for phase in ('curate', 'inspect')]
    assert reports[0] == reports[1] and reports[0]['failure'] is None
    write('report.json', reports[0])
    observed = json.loads((case / 'inspect.json').read_text())
    origin = urlsplit(observed['origin'])
    assert origin.scheme == 'file' and not origin.netloc and not origin.query and not origin.fragment
    assert Path(unquote(origin.path)) == module / 'lib/GhidraDwarfForge.jar'
    for leaf in ('calls.dbg', 'calls.dbg.c'):
        assert (case / leaf).read_bytes() == (case / ('first-' + leaf)).read_bytes()
    program_after = {str(p.relative_to(case / 'project')): digest(p)
        for p in (case / 'project').rglob('*') if p.is_file()}
    changed = [p for p in program_before.keys() | program_after.keys() if program_before.get(p) != program_after.get(p)]
    assert set(changed) <= {'Pcs.rep/idata/~index.bak', 'Pcs.rep/idata/~journal.bak'}, changed
    for variant, path in [('compiler', case / 'calls.reference'), ('forge', case / 'calls.dbg')]:
        for view, option in [('header', '-h'), ('sections', '-SW'), ('attributes', '-A'), ('notes', '-n'),
                ('info', '--debug-dump=info'), ('abbrev', '--debug-dump=abbrev'), ('aranges', '--debug-dump=aranges'),
                ('line', '--debug-dump=decodedline')]:
            run(variant + '-' + view, ['readelf', option, path])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', path])
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', path, case / (variant + '-strict-report.log'),
            *(['--original', case / 'calls.input'] if variant == 'forge' else [])])
    exported = facts.elf(case / 'calls.dbg', allow_big_endian=True)
    assert exported['data'][:16] == original['data'][:16]
    assert exported['header'][:4] == original['header'][:4] and exported['header'][6] == original['header'][6]
    assert exported['header'][4] == exported['header'][9] == 0
    for section in ('.text', '.ARM.attributes'):
        assert facts.section(exported, section)['data'] == facts.section(original, section)['data']
    records = dies.records((case / 'forge-info.log').read_text())
    raw = []
    for name in names:
        expected = 1 if name.endswith('wide') or name.startswith('vfp' if args.pcs == 'hard' else 'base') else 3
        for tag, spelling in [('DW_TAG_subprogram', name), ('DW_TAG_subroutine_type', name + '_type')]:
            record, = [row for row in records if row['tag'] == tag and dies.name(row) == spelling]
            assert int(record['attrs']['DW_AT_calling_convention'].split()[0]) == expected, record
            raw.append(record)
    observations = []
    for variant in ('compiler', 'forge'):
        run(variant + '-runtime', ['bash', source / 'arm-pcs-profile-runtime.sh', case, variant,
            emulator, args.gdb, args.gdb_data])
        observed = json.loads((case / (variant + '-gdb.json')).read_text())
        assert observed['status'] == 'PASS' and observed['exitCode'] == 0
        warnings = (case / (variant + '.stderr')).read_text().splitlines()
        assert len(warnings) <= 1
        for warning in warnings:
            if warning == 'Failed to read a valid object file image from memory.':
                reference.corroborate_unmapped_vdso_sections(observed)
            else:
                assert re.fullmatch(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', warning)
        assert (case / (variant + '.qemu.status')).read_text() == 'exit=0\n'
        assert not (case / (variant + '.qemu.stderr')).read_bytes()
        observations.append(observed)
    after = {path: digest(Path(path)) for path in before}
    assert before == after
    write('result.json', {'status': 'PASS', 'profile': vars(args) | {'ghidra': str(ghidra), 'gdb': str(args.gdb),
        'gdb_data': str(args.gdb_data)}, 'rawCallingConventions': raw, 'gdb': observations,
        'protectedBefore': before, 'protectedAfter': after, 'programBefore': program_before,
        'programAfter': program_after, 'rotatedBackups': changed})
    print('arm-pcs-profile=PASS ' + str(case))


if __name__ == '__main__':
    main()
