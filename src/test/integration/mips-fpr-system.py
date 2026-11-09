#!/usr/bin/env python3
"""Use the actual 64-bit system-emulator transport for O32 FPXX/FP64A FR=1."""
import argparse
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
spec = importlib.util.spec_from_file_location('support', HERE.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def check_diagnostics(diagnostics, labels):
    """Account for exact unsupported call-site messages without hiding new errors."""
    assert isinstance(diagnostics, list) and all(isinstance(message, str) for message in diagnostics)
    prefix = 'Call-site metadata at ELF address '
    expected = Counter(
        prefix + hex(labels[name]) + ': ELF or program is outside the selected ordinary unwind ABIs'
        for name in ('_start', 'main', 'fp_float', 'fp_double'))
    call_sites = [message for message in diagnostics if message.startswith(prefix)]
    assert Counter(call_sites) == expected, ('unexpected call-site diagnostics', diagnostics)
    remaining = [message for message in diagnostics if not message.startswith(prefix)]
    assert len(remaining) == 8, ('unexpected original diagnostic count', remaining)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--endian', choices=('be', 'le'), required=True)
    parser.add_argument('--profile', choices=('fpxx', 'fp64a'), required=True)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = REPOSITORY / 'build/test-results/mips-fpr-system'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.endian + '.' + args.profile + '.', dir=root))
    print(case, flush=True)
    prefix = 'mips' if args.endian == 'be' else 'mipsel'
    target = 'mips32' + args.endian
    emulator = 'qemu-system-mips64' + ('el' if args.endian == 'le' else '')
    compiler = shlex.split(os.environ.get('MIPS_FPR_CC', prefix + '-linux-gnu-gcc'))
    commands = []

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, native=False, **kwargs):
        commands.append({'label': name, 'command': list(map(str, command))})
        write('commands.json', commands)
        support.run(command, case / (name + '.log'), **kwargs)
        text = (case / (name + '.log')).read_text()
        if native:
            assert 'REPORT SCRIPT ERROR' not in text and 'Script error' not in text
        else:
            support.require_clean(case / (name + '.log'))
        return text

    fixture = HERE.parent / 'fixtures/fp_register_aliases.c'
    startup = HERE.parent / 'fixtures/mips-fpr-system-start.S'
    protected_files = [fixture, startup, Path(__file__), HERE / 'mips-fpr-system-gdb.py',
        HERE / 'ghidra_scripts/PrepareFloatingRegisters.java']
    protected_files += [p for p in module.rglob('*') if p.is_file()]
    protected = {str(p): support.digest(p) for p in protected_files}
    reference, original = case / 'reference', case / 'original'
    flags = ['-mfpxx'] if args.profile == 'fpxx' else ['-mfp64', '-mno-odd-spreg']
    run('compile', [*compiler, '-O1', '-g', '-gdwarf-5', '-Wall', '-Wextra', '-Werror', *flags,
        '-mabi=32', '-march=mips32r2', '-G0', '-mno-abicalls', '-fno-pic', '-fno-pie', '-no-pie',
        '-nostdlib', '-static', '-Wl,-Ttext=0x00100000', '-Wl,-e,_start', startup, fixture, '-o', reference])
    run('strip', [prefix + '-linux-gnu-objcopy', '--strip-all', reference, original])
    protected.update({str(p): support.digest(p) for p in (reference, original)})
    write('protected-before.json', protected)
    raw = original.read_bytes()
    assert raw[:5] == b'\x7fELF\x01' and raw[5] == (2 if args.endian == 'be' else 1)
    elf = run('attributes', ['readelf', '-hA', reference])
    fp_name = 'Any FPU' if args.profile == 'fpxx' else '64-bit FPU'
    assert fp_name in elf and 'o32' in elf and 'mips32r2' in elf
    symbols = run('symbols', [prefix + '-linux-gnu-nm', '-n', reference])
    labels = {}
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) == 3 and (fields[2].startswith('fp_') or fields[2] in ('_start', 'main', 'reference_done')):
            assert fields[2] not in labels
            labels[fields[2]] = int(fields[0], 16)
    assert {'_start', 'main', 'fp_float', 'fp_double', 'reference_done'} <= labels.keys()
    write('labels.json', labels)
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(address) + '\n' for name, address in labels.items()))
    write('metadata.json', {'endian': args.endian, 'profile': args.profile, 'cpu': 'MIPS64R2-generic',
        'elfAbi': 'O32', 'requiredRuntimeFr': 1, 'bareMetal': True})
    run('gdb-version', ['gdb-multiarch', '--version'])
    run('qemu-version', [emulator, '--version'])

    def debugger(variant, probe_case=case, invalid=None):
        # The loader consumes the original target in both comparisons. Only
        # GDB's symbol file changes; the processor runs identical instructions.
        # Disable the unused default VGA device as well as its display: minimal
        # CI images do not install the optional Cirrus VGA ROM package.
        with tempfile.TemporaryDirectory(prefix='forge-mips-fpr.') as sockets:
            socket = Path(sockets) / 'gdb'
            qcommand = [emulator, '-M', 'malta', '-cpu', 'MIPS64R2-generic', '-m', '128',
                '-display', 'none', '-vga', 'none', '-serial', 'none', '-monitor', 'none', '-nic', 'none',
                '-device', 'loader,file=' + str(probe_case / 'original') + ',cpu-num=0', '-S',
                '-gdb', 'unix:' + str(socket) + ',server=on,wait=off']
            (probe_case / (variant + '-qemu-command.json')).write_text(json.dumps(qcommand, indent=4) + '\n')
            with (probe_case / (variant + '-qemu.log')).open('w') as out, (probe_case / (variant + '-qemu.stderr')).open('w') as err:
                qemu = subprocess.Popen(qcommand, stdout=out, stderr=err)
                try:
                    deadline = time.monotonic() + 10
                    while not socket.exists() and qemu.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.05)
                    assert socket.exists() and qemu.poll() is None, (
                        'QEMU system reference did not start', qemu.poll(),
                        (probe_case / (variant + '-qemu.stderr')).read_text())
                    gcommand = ['gdb-multiarch', '-q', '-nx', '-batch', '-x', str(HERE / 'mips-fpr-system-gdb.py')]
                    (probe_case / (variant + '-gdb-command.json')).write_text(json.dumps(gcommand, indent=4) + '\n')
                    environment = dict(os.environ, MIPS_FPR_CASE=str(probe_case), MIPS_FPR_VARIANT=variant,
                        MIPS_FPR_SOCKET=str(socket))
                    with (probe_case / (variant + '-gdb.log')).open('w') as gout, (probe_case / (variant + '-gdb.stderr')).open('w') as gerr:
                        observed_process = subprocess.run(gcommand, env=environment, stdout=gout, stderr=gerr, timeout=60)
                    observed = json.loads((probe_case / (variant + '-gdb.json')).read_text())
                    if invalid is None:
                        assert observed_process.returncode == 0
                        support.require_clean(probe_case / (variant + '-gdb.log'))
                        assert observed['status'] == 'PASS' and len(observed['rows']) == 6
                    else:
                        assert observed['status'] == 'FAIL' and observed['error'] == invalid, observed
                        assert 'AssertionError' in (probe_case / (variant + '-gdb.stderr')).read_text()
                    assert qemu.poll() is None
                finally:
                    if qemu.poll() is None:
                        qemu.terminate()
                    try:
                        qemu.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        qemu.kill()
                        qemu.wait(timeout=10)
            stderr = (probe_case / (variant + '-qemu.stderr')).read_text()
            # The owned, non-exiting bare-metal machine is stopped explicitly.
            expected = emulator + ': terminating on signal 15 from pid ' + str(os.getpid()) + ' (python3)\n'
            assert stderr == expected, stderr

    debugger('compiler')
    project = case / 'project'
    project.mkdir()
    imported = run('import', [ghidra / 'support/analyzeHeadless', project, 'FprSystem', '-import', original,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', HERE / 'ghidra_scripts',
        '-postScript', 'PrepareFloatingRegisters.java', target, case / 'labels.txt'], native=True, timeout=240)
    assert 'REPORT: Analysis succeeded' in imported and 'floating-register-preparation=PASS' in imported
    before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', before)
    hashes = None
    for phase in ('first', 'repeat'):
        text = run(phase, [ghidra / 'support/analyzeHeadless', project, 'FprSystem', '-process', original.name,
            '-readOnly', '-noanalysis', '-postScript', 'GhidraDwarfForge.java', '--packaged-natives',
            '--output=' + str(case / 'floating.dbg')], native=True, timeout=240)
        assert 'GhidraDwarfForge symbol export PASS' in text
        assert 'language: MIPS:' + args.endian.upper() + ':32:default' in text
        assert 'native policy: verified packaged libraries in ' + str(module / 'os/linux_x86_64') in text
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in text.splitlines() if 'GhidraDwarfForge report: {' in line]
        write(phase + '-report.json', report)
        assert report['status'] == 'PARTIAL' and report['failure'] is None
        assert not report['failedFunctions'] and not report['skippedFunctions']
        assert report['counts']['functionsExported'] == report['counts']['functionsDecompiled'] == 4
        assert report['target'] == {'architecture': prefix, 'addressBits': 32,
            'byteOrder': 'BIG_ENDIAN' if args.endian == 'be' else 'LITTLE_ENDIAN'}
        omitted = report['omittedLocations']
        assert len(omitted) == 2 and {(row['function'], row['variable'], row['reason']) for row in omitted} == {
            ('fp_double', 'first', 'UNMAPPED_REGISTER'), ('fp_double', 'second', 'UNMAPPED_REGISTER')}
        unsupported = report['unsupportedConstructs']
        assert len(unsupported) == 3 and {(row['kind'], row['name']) for row in unsupported} == {
            ('OPAQUE_TYPE', 'undefined'), ('OPAQUE_TYPE', 'undefined4'), ('OPAQUE_TYPE', 'undefined8')}
        check_diagnostics(report['diagnostics'], labels)
        current = [support.digest(case / n) for n in ('floating.dbg', 'floating.dbg.c')]
        assert hashes is None or hashes == current
        hashes = current
    for variant, artifact in [('compiler', reference), ('forge', case / 'floating.dbg')]:
        dwarf = run(variant + '-gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline,loc', artifact])
        if variant == 'forge':
            assert 'DW_TAG_call_site' not in dwarf and 'DW_AT_call_all' not in dwarf, \
                'unsupported MIPS profile emitted call-site metadata'
        llvm = run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        assert 'No errors.' in llvm
        run(variant + '-strict', ['python3', HERE / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict.txt'), '--original', original])
    debugger('forge')
    # Prove the independent reference fails for wrong DWARF and wrong actual
    # runtime mode. Copies never replace the original ELF or accepted sidecar.
    def section(image, wanted):
        endian = '>' if args.endian == 'be' else '<'
        at = struct.unpack_from(endian + 'I', image, 32)[0]
        size, count, names_index = struct.unpack_from(endian + 'HHH', image, 46)
        assert size == 40 and 0 < names_index < count
        rows = [struct.unpack_from(endian + '10I', image, at + i * size) for i in range(count)]
        row = rows[names_index]
        names = image[row[4]:row[4] + row[5]]
        matched, = [r for r in rows if names[r[0]:].split(b'\0', 1)[0] == wanted]
        return matched

    controls = []
    for kind in ('positive-copy', 'wrong-fpr', 'wrong-fr-mode'):
        directory = case / kind
        directory.mkdir()
        for name in ('reference', 'original', 'metadata.json', 'labels.json'):
            shutil.copy2(case / name, directory / name)
        invalid = None
        if kind == 'wrong-fpr':
            dies = re.split(r'(?=^\s*<\d+><[0-9a-f]+>:)', (case / 'compiler-gnu.log').read_text(), flags=re.M)
            owner, = [i for i, die in enumerate(dies) if 'DW_TAG_subprogram' in die and
                re.search(r'DW_AT_name\s*:.*\bfp_double\s*$', die, re.M)]
            formal = dies[owner + 1]
            assert 'DW_TAG_formal_parameter' in formal and re.search(r'DW_AT_name\s*:.*\bfirst\s*$', formal, re.M)
            offset = int(re.search(r'<([0-9a-f]+)>\s+DW_AT_location', formal)[1], 16)
            image = bytearray(reference.read_bytes())
            row = section(image, b'.debug_info')
            at = row[4] + offset
            assert image[at] in (2, 4) and image[at + 1:at + 3] == b'\x90\x2c'
            image[at + 2] = 46
            (directory / 'reference').write_bytes(image)
            invalid = "AssertionError(('fp_double', 'first', '-9.25'))"
        elif kind == 'wrong-fr-mode':
            image = bytearray(original.read_bytes())
            row = section(image, b'.text')
            assert row[3] == 0x100000
            endian = '>' if args.endian == 'be' else '<'
            assert struct.unpack_from(endian + 'I', image, row[4] + 4)[0] == 0x3c082400
            struct.pack_into(endian + 'I', image, row[4] + 4, 0x3c082000)
            (directory / 'original').write_bytes(image)
            invalid = "AssertionError('the reference requires actual FR=1')"
        run(kind + '-original-elf', ['readelf', '-hASW', directory / 'original'])
        for name in ('reference',):
            run(kind + '-' + name + '-llvm', ['llvm-dwarfdump', '--verify', directory / name])
            run(kind + '-' + name + '-strict', ['python3', HERE / 'check-dwarfdump.py', directory / name,
                directory / (name + '-strict.txt')])
        debugger('compiler', directory, invalid)
        controls.append({'kind': kind, 'expectedRejection': invalid})
    after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', after)
    changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
    assert set(changed) <= {'FprSystem.rep/idata/~index.bak', 'FprSystem.rep/idata/~journal.bak'}, changed
    assert protected == {p: support.digest(Path(p)) for p in protected}
    write('result.json', {'status': 'PASS', 'profile': args.profile, 'endian': args.endian,
        'artifactHashes': hashes, 'requiredRuntimeFr': 1, 'compilerDoubleReference': 'PASS',
        'forgeDoubleLocations': 'UNAVAILABLE', 'originalsUnchanged': True, 'projectHousekeepingChanges': changed,
        'referenceControls': controls})
    print('mips-fpr-system=PASS ' + str(case))


if __name__ == '__main__':
    main()
