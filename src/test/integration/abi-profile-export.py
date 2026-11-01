#!/usr/bin/env python3
"""Validate AArch64 ELF/language/compiler call classification through the packaged exporter."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
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
    parser.add_argument('--language', choices=('v8A', 'AppleSilicon'), default='v8A')
    parser.add_argument('--compiler', choices=('default', 'windows', 'golang', 'swift'), default='default')
    parser.add_argument('--osabi', type=int, default=0)
    parser.add_argument('--abi-version', type=int, default=0)
    parser.add_argument('--flags', type=lambda value: int(value, 0), default=0)
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    args = parser.parse_args()
    assert 0 <= args.osabi <= 255 and 0 <= args.abi_version <= 255 and 0 <= args.flags < 2**32
    assert args.compiler in ({'default', 'windows', 'golang'} if args.language == 'v8A' else {'default', 'swift', 'golang'})
    blocked = not (args.language == 'v8A' and args.compiler == 'default' and args.osabi in (0, 3) and args.abi_version == args.flags == 0)
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/abi-profile'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='.'.join((args.language, args.compiler, str(args.osabi), str(args.abi_version), hex(args.flags), args.role)) + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless' and name != 'gdb-driver':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/mips-floating-call.c'
    protected = [fixture, Path(__file__).resolve(), source / 'abi-profile-gdb.py',
        source / 'abi-profile-gdb.sh', source / 'abi-profile-diagnostics.py', source / 'qemu-socket.sh', source / 'elf-layout-gdb-oracle.sh',
        source / 'check-dwarfdump.py', source.parent / 'performance/export-benchmark.py',
        source / 'ghidra_scripts/PrepareAbiProfile.java', source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    reference, binary = case / 'call.reference', case / 'call.input'
    prefix = 'aarch64-linux-gnu-'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run('compile', [prefix + 'gcc', '-O1', '-g3', '-gdwarf-5', '-gno-variable-location-views',
        *flags, '-Wl,--build-id=sha1', fixture, '-o', reference])
    # Mutate only this disposable fixture, before importing or recording hashes.
    # GNU OSABI is an explicit metadata test, not a claim about compiler defaults.
    data = bytearray(reference.read_bytes())
    write('compiler-original.json', {'sha256': support.digest(reference), 'headerHex': bytes(data[:64]).hex()})
    data[7:9] = bytes((args.osabi, args.abi_version))
    data[48:52] = args.flags.to_bytes(4, 'little')
    reference.write_bytes(data)
    run('strip', [prefix + 'objcopy', '--strip-debug', reference, binary])
    before.update({str(p): support.digest(p) for p in (reference, binary)})
    write('protected-before.json', before)
    run('symbols', ['readelf', '-sW', reference])
    symbols = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in ('fp_call', 'integer_call', 'marker'):
            address = int(fields[1], 16)
            assert fields[7] not in symbols or symbols[fields[7]] == address
            symbols[fields[7]] = address
    assert len(symbols) == 3
    run('input-header', ['readelf', '-hA', binary])
    write('metadata.json', {'language': args.language, 'compiler': args.compiler,
        'osabi': args.osabi, 'abiVersion': args.abi_version, 'flags': args.flags, 'blocked': blocked,
        'qemuCpu': os.environ.get('ABI_PROFILE_QEMU_CPU', 'cortex-a53'), 'role': args.role, 'symbols': symbols})
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'FloatingCall', '-import', binary,
        '-processor', 'AARCH64:LE:64:' + args.language, '-cspec', args.compiler,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareAbiProfile.java', 'curate', 'double', case / 'import.json'], timeout=240)
    import_log = (case / 'import.log').read_text()
    assert 'REPORT: Analysis succeeded' in import_log and 'REPORT SCRIPT ERROR' not in import_log
    # Forced Go selection on a C fixture has no Go runtime tables; account only
    # for these two expected analyzer diagnostics, retaining the full log.
    errors = [line.split(' (', 1)[0] for line in import_log.splitlines() if line.startswith('ERROR ')]
    expected_errors = ['ERROR Go symbol analyzer error: unable to get GoRttiMapper',
        'ERROR Go string analyzer error: unable to get GoRttiMapper'] if args.compiler == 'golang' else []
    assert sorted(errors) == sorted(expected_errors), errors
    write('import-diagnostics.json', {'expectedErrors': errors, 'genuineGoBinary': False})
    snapshot = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', snapshot)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    hashes = None
    for variant, installation in variants:
        output = case / 'fixed.dbg'
        run(variant, [installation / 'support/analyzeHeadless', project, 'FloatingCall', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareAbiProfile.java', 'observe', 'double', case / (variant + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], timeout=240)
        text = (case / (variant + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in text and 'abi-profile-preparation=PASS' in text
        observed = json.loads((case / (variant + '.json')).read_text())
        for row in observed['functions']:
            assert row['entry'] == symbols[row['name']] and row['customStorage'] is False
        if args.role == 'pie-rebased':
            assert observed['rebaseDelta'] >= 0x2000000
        imported = json.loads((case / 'import.json').read_text())
        assert {k: v for k, v in observed.items() if k != 'origin'} == {k: v for k, v in imported.items() if k != 'origin'}
        expected_jar = installation / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
        assert Path(unquote(urlsplit(observed['origin']).path)).resolve() == expected_jar.resolve()
        assert observed['language'] == 'AARCH64:LE:64:' + args.language and observed['compiler'] == args.compiler
        for name in ('fp_call', 'integer_call'):
            assert ('Debugger-injected calls disabled for ' + name + ':' in text) == blocked
        current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        if hashes is not None:
            assert hashes == current
        hashes = current
        if variant == 'fixed':
            shutil.copyfile(output, case / 'first.dbg')
            shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in text.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert not report['failedFunctions'] and report['failure'] is None
        write(variant + '-report.json', report)
    final = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', final)
    changes = sorted(k for k in snapshot.keys() | final.keys() if snapshot.get(k) != final.get(k))
    assert set(changes) <= {'FloatingCall.rep/idata/~index.bak', 'FloatingCall.rep/idata/~journal.bak'}, changes
    for variant, artifact in [('compiler', reference), ('fixed', case / 'fixed.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict-checks.log'), '--original', binary])
    records = []
    for line in (case / 'fixed-info.log').read_text().splitlines():
        header = re.match(r'^\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?', line)
        if header:
            records.append({'depth': int(header[1]), 'offset': int(header[2], 16), 'tag': header[3], 'attrs': {}})
        elif records:
            attr = re.match(r'^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)', line)
            if attr:
                records[-1]['attrs'][attr[1]] = attr[2]
    for name, expected in [('fp_call', 3 if blocked else 1), ('integer_call', 3 if blocked else 1)]:
        row, = [row for row in records if row['tag'] == 'DW_TAG_subprogram' and
            row['attrs'].get('DW_AT_name', '').rsplit(': ', 1)[-1] == name]
        assert int(row['attrs']['DW_AT_calling_convention'].split()[0]) == expected
        assert int(row['attrs']['DW_AT_low_pc'], 16) == symbols[name]
        assert 'DW_AT_type' in row['attrs'] and 'DW_AT_decl_line' in row['attrs']
    for name, expected in [('fp_pointer_type', 3 if blocked else 1), ('integer_pointer_type', 3 if blocked else 1)]:
        row, = [row for row in records if row['tag'] == 'DW_TAG_subroutine_type' and
            row['attrs'].get('DW_AT_name', '').rsplit(': ', 1)[-1] == name]
        assert int(row['attrs']['DW_AT_calling_convention'].split()[0]) == expected
    write('raw-dies.json', records)
    run('gdb-driver', ['bash', source / 'abi-profile-gdb.sh', repository, case], timeout=240)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    write('result.json', {'status': 'PASS', 'language': args.language, 'compiler': args.compiler, 'blocked': blocked,
        'role': args.role, 'inputSha256': before[str(binary)], 'hashes': hashes,
        'projectBackupChanges': changes,
        'jarSha256': support.digest(module / 'lib/GhidraDwarfForge.jar')})
    print('abi-profile-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
