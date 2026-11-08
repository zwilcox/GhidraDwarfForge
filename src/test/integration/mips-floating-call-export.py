#!/usr/bin/env python3
"""Validate MIPS floating call restrictions and unaffected integer calls using the real exporter."""
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
    parser.add_argument('target', choices=('mips32be', 'mips32le'))
    parser.add_argument('--profile', choices=('fpxx', 'fp32', 'n32', 'n64'), required=True)
    parser.add_argument('--scalar', choices=('float', 'double'), required=True)
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    parser.add_argument('--previous-ghidra', type=Path)
    parser.add_argument('--toolchain-root', type=Path)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/mips-floating-call'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='.'.join((args.target, args.profile, args.scalar, args.role)) + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless' and name != 'gdb-driver':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/mips-floating-call.c'
    protected = [fixture, Path(__file__).resolve(), source / 'mips-floating-call-gdb.py',
        source / 'mips-floating-call-gdb.sh', source / 'qemu-socket.sh', source / 'elf-layout-gdb-oracle.sh',
        source / 'check-dwarfdump.py', source.parent / 'performance/export-benchmark.py',
        source / 'ghidra_scripts/PrepareMipsFloatingCall.java', source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    if args.previous_ghidra:
        previous_module = args.previous_ghidra.resolve(strict=True) / 'Ghidra/Extensions/GhidraDwarfForge'
        protected += [p for p in previous_module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    reference, binary = case / 'call.reference', case / 'call.input'
    prefix = 'mips-linux-gnu-' if args.target == 'mips32be' else 'mipsel-linux-gnu-'
    wide = args.profile in ('n32', 'n64')
    compiler_environment, tool_flags = [], []
    sysroot = Path('/usr/mips-linux-gnu' if args.target == 'mips32be' else '/usr/mipsel-linux-gnu')
    emulator = 'qemu-mips' + ('el' if args.target == 'mips32le' else '') + '-static'
    abi_flags = ['-m' + args.profile]
    if wide:
        prefix = 'mips64' + ('el' if args.target == 'mips32le' else '') + '-linux-gnuabi64-'
        sysroot = Path('/usr') / prefix[:-1]
        emulator = 'qemu-mips' + ('64' if args.profile == 'n64' else 'n32') + (
            'el' if args.target == 'mips32le' else '') + '-static'
        abi_flags = ['-mabi=' + ('64' if args.profile == 'n64' else 'n32'), '-march=mips64r2']
    compiler, objcopy = prefix + 'gcc', prefix + 'objcopy'
    if args.toolchain_root:
        assert wide, 'extracted compiler option is for N32/N64'
        toolchain = args.toolchain_root.resolve(strict=True)
        compiler_environment = ['env', 'LD_LIBRARY_PATH=' + str(toolchain / 'usr/lib/x86_64-linux-gnu')]
        compiler = toolchain / 'usr/bin' / (prefix + 'gcc-12')
        objcopy = toolchain / 'usr/bin' / (prefix + 'objcopy')
        tool_flags = ['--sysroot=' + str(toolchain), '-B' + str(toolchain / 'usr' / prefix[:-1] / 'bin') + '/']
        sysroot = toolchain / 'usr' / prefix[:-1]
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    if args.scalar == 'float':
        flags.append('-DFORGE_SCALAR_FLOAT')
    run('compile', [*compiler_environment, compiler, *tool_flags, '-O1', '-g3', '-gdwarf-5', '-gno-variable-location-views',
        *abi_flags, *flags, '-Wl,--build-id=sha1', fixture, '-o', reference])
    run('strip', [*compiler_environment, objcopy, '--strip-debug', reference, binary])
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
    text = (case / 'input-header.log').read_text()
    assert ('FP ABI: Hard float (double precision)' if args.profile != 'fpxx' else 'FP ABI: Hard float (32-bit CPU, Any FPU)') in text
    entry, = re.findall(r'Entry point address:\s+(0x[0-9a-f]+)', text)
    write('metadata.json', {'entryAddress': int(entry, 16), 'emulator': emulator, 'sysroot': str(sysroot), 'target': args.target, 'profile': args.profile, 'scalar': args.scalar,
        'role': args.role, 'symbols': symbols})
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'FloatingCall', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareMipsFloatingCall.java', 'curate', args.scalar, case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    snapshot = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', snapshot)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.insert(0, ('previous', args.previous_ghidra.resolve()))
    hashes = None
    for variant, installation in variants:
        output = case / ('previous.dbg' if variant == 'previous' else 'fixed.dbg')
        run(variant, [installation / 'support/analyzeHeadless', project, 'FloatingCall', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareMipsFloatingCall.java', 'observe', args.scalar, case / (variant + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], timeout=240)
        text = (case / (variant + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in text and 'mips-floating-call-preparation=PASS' in text
        observed = json.loads((case / (variant + '.json')).read_text())
        for row in observed['functions']:
            assert row['entry'] == symbols[row['name']] and row['customStorage'] is False
        if args.role == 'pie-rebased':
            assert observed['rebaseDelta'] >= 0x2000000
        imported = json.loads((case / 'import.json').read_text())
        assert {k: v for k, v in observed.items() if k != 'origin'} == {k: v for k, v in imported.items() if k != 'origin'}
        expected_jar = installation / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
        assert Path(unquote(urlsplit(observed['origin']).path)).resolve() == expected_jar.resolve()
        if variant == 'previous':
            continue
        restriction = 'Debugger-injected calls disabled for fp_call: MIPS floating or variadic'
        assert (restriction in text) == (args.profile == 'fpxx')
        assert 'Debugger-injected calls disabled for integer_call:' not in text
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
    if args.previous_ghidra:
        assert (case / 'previous.dbg.c').read_bytes() == (case / 'fixed.dbg.c').read_bytes()
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
    for name, expected in [('fp_call', 3 if args.profile == 'fpxx' else 1), ('integer_call', 1)]:
        row, = [row for row in records if row['tag'] == 'DW_TAG_subprogram' and
            row['attrs'].get('DW_AT_name', '').rsplit(': ', 1)[-1] == name]
        assert int(row['attrs']['DW_AT_calling_convention'].split()[0]) == expected
        assert int(row['attrs']['DW_AT_low_pc'], 16) == symbols[name]
        assert 'DW_AT_type' in row['attrs'] and 'DW_AT_decl_line' in row['attrs']
    for name, expected in [('fp_pointer_type', 3 if args.profile == 'fpxx' else 1), ('integer_pointer_type', 1)]:
        row, = [row for row in records if row['tag'] == 'DW_TAG_subroutine_type' and
            row['attrs'].get('DW_AT_name', '').rsplit(': ', 1)[-1] == name]
        assert int(row['attrs']['DW_AT_calling_convention'].split()[0]) == expected
    write('raw-dies.json', records)
    run('gdb-driver', ['env', 'MIPS_CALL_PREVIOUS=' + ('previous' if args.previous_ghidra else ''),
        'bash', source / 'mips-floating-call-gdb.sh', repository, case, args.target], timeout=240)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    write('result.json', {'status': 'PASS', 'target': args.target, 'profile': args.profile, 'scalar': args.scalar,
        'role': args.role, 'inputSha256': before[str(binary)], 'hashes': hashes,
        'projectBackupChanges': changes, 'previousPackageCompared': bool(args.previous_ghidra),
        'jarSha256': support.digest(module / 'lib/GhidraDwarfForge.jar')})
    print('mips-floating-call-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
