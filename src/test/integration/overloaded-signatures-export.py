#!/usr/bin/env python3
"""Prove address-qualified overload identity through saved Ghidra and GDB."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


support = load('benchmark', source.parent / 'performance/export-benchmark.py')
facts = load('overload_facts', source / 'dynamic-composite-storage-check.py')
elf_support = load('overload_elf', source / 'retained-function-aliases-export.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=('x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le'))
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    parser.add_argument('--symbols', choices=('retained', 'stripped'), default='retained')
    parser.add_argument('--arm-mode', choices=('arm', 'thumb'), default='arm')
    parser.add_argument('--results-root', type=Path, default=repository / 'build/test-results/overloaded-signatures')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = args.results_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='.'.join((args.target, args.role, args.symbols)) + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, argv, clean=True):
        support.run(argv, case / (name + '.log'), timeout=240)
        if clean:
            support.require_clean(case / (name + '.log'))

    fixture = source.parent / 'fixtures/overloaded-signatures.cpp'
    protected = [Path(__file__), fixture, source / 'overloaded-signatures-gdb.py',
        source / 'overloaded-signatures-gdb.sh', source / 'ghidra_scripts/PrepareOverloadedSignatures.java',
        source / 'ghidra_scripts/RebaseFixtureProgram.java', source / 'check-dwarfdump.py',
        source / 'qemu-socket.sh', source / 'elf-layout-gdb-oracle.sh',
        source / 'dynamic-composite-storage-check.py', source / 'dynamic-parameter-storage-check.py',
        source / 'retained-function-aliases-export.py',
        source.parent / 'performance/export-benchmark.py']
    protected += [path for path in module.rglob('*') if path.is_file()]
    before = {str(path): support.digest(path) for path in protected}
    reference, binary, output = [case / ('overloads.' + suffix) for suffix in ('reference', 'input', 'dbg')]
    prefix = {'x86_64': '', 'aarch64': 'aarch64-linux-gnu-', 'arm32': 'arm-linux-gnueabihf-',
        'mips32be': 'mips-linux-gnu-', 'mips32le': 'mipsel-linux-gnu-'}[args.target]
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    if args.target.startswith('mips'):
        flags += ['-mabi=32', '-march=mips32r2', '-mfp32', '-mhard-float']
    if args.target == 'arm32':
        flags += ['-march=armv7-a', '-mfpu=vfpv3-d16', '-mfloat-abi=hard', '-m' + args.arm_mode, '-funwind-tables']
    run('compile', [prefix + 'g++', '-O1', '-g', '-gdwarf-5', '-gno-variable-location-views',
        '-fno-inline', '-fno-omit-frame-pointer', '-Wl,--build-id=sha1', *flags, fixture, '-o', reference])
    run('strip', [prefix + 'objcopy', '--strip-debug' if args.symbols == 'retained' else '--strip-all', reference, binary])
    before.update({str(path): support.digest(path) for path in (reference, binary)})
    write('protected-before.json', before)
    run('symbols', ['readelf', '-sW', reference])
    originals = ['_ZN8observed7combineEi', '_ZN8observed7combineEd']
    symbols = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in originals:
            assert fields[3] == 'FUNC' and fields[6].isdigit()
            record = (int(fields[1], 16), int(fields[2]))
            assert fields[7] not in symbols or symbols[fields[7]] == record
            symbols[fields[7]] = record
    entries = [symbols[name][0] & (~1 if args.target == 'arm32' else -1) for name in originals]
    run('input-symbols', ['readelf', '-sW', binary])
    original_names = {fields[7] for line in (case / 'input-symbols.log').read_text().splitlines()
        if len(fields := line.split()) == 8 and fields[7] in originals and fields[6].isdigit()}
    write('metadata.json', {'target': args.target, 'role': args.role, 'symbols': args.symbols,
        'armMode': args.arm_mode if args.target == 'arm32' else None, 'entries': entries,
        'compilerFlags': flags, 'originalNames': sorted(original_names), 'originalSymbols': symbols})
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Overloads', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareOverloadedSignatures.java', 'curate', case / 'curated.json', *map(hex, entries)], clean=False)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    curated = json.loads((case / 'curated.json').read_text())
    for index, row in enumerate(curated):
        assert row['entry'] == entries[index]
        assert row['parameter'] == row['return'] == ('int' if index == 0 else 'double')
        if args.role == 'pie-rebased':
            assert row['delta'] >= 0x2000000
            assert ' by 0x2000000' in (case / 'import.log').read_text()
        elif args.role == 'exec':
            assert row['delta'] == 0
        assert Path(unquote(urlsplit(row['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    project_before = {str(path.relative_to(project)): support.digest(path) for path in project.rglob('*') if path.is_file()}
    write('project-before.json', project_before)
    hashes = None
    for iteration in ('first', 'repeat'):
        run(iteration, [ghidra / 'support/analyzeHeadless', project, 'Overloads', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts', '-postScript',
            'PrepareOverloadedSignatures.java', 'observe', case / (iteration + '.json'), *map(hex, entries),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], clean=False)
        log = (case / (iteration + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in log
        assert curated == json.loads((case / (iteration + '.json')).read_text())
        current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        assert hashes is None or hashes == current
        hashes = current
        if iteration == 'first':
            shutil.copyfile(output, case / 'first.dbg')
            shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert not report['failedFunctions'] and report['failure'] is None
        omitted = [message for message in report['diagnostics'] if message.startswith('Omitted function alias ')]
        assert omitted == ['Omitted function alias Recovered::nested::ambiguous_alias: ambiguous current symbol display name'], omitted
        write(iteration + '-report.json', report)
    for variant, artifact in [('compiler', reference), ('forge', output)]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n'), ('symbols', '-sW')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict-checks.log'), '--original', binary])
    original_ident, original_header, original_sections = elf_support.elf(binary)
    ident, header, sections = elf_support.elf(output)
    assert ident == original_ident and header[:4] == original_header[:4] and header[6] == original_header[6]
    assert header[4] == header[8] == header[9] == 0
    assert sections['.text'][0][3] == original_sections['.text'][0][3]
    assert sections['.note.gnu.build-id'][1] == original_sections['.note.gnu.build-id'][1]
    for name in ('.dynsym', '.dynstr'):
        if name in original_sections:
            assert sections[name][1] == original_sections[name][1]
    table, records = sections['.symtab']
    strings = list(sections.values())[table[6]][1]
    wide, order = ident[4] == 2, '<' if ident[5] == 1 else '>'
    width = 24 if wide else 16
    assert table[9] == width
    aliases = {}
    for start in range(0, len(records), width):
        fields = struct.unpack_from(order + ('IBBHQQ' if wide else 'IIIBBH'), records, start)
        if wide:
            name, info_byte, other, section, value, size = fields
        else:
            name, value, size, info_byte, other, section = fields
        name = strings[name:strings.index(0, name)].decode()
        if name in {row['alias'] for row in curated}:
            assert name not in aliases and info_byte == 2 and other == 0 and section != 0
            aliases[name] = [value, size]
    assert aliases == {row['alias']: [symbols[originals[index]][0], row['size']]
        for index, row in enumerate(curated)}
    write('raw-aliases.json', aliases)
    info = (case / 'forge-info.log').read_text()
    assert 'DW_AT_linkage_name' not in info
    dies = facts.die_records(info)
    by_offset = {row['offset']: row for row in dies}
    functions = [row for row in dies if row['tag'] == 'DW_TAG_subprogram'
        and facts.facts.die_name(row) == 'Recovered::nested::combine']
    assert len(functions) == 2
    raw = []
    for index, entry in enumerate(entries):
        function, = [row for row in functions if int(row['attrs']['DW_AT_low_pc'], 16) == entry]
        parameter, = [row for row in facts.children(dies, dies.index(function)) if row['tag'] == 'DW_TAG_formal_parameter']
        assert facts.facts.die_name(parameter) == 'value' and 'DW_AT_location' in parameter['attrs']
        assert function['attrs']['DW_AT_type'] == parameter['attrs']['DW_AT_type']
        offset = int(re.fullmatch(r'<0x([0-9a-f]+)>', function['attrs']['DW_AT_type'])[1], 16)
        dtype = by_offset[offset]
        assert dtype['tag'] == 'DW_TAG_base_type'
        assert int(dtype['attrs']['DW_AT_byte_size']) == (4 if index == 0 else 8)
        assert dtype['attrs']['DW_AT_encoding'].split()[0] == ('5' if index == 0 else '4')
        line = int(function['attrs']['DW_AT_decl_line'])
        declaration = Path(str(output) + '.c').read_text().splitlines()[line - 1]
        assert ('int' if index == 0 else 'double') + ' Recovered::nested::combine(' in declaration, declaration
        raw.append({'function': function, 'parameter': parameter, 'type': dtype})
    write('raw-dies.json', raw)
    assert 'ambiguous_alias' not in (case / 'forge-symbols.log').read_text()
    run('gdb-driver', ['bash', source / 'overloaded-signatures-gdb.sh', repository, case, args.target])
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(path.relative_to(project)): support.digest(path) for path in project.rglob('*') if path.is_file()}
    write('project-after.json', project_after)
    changes = {name for name in project_before.keys() | project_after.keys() if project_before.get(name) != project_after.get(name)}
    assert changes <= {'Overloads.rep/idata/~index.bak', 'Overloads.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role,
        'symbols': args.symbols, 'artifactHashes': hashes, 'projectChanges': sorted(changes)})
    print('OVERLOADED_SIGNATURES_PASS', flush=True)


if __name__ == '__main__':
    main()
