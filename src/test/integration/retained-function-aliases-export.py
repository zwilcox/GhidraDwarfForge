#!/usr/bin/env python3
"""Prove retained ELF alias lookup separately from curated DWARF identity."""
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
spec = importlib.util.spec_from_file_location('support', source.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def elf(path):
    data = path.read_bytes()
    assert data[:4] == b'\x7fELF' and data[4] in (1, 2) and data[5] in (1, 2)
    wide, order = data[4] == 2, '<' if data[5] == 1 else '>'
    header = struct.unpack_from(order + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'), data, 16)
    width = 64 if wide else 40
    assert header[10] == width and header[11] > 0
    sections = [struct.unpack_from(order + ('IIQQQQIIQQ' if wide else 'IIIIIIIIII'),
        data, header[5] + index * width) for index in range(header[11])]
    names = sections[header[12]]
    strings = data[names[4]:names[4] + names[5]]
    named = {strings[s[0]:].split(b'\0', 1)[0].decode(): (s, data[s[4]:s[4] + s[5]]) for s in sections}
    return data[:16], header, named


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=('x86_64', 'i386', 'aarch64', 'mips32be', 'mips32le'))
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    parser.add_argument('--symbols', choices=('retained', 'stripped'), default='retained')
    parser.add_argument('--results-root', type=Path,
        default=repository / 'build/test-results/retained-function-aliases')
    parser.add_argument('--mips-fp32', action='store_true', help='Build the explicit O32 FP32 fixture profile')
    parser.add_argument('--hash-style', choices=('default', 'both'), default='default')
    args = parser.parse_args()
    if args.mips_fp32 and not args.target.startswith('mips'):
        parser.error('--mips-fp32 requires a MIPS target')
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = args.results_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='.'.join((args.target, args.role, args.symbols)) + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/retained-function-aliases.cpp'
    protected = [fixture, Path(__file__).resolve(), source / 'retained-function-aliases-gdb.py',
        source / 'retained-function-aliases-gdb.sh', source / 'qemu-socket.sh',
        source / 'elf-layout-gdb-oracle.sh', source / 'dynamic-composite-storage-check.py',
        source / 'dynamic-parameter-storage-check.py', source / 'check-dwarfdump.py',
        source.parent / 'performance/export-benchmark.py',
        source / 'ghidra_scripts/PrepareRetainedAliases.java', source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    extra_sources = []
    if args.target == 'i386':
        extra_sources.append(source.parent / 'fixtures/i386-alias-entry.cpp')
        protected += extra_sources
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    reference, binary = case / 'aliases.reference', case / 'aliases.input'
    prefix = {'x86_64': '', 'i386': '', 'aarch64': 'aarch64-linux-gnu-',
        'mips32be': 'mips-linux-gnu-', 'mips32le': 'mipsel-linux-gnu-'}[args.target]
    cc, objcopy = prefix + 'g++', prefix + 'objcopy'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    if args.target == 'i386':
        flags = ['-m32', '-nostdlib', '-fno-stack-protector', '-Wl,-e,_start',
            *(['-fno-pie', '-static'] if args.role == 'exec' else ['-fPIE', '-static-pie'])]
    if args.mips_fp32:
        flags.append('-mfp32')
    if args.hash_style != 'default':
        flags.append('-Wl,--hash-style=' + args.hash_style)
    run('compile', [cc, '-O1', '-g3', '-gdwarf-5', '-gno-variable-location-views', *flags,
        '-Wl,--build-id=sha1', fixture, *extra_sources, '-o', reference])
    run('strip', [objcopy, '--strip-debug' if args.symbols == 'retained' else '--strip-all', reference, binary])
    before.update({str(reference): support.digest(reference), str(binary): support.digest(binary)})
    write('protected-before.json', before)
    run('symbols', ['readelf', '-sW', reference])
    symbols = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        f = line.split()
        if len(f) == 8 and ('observed' in f[7] or f[7] == 'second_identity'):
            record = {'address': int(f[1], 16), 'size': int(f[2]), 'type': f[3], 'binding': f[4], 'section': int(f[6])}
            assert f[7] not in symbols or symbols[f[7]] == record, 'conflicting static/dynamic symbol records'
            symbols[f[7]] = record
    unique, aliased = '_ZN8observed6uniqueEi', '_ZN8observed7aliasedEi'
    assert symbols[aliased] == symbols['second_identity']
    names = [('analyst_unique', unique, '_ZZN8observed6uniqueEiE13private_count', 7),
        ('analyst_alias', aliased, '_ZZN8observed7aliasedEiE13private_count', 3)]
    rows, prep = [], []
    for name, original, private, value in names:
        f, d = symbols[original], symbols[private]
        assert f['type'] == 'FUNC' and f['binding'] == 'GLOBAL' and d['type'] == 'OBJECT' and d['size'] == 4
        row = {'name': 'recovered::' + name, 'entry': f['address'], 'end': f['address'] + f['size'],
            'original': original, 'privateAddress': d['address'], 'privateValue': value}
        if args.target.startswith('mips'):
            # A MIPS return has a delay slot. Guard the actual jr ra, not the
            # last instruction, and prove the fixture instruction from bytes.
            ident, _, sections = elf(reference)
            section, payload = list(sections.values())[f['section']]
            row['returnInstruction'] = row['end'] - 8
            offset = row['returnInstruction'] - section[3]
            assert offset >= 0 and offset + 8 <= len(payload)
            assert int.from_bytes(payload[offset:offset + 4], 'big' if ident[5] == 2 else 'little') == 0x03e00008
        else:
            row['returnInstruction'] = row['end'] - (1 if args.target in ('x86_64', 'i386') else 4)
        if args.target == 'i386' and args.role != 'exec':
            _, _, sections = elf(reference)
            section, payload = list(sections.values())[f['section']]
            offset = row['entry'] - section[3]
            assert payload[offset] == 0xe8  # Independently decode this fixture's PC-thunk call.
            thunk = row['entry'] + 5 + int.from_bytes(payload[offset + 1:offset + 5], 'little', signed=True)
            thunk_offset = thunk - section[3]
            assert 0 <= thunk_offset <= len(payload) - 4
            assert payload[thunk_offset:thunk_offset + 4] == bytes.fromhex('8b0424c3')
            row['entryThunk'] = {'entry': thunk, 'bytes': '8b0424c3', 'returnPc': row['entry'] + 5}
        rows.append(row)
        prep.append(' '.join([name, hex(row['entry']), hex(row['end']), hex(row['privateAddress'])]))
    write('symbols.json', symbols)
    run('input-symbols', ['readelf', '-sW', binary])
    original_symbols = {}
    for line in (case / 'input-symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in (unique, aliased, 'second_identity'):
            address = int(fields[1], 16)
            assert fields[3] == 'FUNC' and fields[6].isdigit()
            assert fields[7] not in original_symbols or original_symbols[fields[7]] == address
            original_symbols[fields[7]] = address
    write('metadata.json', {'target': args.target, 'role': args.role, 'symbols': args.symbols,
        'originalSymbols': original_symbols, 'mipsFp32': args.mips_fp32, 'functions': rows})
    (case / 'preparation.txt').write_text('\n'.join(prep) + '\n')
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Aliases', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareRetainedAliases.java', 'curate', case / 'preparation.txt', case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    hashes = None
    for iteration in ('first', 'repeat'):
        output = case / 'aliases.dbg'
        run(iteration, [ghidra / 'support/analyzeHeadless', project, 'Aliases', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareRetainedAliases.java', 'observe', case / 'preparation.txt', case / (iteration + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], timeout=240)
        log = (case / (iteration + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in log
        model = json.loads((case / (iteration + '.json')).read_text())
        assert model == json.loads((case / 'import.json').read_text())
        assert Path(unquote(urlsplit(model['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
        if args.role == 'pie-rebased':
            assert model['rebaseDelta'] >= 0x2000000
        current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        if hashes is not None:
            assert hashes == current
        hashes = current
        if iteration == 'first':
            shutil.copyfile(output, case / 'first.dbg')
            shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert not report['failedFunctions'] and report['failure'] is None
        write(iteration + '-report.json', report)
    original, oh, os = elf(binary)
    debug, dh, ds = elf(case / 'aliases.dbg')
    assert original == debug and oh[:4] == dh[:4] and oh[6] == dh[6]
    assert dh[4] == dh[8] == dh[9] == 0
    assert os['.text'][0][3] == ds['.text'][0][3]
    assert os['.note.gnu.build-id'][1] == ds['.note.gnu.build-id'][1]
    for name in ('.symtab', '.strtab'):
        assert (name in os) == (args.symbols == 'retained')
        assert (name in ds) == (args.symbols == 'retained')
        if name in os:
            assert os[name][1] == ds[name][1]
    for variant, artifact in [('compiler', reference), ('forge', case / 'aliases.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n'), ('symbols', '-sW')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict-checks.log'), '--original', binary])
    info = (case / 'forge-info.log').read_text()
    assert 'DW_AT_linkage_name' not in info and 'unbacked_' not in info
    for row in rows:
        assert row['name'] in info
    assert 'unbacked_' not in (case / 'forge-symbols.log').read_text()
    facts_spec = importlib.util.spec_from_file_location('facts', source / 'dynamic-composite-storage-check.py')
    facts = importlib.util.module_from_spec(facts_spec)
    facts_spec.loader.exec_module(facts)
    dies = facts.die_records(info)
    by_offset = {d['offset']: d for d in dies}
    raw = []
    for row in rows:
        function, = [d for d in dies if d['tag'] == 'DW_TAG_subprogram' and facts.facts.die_name(d) == row['name']]
        assert int(function['attrs']['DW_AT_low_pc'], 16) == row['entry']
        assert int(function['attrs']['DW_AT_high_pc'], 0) == row['end'] - row['entry']
        assert 'DW_AT_decl_line' in function['attrs']
        children = list(facts.children(dies, dies.index(function)))
        parameter, = [d for d in children if d['tag'] == 'DW_TAG_formal_parameter']
        assert facts.facts.die_name(parameter) == 'value' and 'DW_AT_location' in parameter['attrs']
        owned, = [d for d in children if d['tag'] == 'DW_TAG_variable' and facts.facts.die_name(d) == 'private_count']
        assert int(re.search(r'DW_OP_addr: ([0-9a-f]+)', owned['attrs']['DW_AT_location'])[1], 16) == row['privateAddress']
        for node in (function, parameter, owned):
            offset = int(re.fullmatch(r'<0x([0-9a-f]+)>', node['attrs']['DW_AT_type'])[1], 16)
            dtype = by_offset[offset]
            assert dtype['tag'] == 'DW_TAG_base_type' and int(dtype['attrs']['DW_AT_byte_size']) == 4
            assert dtype['attrs']['DW_AT_encoding'].split()[0] == '5'
        raw.append({'function': function, 'parameter': parameter, 'private': owned})
    write('raw-dies.json', raw)
    run('gdb-driver', ['bash', source / 'retained-function-aliases-gdb.sh', repository, case, args.target], timeout=240)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Aliases.rep/idata/~index.bak', 'Aliases.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role, 'symbols': args.symbols,
        'inputSha256': before[str(binary)], 'hashes': hashes, 'protectedUnchanged': True, 'projectBackupChanges': changes})
    print('retained-function-aliases-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
