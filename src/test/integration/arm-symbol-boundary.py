#!/usr/bin/env python3
"""Compile and export a sectionless ARM EABI5 Thumb definition at a PT_LOAD end."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('inventory', source / 'sectionless-alias-check.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--conflict', choices=('function-tag', 'mapping'), help='Require omission for contradictory original ELF mode metadata')
    parser.add_argument('--output', type=Path, default=repository / 'build/test-results/arm-symbol-boundary')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    args.output.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='run.', dir=args.output.resolve()))
    print(case, flush=True)
    fixture = repository / 'src/test/fixtures/arm-symbol-boundary.S'
    linker = fixture.with_suffix('.ld')
    protected = {str(p): digest(p) for p in module.rglob('*') if p.is_file()}
    protected.update({str(p): digest(p) for p in [fixture, linker, Path(__file__).resolve(),
        source / 'arm-symbol-boundary-gdb.py', source / 'arm-symbol-boundary-gdb.sh',
        source / 'ghidra_scripts/PrepareArmBoundary.java', source / 'sectionless-alias-check.py']})

    def run(name, command, timeout=240):
        command = list(map(str, command))
        (case / (name + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
        result = subprocess.run(command, capture_output=True, timeout=timeout)
        (case / (name + '.log')).write_bytes(result.stdout)
        (case / (name + '.stderr')).write_bytes(result.stderr)
        assert result.returncode == 0, (name, result.returncode, result.stderr)
        if Path(command[0]).name != 'analyzeHeadless':
            assert not result.stderr, (name, result.stderr)
        return result.stdout.decode()

    reference = case / 'reference.elf'
    compile_args = [os.environ.get('ARM_CC', 'arm-linux-gnueabihf-gcc'), '-nostdlib', '-shared',
        '-Wl,-Bsymbolic', '-Wl,--build-id=none', '-Wl,--hash-style=both', '-Wl,-T,' + str(linker), fixture, '-o']
    run('compile', [*compile_args, reference])
    run('compile-repeat', [*compile_args, case / 'reference.repeat.elf'])
    assert reference.read_bytes() == (case / 'reference.repeat.elf').read_bytes()
    data = bytearray(reference.read_bytes())
    assert data[:7] == b'\x7fELF\x01\x01\x01'
    header = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
    assert header[:3] == (3, 40, 1) and header[6] & 0xff000000 == 0x05000000
    loads = [struct.unpack_from('<IIIIIIII', data, header[4] + i * header[8]) for i in range(header[9])]
    executable, = [row for row in loads if row[0] == 1 and row[6] & 1]
    assert executable[2] + executable[4] == executable[2] + executable[5] == 0x1020
    _, _, sections = inventory.elf_support.elf(reference)
    table, records = sections['.dynsym']
    strings = list(sections.values())[table[6]][1]
    boundary = []
    for offset in range(0, len(records), 16):
        name, value, size, info, other, section = struct.unpack_from('<IIIBBH', records, offset)
        if strings[name:strings.index(0, name)] == b'boundary':
            boundary.append((value, size, info & 15, section))
    assert len(boundary) == 1 and boundary[0][:3] == (0x101d, 4, 2) and boundary[0][3] != 0
    assert (boundary[0][0] & ~1) + boundary[0][1] == executable[2] + executable[5]
    mutations = []
    if args.conflict == 'function-tag':
        for key in ('.dynsym', '.symtab'):
            table, records = sections[key]
            strings = list(sections.values())[table[6]][1]
            for offset in range(0, len(records), 16):
                name, value, size, info, other, section = struct.unpack_from('<IIIBBH', records, offset)
                if strings[name:strings.index(0, name)] == b'boundary':
                    assert value == 0x101d and size == 4
                    position = table[4] + offset + 4
                    struct.pack_into('<I', data, position, 0x101c)
                    mutations.append({'table': key, 'offset': position, 'before': value, 'after': 0x101c})
        assert len(mutations) == 2
    elif args.conflict == 'mapping':
        table, records = sections['.symtab']
        strings_table, strings = list(sections.values())[table[6]]
        for offset in range(0, len(records), 16):
            name, value, size, info, other, section = struct.unpack_from('<IIIBBH', records, offset)
            if strings[name:strings.index(0, name)] == b'$t':
                assert value == 0x101c and info == 0
                position = strings_table[4] + name + 1
                data[position] = ord('a')
                mutations.append({'table': '.strtab', 'offset': position, 'before': ord('t'), 'after': ord('a')})
        assert len(mutations) == 1
    else:
        struct.pack_into('<I', data, 32, 0)
        struct.pack_into('<HH', data, 48, 0, 0)
    binary = case / ('mode-conflict.elf' if args.conflict else 'sectionless.elf')
    (case / 'mutations.json').write_text(json.dumps(mutations, indent=4) + '\n')
    binary.write_bytes(data)
    binary.chmod(0o755)
    protected.update({str(p): digest(p) for p in (reference, binary)})
    (case / 'protected-before.json').write_text(json.dumps(protected, indent=4) + '\n')
    for label, path in [('reference', reference), ('sectionless', binary)]:
        run(label + '-execute', ['qemu-arm-static', path], 30)
        for option in ['-h', '-SW', '-n']:
            run(label + option, ['readelf', option, path])
    project = case / 'project'
    project.mkdir()
    text = run('import', [ghidra / 'support/analyzeHeadless', project, 'Boundary', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        '-postScript', 'PrepareArmBoundary.java', 'curate', case / 'curated.json'])
    assert 'REPORT: Analysis succeeded' in text and (case / 'curated.json').is_file()
    before = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
    for iteration in ['first', 'repeat']:
        text = run(iteration, [ghidra / 'support/analyzeHeadless', project, 'Boundary', '-process', binary.name,
            '-noanalysis', '-readOnly', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareArmBoundary.java', 'observe', case / (iteration + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'boundary.dbg')])
        assert 'GhidraDwarfForge symbol export PASS' in text
        if args.conflict:
            reason = ('original function tag contradicts decoded mode' if args.conflict == 'function-tag'
                else 'original mapping at entry contradicts decoded mode')
            assert 'Omitted function alias alternate_boundary: ARM mode policy: ' + reason in text
        else:
            assert 'Omitted function alias' not in text
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in text.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert not report['failedFunctions'] and report['failure'] is None
        model = json.loads((case / (iteration + '.json')).read_text())
        assert Path(unquote(urlsplit(model['origin']).path)).resolve() == module / 'lib/GhidraDwarfForge.jar'
        assert json.loads((case / (iteration + '.json')).read_text()) == json.loads((case / 'curated.json').read_text())
        hashes = [digest(case / name) for name in ('boundary.dbg', 'boundary.dbg.c')]
        if iteration == 'first':
            first = hashes
        else:
            assert first == hashes
    after = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
    changes = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    assert changes <= {'Boundary.rep/idata/~index.bak', 'Boundary.rep/idata/~journal.bak'}
    sidecar = case / 'boundary.dbg'
    # Source-owned instruction bytes and original section addresses establish
    # both primary mode cues independently of the emitted symbol inventory.
    assert sections['.text'][0][3] == 0x1000
    assert sections['.text'][1] == bytes.fromhex(
        '0700a0e3 040000fa 0c0050e3 0100a013 0000a003 0170a0e3 000000ef')
    assert sections['.tail'][0][3] == 0x101c
    assert sections['.tail'][1] == bytes.fromhex('05307047')
    aliases = [
        {'alias': '__forge_arm_mode_00001000', 'entry': 0x1000, 'size': 28},
        {'alias': '__forge_arm_mode_0000101c', 'entry': 0x101c, 'size': 4},
        {'alias': 'alternate_boundary', 'entry': 0x101c, 'size': 4},
    ]
    values = {'__forge_arm_mode_00001000': 0x1000,
        '__forge_arm_mode_0000101c': 0x101d, 'alternate_boundary': 0x101d}
    if args.conflict:
        _, _, old_sections = inventory.elf_support.elf(binary)
        _, _, emitted = inventory.elf_support.elf(sidecar)
        for name in ('.symtab', '.strtab', '.dynsym', '.dynstr'):
            assert old_sections[name][1] == emitted[name][1], 'original mode metadata was rewritten: ' + name
    else:
        inventory.verify(reference, binary, sidecar, aliases, case / 'raw-inventory.json', values)
        inventory.corruption_controls(reference, binary, sidecar, aliases, case / 'raw-controls', values)
    for option in ['-h', '-SW', '-sW', '-n']:
        run('sidecar' + option, ['readelf', option, sidecar])
    for view in ['info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges']:
        run(view, ['readelf', '--debug-dump=' + view, sidecar])
    assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', sidecar])
    run('strict', ['python3', source / 'check-dwarfdump.py', sidecar, case / 'strict-checks.log', '--original', binary])
    run('runtime', ['bash', source / 'arm-symbol-boundary-gdb.sh', repository, case, args.conflict or 'none'])
    assert all(digest(Path(path)) == value for path, value in protected.items())
    (case / 'result.json').write_text(json.dumps({'status': 'PASS', 'conflict': args.conflict,
        'runtimeScope': 'compiler pass; conflicting mapping rejects stopped decode' if args.conflict == 'mapping'
            else 'compiler and curated function pass', 'codeEnd': '0x1020', 'taggedValue': '0x101d',
        'size': 4, 'originalSha256': digest(binary), 'jarSha256': digest(module / 'lib/GhidraDwarfForge.jar'),
        'artifactHashes': hashes, 'projectBackupChanges': sorted(changes)}, indent=4) + '\n')
    print('ARM_SYMBOL_BOUNDARY_PASS', flush=True)


if __name__ == '__main__':
    main()
