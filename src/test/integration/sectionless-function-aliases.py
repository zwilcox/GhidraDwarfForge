#!/usr/bin/env python3
"""Freshly import sectionless copies of source-built alias fixtures and test real exports."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('elf_support', source / 'retained-function-aliases-export.py')
elf_support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf_support)
spec = importlib.util.spec_from_file_location('inventory_check', source / 'sectionless-alias-check.py')
inventory_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory_check)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def arm_mode_aliases(base):
    """Carry independently validated primary mode cues into the sectionless oracle."""
    original = elf_support.elf(base / 'aliases.input')[2]
    baseline = elf_support.elf(base / 'aliases.dbg')[2]
    if '.symtab' not in baseline:
        return [], {}
    metadata = json.loads((base / 'metadata.json').read_text())
    compiler_symbols = (base / 'symbols.log').read_text()
    elf_support.arm_mode_inventory(original, baseline, compiler_symbols, metadata['functions'])
    table, records = baseline['.symtab']
    names = baseline['.strtab'][1]
    expected = {}
    for offset in range(original['.dynsym'][0][7] * 16, table[7] * 16, 16):
        name, value, size, info, other, section = struct.unpack_from('<IIIBBH', records, offset)
        name = names[name:].split(b'\0', 1)[0].decode()
        expected[name] = (value, size)
    # Without section roles Ghidra also recovers the PLT resolver prefix as a
    # function. Prove its exact four instructions and compiler mapping limits;
    # do not derive an expected cue from the sectionless output being tested.
    plt, code = original['.plt']
    assert struct.unpack_from('<4I', code) == (0xe52de004, 0xe59fe004, 0xe08fe00e, 0xe5bef008)
    plt_index = list(original).index('.plt')
    mappings = {(int(fields[1], 16), fields[7].split('.')[0])
        for line in compiler_symbols.splitlines() if len(fields := line.split()) == 8
        and fields[6] == str(plt_index) and fields[7].split('.')[0] in ('$a', '$t', '$d')}
    assert (plt[3], '$a') in mappings and (plt[3] + 16, '$d') in mappings
    name = '__forge_arm_mode_%08x' % plt[3]
    assert name not in expected or expected[name] == (plt[3], 16)
    expected[name] = (plt[3], 16)
    return ([{'alias': name, 'entry': value & ~1, 'size': size}
        for name, (value, size) in sorted(expected.items())],
        {name: value for name, (value, size) in expected.items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=('x86_64', 'i386', 'aarch64', 'arm32', 'mips32be', 'mips32le'))
    parser.add_argument('--arm-mode', choices=('arm', 'thumb', 'mixed'))
    parser.add_argument('--base-root', type=Path, required=True)
    parser.add_argument('--expect-omission', action='store_true', help='Require complete-count diagnostic and intact primary debugging')
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'))
    parser.add_argument('--output', type=Path, default=repository / 'build/test-results/sectionless-function-aliases')
    args = parser.parse_args()
    assert (args.target == 'arm32') == (args.arm_mode is not None), 'ARM fixtures require an explicit mode'
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    jar = module / 'lib/GhidraDwarfForge.jar'
    args.output.mkdir(parents=True, exist_ok=True)
    candidates = []
    for base in sorted(args.base_root.resolve().glob('**/' + args.target + '.*/metadata.json')):
        metadata = json.loads(base.read_text())
        if (metadata['symbols'] == 'stripped' and (args.role is None or metadata['role'] == args.role) and
                (args.arm_mode is None or metadata.get('armMode') == args.arm_mode)):
            candidates.append(base.parent)
    assert len(candidates) == (1 if args.role else 3), 'require one passing source fixture per requested role'
    for base in candidates:
        metadata = json.loads((base / 'metadata.json').read_text())
        if args.target == 'arm32':
            # A passing compiler oracle supplies fixture facts. The existing
            # unaliased Thumb PIE export has a separately recorded mode gap.
            assert json.loads((base / 'compiler-gdb.json').read_text())['status'] == 'PASS'
            compile_command = json.loads((base / 'compile.command.json').read_text())
            assert '-march=armv7-a' in compile_command
            metadata['gdbArchitecture'] = 'armv7'
        else:
            assert json.loads((base / 'result.json').read_text())['status'] == 'PASS'
        case = Path(tempfile.mkdtemp(prefix=args.target + '.' + metadata['role'] + '.', dir=args.output.resolve()))
        print(case, flush=True)
        protected = {str(p): digest(p) for p in base.glob('*') if p.is_file()}
        protected.update({str(p): digest(p) for p in module.rglob('*') if p.is_file()})
        protected.update({str(p): digest(p) for p in (Path(__file__).resolve(),
            source / 'ghidra_scripts/PrepareRetainedAliases.java', source / 'ghidra_scripts/PrepareLocalSymbolMerge.java',
            source / 'ghidra_scripts/RebaseFixtureProgram.java', source / 'local-symbol-merge-gdb.py',
            source / 'local-symbol-merge-gdb.sh', source / 'retained-function-aliases-gdb.py',
            source / 'retained-function-aliases-gdb.sh', source / 'qemu-socket.sh', source / 'elf-layout-gdb-oracle.sh',
            source / 'check-dwarfdump.py', source / 'sectionless-alias-check.py',
            source / 'retained-function-aliases-export.py')})
        binary = case / 'aliases.input'
        data = bytearray((base / 'aliases.input').read_bytes())
        wide, order = data[4] == 2, '<' if data[5] == 1 else '>'
        struct.pack_into(order + ('Q' if wide else 'I'), data, 40 if wide else 32, 0)
        struct.pack_into(order + 'HH', data, 60 if wide else 48, 0, 0)
        binary.write_bytes(data)
        binary.chmod(0o755)
        protected[str(binary)] = digest(binary)
        (case / 'protected-before.json').write_text(json.dumps(protected, indent=4) + '\n')
        project = case / 'project'
        project.mkdir()

        def run(name, command, timeout=240):
            command = list(map(str, command))
            (case / (name + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            (case / (name + '.log')).write_bytes(result.stdout)
            (case / (name + '.stderr')).write_bytes(result.stderr)
            assert result.returncode == 0, (name, result.returncode, result.stderr.decode(errors='replace'))
            if Path(command[0]).name != 'analyzeHeadless':
                assert not result.stderr, (name, result.stderr)
            return result.stdout.decode()

        rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if metadata['role'] == 'pie-rebased' else []
        text = run('import', [ghidra / 'support/analyzeHeadless', project, 'Aliases', '-import', binary,
            '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
            '-postScript', 'PrepareRetainedAliases.java', 'curate', base / 'preparation.txt', case / 'primary-curated.json',
            '-postScript', 'PrepareLocalSymbolMerge.java', 'curate', case / 'aliases.json',
            '-postScript', 'PrepareRetainedAliases.java', 'observe', base / 'preparation.txt', case / 'curated.json'])
        assert 'REPORT: Analysis succeeded' in text and (case / 'aliases.json').is_file()
        project_before = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
        (case / 'project-before.json').write_text(json.dumps(project_before, indent=4) + '\n')
        for iteration in ('first', 'repeat'):
            text = run(iteration, [ghidra / 'support/analyzeHeadless', project, 'Aliases', '-process', binary.name,
                '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
                '-postScript', 'PrepareRetainedAliases.java', 'observe', base / 'preparation.txt', case / (iteration + '-model.json'),
                '-postScript', 'PrepareLocalSymbolMerge.java', 'observe', case / (iteration + '-aliases.json'),
                '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'aliases.dbg')])
            assert 'GhidraDwarfForge symbol export PASS' in text
            report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
                for line in text.splitlines() if 'GhidraDwarfForge report: {' in line]
            assert not report['failedFunctions'] and report['failure'] is None
            if args.expect_omission:
                assert 'Omitted function aliases: complete PT_DYNAMIC symbol count unavailable' in text
            else:
                assert 'Omitted function alias' not in text, text
            model = json.loads((case / (iteration + '-model.json')).read_text())
            assert model == json.loads((case / 'curated.json').read_text())
            assert Path(unquote(urlsplit(model['origin']).path)).resolve() == jar
            assert json.loads((case / (iteration + '-aliases.json')).read_text()) == json.loads((case / 'aliases.json').read_text())
            if iteration == 'first':
                shutil.copyfile(case / 'aliases.dbg', case / 'first.dbg')
                shutil.copyfile(case / 'aliases.dbg.c', case / 'first.dbg.c')
            else:
                assert (case / 'aliases.dbg').read_bytes() == (case / 'first.dbg').read_bytes()
                assert (case / 'aliases.dbg.c').read_bytes() == (case / 'first.dbg.c').read_bytes()
        aliases = {row['primary']: row for row in json.loads((case / 'aliases.json').read_text())}
        metadata['input'] = str(binary)
        metadata['inputSymbols'] = 'stripped'
        metadata['symbols'] = 'stripped' if args.expect_omission else 'retained'
        metadata['retainedOriginals'] = []
        for row in metadata['functions']:
            metadata['retainedOriginals'].append({'name': row['original'], 'entry': row['entry'],
                'end': row['end'], 'present': row['original'] in metadata['originalSymbols']})
            if row['name'].endswith('analyst_alias'):
                metadata['retainedOriginals'].append({'name': 'second_identity', 'entry': row['entry'],
                    'end': row['end'], 'present': 'second_identity' in metadata['originalSymbols']})
            if not args.expect_omission:
                row['original'] = aliases[row['name']]['alias']
        (case / 'metadata.json').write_text(json.dumps(metadata, indent=4) + '\n')
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(view, ['readelf', '--debug-dump=' + view, case / 'aliases.dbg'])
        run('headers', ['readelf', '-hSWs', case / 'aliases.dbg'])
        assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', case / 'aliases.dbg'])
        run('strict', ['python3', source / 'check-dwarfdump.py', case / 'aliases.dbg',
            case / 'strict-checks.log', '--original', binary, '--frame-reference', base / 'aliases.input'])
        _, _, emitted = elf_support.elf(case / 'aliases.dbg')
        if args.expect_omission:
            assert '.symtab' not in emitted
            shutil.copy2(base / 'aliases.reference', case / 'aliases.reference')
            run('gdb', ['bash', source / 'retained-function-aliases-gdb.sh', repository, case, args.target])
            for index, label in enumerate(aliases.values()):
                result = subprocess.run(['gdb-multiarch', '-q', '-nx', '-batch',
                    '-ex', 'set debuginfod enabled off', '-ex', 'set auto-solib-add off',
                    '-ex', 'file ' + str(binary), '-ex', 'symbol-file ' + str(case / 'aliases.dbg'),
                    '-ex', "print &'" + label['alias'] + "'"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
                (case / ('omitted-alias-' + str(index) + '.log')).write_bytes(result.stdout)
                assert result.returncode != 0 and b'No symbol' in result.stdout
        else:
            assert '.symtab' in emitted
            symbol_values = ({aliases[row['name']]['alias']: row['elfSymbolValue'] for row in metadata['functions']}
                             if args.target == 'arm32' else None)
            expected_aliases = list(aliases.values())
            if args.target == 'arm32':
                cues, cue_values = arm_mode_aliases(base)
                expected_aliases += cues
                assert not (symbol_values.keys() & cue_values.keys())
                symbol_values.update(cue_values)
            inventory_check.verify(base / 'aliases.input', binary, case / 'aliases.dbg',
                expected_aliases, case / 'raw-inventory.json', symbol_values)
            if metadata['role'] == 'exec':
                inventory_check.corruption_controls(base / 'aliases.input', binary, case / 'aliases.dbg',
                    expected_aliases, case / 'corruption-controls', symbol_values)
            run('gdb', ['bash', source / 'local-symbol-merge-gdb.sh', repository, case, args.target, base / 'compiler-gdb.log'])
        after = {p: digest(Path(p)) for p in protected}
        (case / 'protected-after.json').write_text(json.dumps(after, indent=4) + '\n')
        assert after == protected
        project_after = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
        (case / 'project-after.json').write_text(json.dumps(project_after, indent=4) + '\n')
        changes = {p for p in project_before.keys() | project_after.keys() if project_before.get(p) != project_after.get(p)}
        assert changes <= {'Aliases.rep/idata/~index.bak', 'Aliases.rep/idata/~journal.bak'}, changes
        (case / 'result.json').write_text(json.dumps({'status': 'PASS', 'target': args.target, 'role': metadata['role'],
            'aliasDisposition': 'omitted-incomplete-count' if args.expect_omission else 'emitted',
            'baseCase': str(base), 'jarSha256': digest(jar), 'inputSha256': digest(binary),
            'sidecarSha256': digest(case / 'aliases.dbg'), 'projectBackupChanges': sorted(changes)}, indent=4) + '\n')
        print('sectionless-function-aliases=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
