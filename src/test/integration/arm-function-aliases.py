#!/usr/bin/env python3
"""Prove automatic ARM/Thumb alias exports against compiler facts and an isolated writer."""
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

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('elf_support', source / 'retained-function-aliases-export.py')
elf_support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf_support)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--base-root', type=Path, required=True)
    parser.add_argument('--arm-mode', choices=('arm', 'thumb', 'mixed'), required=True)
    parser.add_argument('--results-root', type=Path, default=repository / 'build/test-results/arm-function-aliases')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    jar = module / 'lib/GhidraDwarfForge.jar'
    root = args.results_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    bases = sorted(args.base_root.resolve().glob('arm32.*/metadata.json'))
    assert len(bases) == 6
    population = {(json.loads(p.read_text())['role'], json.loads(p.read_text())['symbols']) for p in bases}
    assert population == {(role, symbols) for role in ('exec', 'pie', 'pie-rebased') for symbols in ('retained', 'stripped')}
    probe = repository / 'src/test/java/ghidradwarfforge/elf/LocalSymbolMergeProbe.java'
    classes = Path(tempfile.mkdtemp(prefix='classes.', dir=root))
    java = str(Path(os.environ['FORGE_JAVA21_HOME']) / 'bin/java') if 'FORGE_JAVA21_HOME' in os.environ else 'java'
    javac = str(Path(os.environ['JAVA_HOME']) / 'bin/javac') if 'JAVA_HOME' in os.environ else 'javac'
    command = [javac, '--release', '21', '-cp', str(jar), '-d', str(classes), str(probe)]
    result = subprocess.run(command, capture_output=True, timeout=60)
    (classes / 'compile.command.json').write_text(json.dumps(command) + '\n')
    (classes / 'compile.stdout').write_bytes(result.stdout)
    (classes / 'compile.stderr').write_bytes(result.stderr)
    assert result.returncode == 0 and not result.stderr
    for metadata_path in bases:
        base = metadata_path.parent
        metadata = json.loads(metadata_path.read_text())
        assert metadata['target'] == 'arm32' and metadata['armMode'] == args.arm_mode
        prepared = json.loads((base / 'result.json').read_text())
        assert prepared['status'] == 'PREPARED_FOR_ALIAS_RUNTIME' and prepared['runtime'] == 'compiler-only'
        assert json.loads((base / 'compiler-gdb.json').read_text())['status'] == 'PASS'
        assert json.loads((base / 'protected-after.json').read_text())[str(jar)] == digest(jar)
        case = Path(tempfile.mkdtemp(prefix='.'.join((args.arm_mode, metadata['role'], metadata['symbols'])) + '.', dir=root))
        print(case, flush=True)
        protected = [p for p in base.rglob('*') if p.is_file()] + [p for p in module.rglob('*') if p.is_file()]
        protected += [Path(__file__), probe, source / 'retained-function-aliases-export.py',
            source / 'local-symbol-merge-gdb.py', source / 'local-symbol-merge-gdb.sh',
            source / 'ghidra_scripts/PrepareLocalSymbolMerge.java', source / 'check-dwarfdump.py']
        protected += list(classes.glob('**/*.class'))
        before = {str(p): digest(p) for p in protected}
        (case / 'protected-before.json').write_text(json.dumps(before, indent=4) + '\n')

        def run(label, argv, timeout=240):
            argv = list(map(str, argv))
            (case / (label + '.command.json')).write_text(json.dumps(argv, indent=4) + '\n')
            outcome = subprocess.run(argv, capture_output=True, timeout=timeout)
            (case / (label + '.log')).write_bytes(outcome.stdout)
            (case / (label + '.stderr')).write_bytes(outcome.stderr)
            assert outcome.returncode == 0, (label, case)
            if Path(argv[0]).name != 'analyzeHeadless':
                assert not outcome.stderr, (label, outcome.stderr)
            return outcome.stdout.decode()

        shutil.copytree(base / 'project', case / 'project')
        shutil.copy2(base / 'aliases.input', case / 'aliases.input')
        headless = [ghidra / 'support/analyzeHeadless', case / 'project', 'Aliases', '-process', 'aliases.input', '-noanalysis']
        export = ['-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'aliases.dbg')]
        assert 'GhidraDwarfForge symbol export PASS' in run('baseline', [*headless, '-readOnly', *export])
        shutil.copyfile(case / 'aliases.dbg', case / 'baseline.dbg')
        shutil.copyfile(case / 'aliases.dbg.c', case / 'baseline.dbg.c')
        for mode in ('curate', 'observe'):
            log = run(mode, [*headless, *(['-readOnly'] if mode == 'observe' else []), '-scriptPath', source / 'ghidra_scripts',
                '-postScript', 'PrepareLocalSymbolMerge.java', mode, case / (mode + '.json'), *export])
            assert 'GhidraDwarfForge symbol export PASS' in log and 'Omitted function alias' not in log
            report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
                for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
            assert not report['failedFunctions'] and report['failure'] is None
            if mode == 'curate':
                shutil.copyfile(case / 'aliases.dbg', case / 'automatic.dbg')
                project_before = {str(p.relative_to(case / 'project')): digest(p) for p in (case / 'project').rglob('*') if p.is_file()}
        assert (case / 'automatic.dbg').read_bytes() == (case / 'aliases.dbg').read_bytes()
        assert (case / 'baseline.dbg.c').read_bytes() == (case / 'aliases.dbg.c').read_bytes()
        labels = json.loads((case / 'curate.json').read_text())
        assert labels == json.loads((case / 'observe.json').read_text())
        labels = {row['primary']: row for row in labels}
        metadata['inputSymbols'] = metadata['symbols']
        metadata['symbols'] = 'retained'
        metadata['input'] = str(case / 'aliases.input')
        metadata['retainedOriginals'] = []
        expected = {}
        for row in metadata['functions']:
            for name in [row['original']] + (['second_identity'] if row['name'].endswith('analyst_alias') else []):
                metadata['retainedOriginals'].append({'name': name, 'entry': row['entry'], 'end': row['end'],
                    'present': name in metadata['originalSymbols']})
            label = labels[row['name']]
            assert label['entry'] == row['entry'] and label['size'] == row['end'] - row['entry']
            assert label['source'] == 'USER_DEFINED' and not label['isPrimary']
            row['original'] = label['alias']
            expected[label['alias']] = (row['elfSymbolValue'], label['size'])
        (case / 'metadata.json').write_text(json.dumps(metadata, indent=4) + '\n')
        _, _, original = elf_support.elf(case / 'aliases.input')
        _, _, baseline = elf_support.elf(case / 'baseline.dbg')
        _, _, automatic = elf_support.elf(case / 'automatic.dbg')
        records = []
        if '.symtab' not in original and '.symtab' in baseline:
            elf_support.arm_mode_inventory(original, baseline, (base / 'symbols.log').read_text(), metadata['functions'])
            table, payload = baseline['.symtab']
            names = baseline['.strtab'][1]
            for index in range(original['.dynsym'][0][7], table[7]):
                name, value, size, info, other, section = struct.unpack_from('<IIIBBH', payload, index * 16)
                assert info == 2 and other == 0
                records.append([names[name:].split(b'\0', 1)[0].decode(), value & ~1, size, section, value])
        section = list(original).index('.text')
        records += [[row['original'], row['entry'], row['end'] - row['entry'], section, row['elfSymbolValue']]
            for row in metadata['functions']]
        (case / 'symbols.tsv').write_text(''.join('\t'.join(map(str, row)) + '\n' for row in records))
        for name in ('writer.dbg', 'writer-repeat.dbg'):
            text = run(name, [java, '-cp', os.pathsep.join((str(classes), str(jar))), 'ghidradwarfforge.elf.LocalSymbolMergeProbe',
                case / 'aliases.input', case / 'baseline.dbg', case / 'symbols.tsv', case / name, len(records)])
            assert 'java=21.' in text and 'curated-alias-writer=PASS' in text
            assert jar.resolve().as_uri() in text.replace('file:/', 'file:///')
            assert (case / name).read_bytes() == (case / 'automatic.dbg').read_bytes()
        for name, (_, payload) in baseline.items():
            if name.startswith('.debug_'):
                assert automatic[name][1] == payload
        table, payload = baseline['.symtab'] if '.symtab' in baseline else baseline['.dynsym']
        names = baseline['.strtab' if '.symtab' in baseline else '.dynstr'][1]
        new, data = automatic['.symtab']
        strings = automatic['.strtab'][1]
        split = table[7] * 16
        assert new[7] == table[7] + 2 and data[:split] + data[split + 32:] == payload and strings.startswith(names)
        actual = {}
        for offset in range(split, split + 32, 16):
            name, value, size, info, other, index = struct.unpack_from('<IIIBBH', data, offset)
            assert info == 2 and other == 0 and index == section
            actual[strings[name:].split(b'\0', 1)[0].decode()] = (value, size)
        assert actual == expected
        assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', case / 'aliases.dbg'])
        run('strict', ['python3', source / 'check-dwarfdump.py', case / 'aliases.dbg', case / 'strict-checks.log',
            '--original', case / 'aliases.input'])
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run('readelf-' + view, ['readelf', '--debug-dump=' + view, case / 'aliases.dbg'])
        for label, option in (('headers', '-h'), ('sections', '-SW'), ('notes', '-n'), ('symbols', '-sW')):
            run('readelf-' + label, ['readelf', option, case / 'aliases.dbg'])
        run('gdb', ['bash', source / 'local-symbol-merge-gdb.sh', repository, case, 'arm32', base / 'compiler-gdb.log'])
        gdb = json.loads((case / 'forge-gdb.json').read_text())
        assert gdb['status'] == 'PASS' and len(gdb['calls']) == 4 and len(gdb['staticInstructions']) == 2
        after = {str(p): digest(p) for p in protected}
        assert after == before
        assert digest(case / 'aliases.input') == digest(base / 'aliases.input')
        project_after = {str(p.relative_to(case / 'project')): digest(p) for p in (case / 'project').rglob('*') if p.is_file()}
        changes = {p for p in project_before.keys() | project_after.keys() if project_before.get(p) != project_after.get(p)}
        assert changes <= {'Aliases.rep/idata/~index.bak', 'Aliases.rep/idata/~journal.bak'}
        for name, value in [('protected-after', after), ('project-before', project_before), ('project-after', project_after)]:
            (case / (name + '.json')).write_text(json.dumps(value, indent=4) + '\n')
        result = {'status': 'PASS', 'armMode': args.arm_mode, 'role': metadata['role'], 'symbols': metadata['inputSymbols'],
            'baseCase': str(base), 'jarSha256': digest(jar), 'automaticExportMatchesIndependentWriter': True,
            'projectBackupChanges': sorted(changes), 'aliasValues': actual}
        (case / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
        print('arm-function-aliases=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
