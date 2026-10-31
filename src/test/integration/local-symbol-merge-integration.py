#!/usr/bin/env python3
"""Compare automatic analyst-alias export with independently invoked installed ELF packaging."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('support', source.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
spec = importlib.util.spec_from_file_location('elf_support', source / 'retained-function-aliases-export.py')
elf_support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf_support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=('x86_64', 'i386', 'aarch64', 'mips32be', 'mips32le'))
    parser.add_argument('--symbols', choices=('both', 'retained', 'stripped'), default='both')
    parser.add_argument('--base-root', type=Path,
        default=repository / 'build/test-results/retained-function-aliases')
    parser.add_argument('--previous-jar', type=Path)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    jar = module / 'lib/GhidraDwarfForge.jar'
    base_root = args.base_root.resolve()
    bases = sorted(base_root.glob(args.target + '.*'))
    if args.symbols != 'both':
        bases = [base for base in bases if json.loads((base / 'metadata.json').read_text())['symbols'] == args.symbols]
    expected_cases = 6 if args.symbols == 'both' else 3
    assert len(bases) == expected_cases, 'run the fresh retained/stripped alias cases first'
    root = repository / 'build/test-results/local-symbol-merge'
    root.mkdir(parents=True, exist_ok=True)
    compilation = Path(tempfile.mkdtemp(prefix=args.target + '.classes.', dir=root))
    probe = repository / 'src/test/java/ghidradwarfforge/elf/LocalSymbolMergeProbe.java'
    javac = str(Path(os.environ['JAVA_HOME']) / 'bin/javac') if 'JAVA_HOME' in os.environ else 'javac'
    java = str(Path(os.environ['FORGE_JAVA21_HOME']) / 'bin/java') if 'FORGE_JAVA21_HOME' in os.environ else 'java'
    support.run([javac, '--release', '21', '-cp', jar, '-d', compilation, probe], compilation / 'compile.log')
    support.require_clean(compilation / 'compile.log')
    completed = []
    for base in bases:
        original_metadata = json.loads((base / 'metadata.json').read_text())
        assert original_metadata['target'] == args.target
        assert json.loads((base / 'result.json').read_text())['status'] == 'PASS'
        base_protected = json.loads((base / 'protected-after.json').read_text())
        assert base_protected[str(jar)] == support.digest(jar), 'base export used a different installed JAR'
        role, symbols = original_metadata['role'], original_metadata['symbols']
        case = Path(tempfile.mkdtemp(prefix='.'.join((args.target, role, symbols)) + '.', dir=root))
        print(case, flush=True)

        def write(name, value):
            (case / name).write_text(json.dumps(value, indent=4) + '\n')

        def run(name, command, **kwargs):
            result = support.run(command, case / (name + '.log'), **kwargs)
            if Path(command[0]).name != 'analyzeHeadless':
                support.require_clean(case / (name + '.log'))
            return result

        protected = [p for p in base.rglob('*') if p.is_file()]
        protected += [p for p in module.rglob('*') if p.is_file()]
        protected += [probe, Path(__file__).resolve(), source / 'local-symbol-merge-gdb.py',
            source / 'local-symbol-merge-gdb.sh', source / 'ghidra_scripts/PrepareLocalSymbolMerge.java',
            source / 'retained-function-aliases-export.py', source / 'qemu-socket.sh',
            source / 'elf-layout-gdb-oracle.sh', source / 'check-dwarfdump.py',
            source.parent / 'performance/export-benchmark.py']
        protected += list(compilation.rglob('*.class'))
        if args.previous_jar:
            protected.append(args.previous_jar.resolve(strict=True))
        before = {str(p): support.digest(p) for p in protected}
        write('protected-before.json', before)
        shutil.copytree(base / 'project', case / 'project')
        shutil.copy2(base / 'aliases.input', case / 'aliases.input')
        # Export the unchanged saved program at the same final source path before
        # adding labels. This is the independent DWARF/source baseline.
        run('before-aliases', [ghidra / 'support/analyzeHeadless', case / 'project', 'Aliases',
            '-process', 'aliases.input', '-noanalysis', '-readOnly', '-postScript',
            'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'aliases.dbg')], timeout=240)
        assert 'GhidraDwarfForge symbol export PASS' in (case / 'before-aliases.log').read_text()
        shutil.copyfile(case / 'aliases.dbg', case / 'baseline.dbg')
        shutil.copyfile(case / 'aliases.dbg.c', case / 'baseline.dbg.c')
        for mode in ('curate', 'observe'):
            run(mode, [ghidra / 'support/analyzeHeadless', case / 'project', 'Aliases',
                '-process', 'aliases.input', '-noanalysis', *(['-readOnly'] if mode == 'observe' else []),
                '-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareLocalSymbolMerge.java',
                mode, case / (mode + '.json'), '-postScript', 'GhidraDwarfForge.java',
                '--packaged-natives', '--output=' + str(case / 'aliases.dbg')], timeout=240)
            log = (case / (mode + '.log')).read_text()
            assert 'GhidraDwarfForge symbol export PASS' in log
            report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
                for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
            assert not report['failedFunctions'] and report['failure'] is None
            if mode == 'curate':
                shutil.copyfile(case / 'aliases.dbg', case / 'automatic.dbg')
                shutil.copyfile(case / 'aliases.dbg.c', case / 'automatic.dbg.c')
                snapshot = {str(p.relative_to(case / 'project')): support.digest(p)
                    for p in (case / 'project').rglob('*') if p.is_file()}
                write('project-before.json', snapshot)
        assert (case / 'aliases.dbg').read_bytes() == (case / 'automatic.dbg').read_bytes()
        assert (case / 'aliases.dbg.c').read_bytes() == (case / 'baseline.dbg.c').read_bytes()
        labels = json.loads((case / 'curate.json').read_text())
        assert labels == json.loads((case / 'observe.json').read_text())
        labels = {row['primary']: row for row in labels}
        metadata = json.loads(json.dumps(original_metadata))
        metadata['inputSymbols'] = symbols
        metadata['symbols'] = 'retained'  # The supplemental analyst aliases must exist.
        metadata['input'] = str(case / 'aliases.input')
        metadata['retainedOriginals'] = []
        for row in metadata['functions']:
            metadata['retainedOriginals'].append({'name': row['original'], 'entry': row['entry'], 'end': row['end'],
                'present': row['original'] in metadata['originalSymbols']})
            if row['name'].endswith('analyst_alias'):
                metadata['retainedOriginals'].append({'name': 'second_identity', 'entry': row['entry'], 'end': row['end'],
                    'present': 'second_identity' in metadata['originalSymbols']})
            label = labels[row['name']]
            assert label['entry'] == row['entry'] and label['size'] == row['end'] - row['entry']
            assert label['source'] == 'USER_DEFINED' and not label['isPrimary']
            row['original'] = label['alias']
        write('metadata.json', metadata)
        negative = subprocess.run(['gdb-multiarch', '-q', '-nx', '-batch', '-ex', 'set debuginfod enabled off',
            '-ex', 'set auto-solib-add off', '-ex', 'file ' + str(case / 'aliases.input'),
            '-ex', 'symbol-file ' + str(case / 'baseline.dbg'), '-ex', "print &'" + metadata['functions'][0]['original'] + "'"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        (case / 'baseline-lookup.log').write_bytes(negative.stdout)
        assert negative.returncode != 0 and b'No symbol' in negative.stdout
        _, _, sections = elf_support.elf(case / 'aliases.input')
        section_index = list(sections).index('.text')
        records = ['\t'.join([row['original'], str(row['entry']), str(row['end'] - row['entry']), str(section_index)])
            for row in sorted(metadata['functions'], key=lambda row: (row['entry'], row['original']))]
        (case / 'symbols.tsv').write_text('\n'.join(records) + '\n')
        command = [java, '-cp', str(compilation) + os.pathsep + str(jar),
            'ghidradwarfforge.elf.LocalSymbolMergeProbe', case / 'aliases.input', case / 'baseline.dbg', case / 'symbols.tsv']
        for suffix in ('aliases.dbg', 'repeat.dbg'):
            run('writer-' + suffix, [*command, case / suffix])
            text = (case / ('writer-' + suffix + '.log')).read_text()
            assert 'java=21.' in text and 'curated-alias-writer=PASS' in text
            assert jar.resolve().as_uri() in text.replace('file:/', 'file:///')
        assert (case / 'aliases.dbg').read_bytes() == (case / 'repeat.dbg').read_bytes()
        assert (case / 'aliases.dbg').read_bytes() == (case / 'automatic.dbg').read_bytes()
        if args.previous_jar:
            previous = case / 'previous.dbg'
            previous.write_bytes(b'previous output sentinel')
            comparison = subprocess.run([java, '-cp', str(compilation) + os.pathsep + str(args.previous_jar.resolve()),
                *map(str, command[3:]), str(previous)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            (case / 'previous-writer.log').write_bytes(comparison.stdout)
            if symbols == 'retained':
                assert comparison.returncode != 0 and b'conflict with existing sections' in comparison.stdout
                assert previous.read_bytes() == b'previous output sentinel'
            else:
                assert comparison.returncode == 0 and previous.read_bytes() == (case / 'aliases.dbg').read_bytes()
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(view, ['readelf', '--debug-dump=' + view, case / 'aliases.dbg'])
        for name, option in [('headers', '-h'), ('sections', '-SW'), ('symbols', '-sW'), ('notes', '-n')]:
            run(name, ['readelf', option, case / 'aliases.dbg'])
        run('llvm', ['llvm-dwarfdump', '--verify', case / 'aliases.dbg'])
        assert 'No errors.' in (case / 'llvm.log').read_text()
        run('strict', ['python3', source / 'check-dwarfdump.py', case / 'aliases.dbg',
            case / 'strict-checks.log', '--original', case / 'aliases.input'])
        run('gdb-driver', ['bash', source / 'local-symbol-merge-gdb.sh', repository, case, args.target,
            base / 'compiler-gdb.log'], timeout=180)
        ident, bh, baseline = elf_support.elf(case / 'baseline.dbg')
        _, ch, candidate = elf_support.elf(case / 'aliases.dbg')
        assert bh[:4] == ch[:4] and bh[6] == ch[6] and ch[4] == ch[8] == ch[9] == 0
        for name, (section, payload) in baseline.items():
            if name.startswith('.debug_') or name in ('.text', '.eh_frame', '.note.gnu.build-id'):
                assert candidate[name][1] == payload
        if symbols == 'retained':
            old, old_bytes = baseline['.symtab']
            new, new_bytes = candidate['.symtab']
            width = 24 if ident[4] == 2 else 16
            split = old[7] * width
            assert new[7] == old[7] + 2 and new[6] == old[6]
            assert old_bytes == new_bytes[:split] + new_bytes[split + 2 * width:]
            old_strings = baseline['.strtab'][1]
            assert candidate['.strtab'][1][:len(old_strings)] == old_strings
        elif '.dynsym' in baseline:
            old, old_bytes = baseline['.dynsym']
            new, new_bytes = candidate['.symtab']
            width = 24 if ident[4] == 2 else 16
            split = old[7] * width
            assert new[7] == old[7] + 2 and new[2] == new[3] == 0
            assert old_bytes == new_bytes[:split] + new_bytes[split + 2 * width:]
            old_strings = baseline['.dynstr'][1]
            assert candidate['.strtab'][1][:len(old_strings)] == old_strings
            for name, (section, payload) in baseline.items():
                if name in ('.dynsym', '.dynstr', '.hash', '.gnu.hash', '.dynamic') or name.startswith('.gnu.version'):
                    assert candidate[name][1] == payload, name
                    # Offsets may move, but target addresses, links, flags and counts must not.
                    assert candidate[name][0][:4] == section[:4] and candidate[name][0][5:] == section[5:], name
        after = {name: support.digest(Path(name)) for name in before}
        write('protected-after.json', after)
        assert before == after
        assert (case / 'aliases.input').read_bytes() == (base / 'aliases.input').read_bytes()
        final = {str(p.relative_to(case / 'project')): support.digest(p)
            for p in (case / 'project').rglob('*') if p.is_file()}
        write('project-after.json', final)
        changes = {p for p in snapshot.keys() | final.keys() if snapshot.get(p) != final.get(p)}
        assert changes <= {'Aliases.rep/idata/~index.bak', 'Aliases.rep/idata/~journal.bak'}
        write('result.json', {'status': 'PASS', 'target': args.target, 'role': role, 'symbols': symbols,
            'baseCase': str(base), 'jarSha256': support.digest(jar), 'projectBackupChanges': sorted(changes),
            'previousComparison': bool(args.previous_jar), 'protectedUnchanged': True,
            'automaticExportMatchesIndependentWriter': True})
        completed.append(str(case))
        print('local-symbol-merge-integration=PASS ' + str(case), flush=True)
    assert len(completed) == expected_cases


if __name__ == '__main__':
    main()
