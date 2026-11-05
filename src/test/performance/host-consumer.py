#!/usr/bin/env python3
"""Independently validate Windows-produced workload DWARF and execute Linux GDB."""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import sys
import tarfile

SOURCE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('performance_support', SOURCE / 'export-benchmark.py')
SUPPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUPPORT)


def prepare_compiler_sources(workload, corpus, case, metadata):
    """Relocate hash-bound compiler sources without following recorded host paths."""
    def verified(relative):
        path = (corpus / relative).resolve(strict=True)
        assert path.is_relative_to(corpus.resolve())
        assert SUPPORT.digest(path) == metadata['files'][relative], relative
        return path

    root = case / 'compiler-source'
    root.mkdir(exist_ok=False)
    if workload['name'] == 'sqlite':
        command = json.loads(verified('build-evidence/sqlite-compile.command.json').read_text())
        old_source, = [Path(arg) for arg in command if arg.endswith('/sqlite-workload.c')]
        sqlite_source, = [Path(arg) for arg in command if arg.endswith('/sqlite3.c')]
        assert old_source.parent == sqlite_source.parent
        files = {}
        for name in ('sqlite-workload.c', 'sqlite3.c', 'sqlite3.h'):
            original = verified('sqlite/' + name)
            copied = root / name
            # Retain source times from the corpus, rather than making sources
            # newer than the private compiler-reference copy created earlier.
            shutil.copy2(original, copied)
            assert SUPPORT.digest(copied) == SUPPORT.digest(original)
            files[name] = SUPPORT.digest(copied)
        mappings = [(str(old_source.parent), str(root))]
        expected = root / 'sqlite-workload.c'
        archive_hash = None
    else:
        assert workload['name'] == 'uboot'
        archive = verified('sources/u-boot-2025.01.tar.bz2')
        archive_hash = SUPPORT.digest(archive)
        assert archive_hash == workload['sourceArchiveSha256'] == \
            'cdef7d507c93f1bbd9f015ea9bc21fa074268481405501945abc6f854d5b686f'
        command = json.loads(verified('build-evidence/uboot-build.command.json').read_text())
        assert command[:2] == ['make', '-C']
        old_tree = Path(command[2])
        old_objects, = [Path(arg[2:]) for arg in command if arg.startswith('O=')]
        assert old_tree.name == 'u-boot-2025.01' and old_objects.name == 'objects'
        with tarfile.open(archive) as packed:
            packed.extractall(root, filter='data')
        tree = root / 'u-boot-2025.01'
        objects = root / 'objects'
        objects.mkdir()
        mappings = [(str(old_tree), str(tree)), (str(old_objects), str(objects))]
        expected = tree / 'cmd/echo.c'
        files = {'u-boot-2025.01/cmd/echo.c': SUPPORT.digest(expected)}
    assert expected.resolve().is_relative_to(root.resolve())
    result = {'root': str(root), 'substitutions': mappings, 'expectedBreakpointSource': str(expected),
        'expectedBreakpointSha256': SUPPORT.digest(expected), 'sourceFiles': files,
        'archiveSha256': archive_hash,
        'scope': 'Verified corpus sources relocated into private consumer storage. '
            'Recorded build paths are substitution strings only; never read from those paths.'}
    (case / 'compiler-source.json').write_text(json.dumps(result, indent=4) + '\n')
    return result


def validate_gdb(workload, corpus, case, artifact_dir, sidecar, binary, reference,
        compiler_sources=None):
    """Shared runtime oracle for host transfer and private candidate experiments."""
    def run(name, command, **kwargs):
        return SUPPORT.run(command, case / (name + '.log'), **kwargs)
    validation = {}
    variants = (('compiler', reference), ('forge', binary)) if reference is not None else (('forge', binary),)
    for variant, executable in variants:
        commands = ['set pagination off', 'set confirm off', 'set debuginfod enabled off',
            'set auto-solib-add off', 'set disable-randomization off', 'set startup-with-shell on',
            'file ' + json.dumps(str(executable)), 'directory ' + str(artifact_dir)]
        if variant == 'compiler' and compiler_sources is not None:
            for before, after in compiler_sources['substitutions']:
                commands += ['set substitute-path ' + json.dumps(before) + ' ' + json.dumps(after)]
        if workload['name'] == 'uboot':
            commands += ['set args ' + shlex.join(['-d', str(corpus / workload['dtb']),
                '-c', 'echo forge-uboot-gdb=PASS']) + ' > ' +
                shlex.quote(str(case / (variant + '-inferior.log'))) + ' 2>&1']
        commands += ['starti', 'python', 'exits = []',
            'gdb.events.exited.connect(lambda event: exits.append(getattr(event, "exit_code", None)))',
            'expected = ' + repr(workload['addresses']),
            'bias = int(gdb.parse_and_eval("&main")) - expected["main"]',
            'assert bias ' + ('> 0' if workload['kind'] == 'pie' else '== 0')]
        if variant == 'forge':
            commands += ['gdb.execute("symbol-file -o " + hex(bias) + " " + ' + repr(str(sidecar)) + ')',
                'for name, address in expected.items():']
            if workload['name'] == 'uboot':
                commands += ['    if name == "main": continue  # explicitly omitted imported thunk']
            commands += ['    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)',
                # do_echo also names a legitimate static data object. Test
                # function ownership at its named breakpoint below instead.
                '    if name == "do_echo": continue',
                '    assert symbol and symbol.is_function and symbol.symtab, name',
                '    assert symbol.symtab.filename.endswith(".dbg.c"), name',
                '    assert int(symbol.value().address) == bias + address, name']
        commands += ['end']
        point = 'do_echo' if workload['name'] == 'uboot' else 'benchmark_checkpoint'
        commands += ['ptype ' + ('sandbox_main' if workload['name'] == 'uboot' else point),
            'python point = gdb.Breakpoint(' + (repr(point) if workload['name'] == 'uboot'
                else '"*" + hex(bias + expected["benchmark_checkpoint"])') + ')', 'continue', 'python',
            'assert int(gdb.parse_and_eval("$pc")) == bias + expected[' + repr(point) + ']']
        if variant == 'compiler' and compiler_sources is not None:
            commands += ['import hashlib', 'from pathlib import Path',
                'source = Path(gdb.selected_frame().find_sal().symtab.fullname()).resolve()',
                'assert source == Path(' + repr(compiler_sources['expectedBreakpointSource']) + ').resolve()',
                'assert hashlib.sha256(source.read_bytes()).hexdigest() == ' +
                    repr(compiler_sources['expectedBreakpointSha256']),
                'listing = gdb.execute("list *$pc", to_string=True)',
                'assert "No such file" not in listing and "No source" not in listing',
                'print(listing)']
        if variant == 'forge':
            commands += ['block = gdb.block_for_pc(int(gdb.parse_and_eval("$pc")))',
                'while block is not None and block.function is None: block = block.superblock',
                'assert block and block.function.symtab.filename.endswith(".dbg.c")',
                'sal = gdb.selected_frame().find_sal()', 'assert sal.line > 0',
                'listing = gdb.execute("list *$pc", to_string=True)',
                'assert "No such file" not in listing and "No source" not in listing',
                'print(listing)']
        if workload['name'] == 'uboot':
            commands += (['assert int(gdb.parse_and_eval("argc")) == 2',
                'assert gdb.parse_and_eval("argv[1]").string() == "forge-uboot-gdb=PASS"']
                if variant == 'compiler' else ['assert int(gdb.parse_and_eval("*(unsigned long*)&gd")) != 0'])
            commands += ['end', 'disable breakpoints', 'next', 'step', 'continue', 'python assert exits == [0]']
        else:
            commands += ['assert int(gdb.parse_and_eval("*(unsigned int*)&observed_count")) == 100',
                'assert int(gdb.parse_and_eval("*(unsigned int*)&observed_sum")) == 5050',
                'gdb.execute("disable breakpoints")',
                'finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)',
                'gdb.execute("next")', 'assert finish.return_value is None', 'gdb.execute("step")',
                'if finish.return_value is None: gdb.execute("continue")',
                'assert int(finish.return_value) == 5150', 'gdb.execute("continue")',
                'assert exits == [0]', 'end']
        commands += ['echo host-consumer-' + variant + '=PASS\\n', '']
        script = case / (variant + '.gdb')
        script.write_text('\n'.join(commands))
        validation[variant + '-gdb'] = run(variant + '-gdb',
            ['gdb-multiarch', '-nx', '-q', '-batch', '-x', script], measured=True, timeout=180, cwd=case)
        SUPPORT.require_clean(case / (variant + '-gdb.log'))
        assert 'host-consumer-' + variant + '=PASS' in (case / (variant + '-gdb.log')).read_text()
        if workload['name'] == 'uboot':
            assert 'forge-uboot-gdb=PASS' in (case / (variant + '-inferior.log')).read_text()
    return validation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path)
    parser.add_argument('windows_results', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    corpus = args.corpus.resolve(strict=True)
    metadata = json.loads((corpus / 'corpus.json').read_text())
    for name, digest in metadata['files'].items():
        path = (corpus / name).resolve(strict=True)
        assert path.is_relative_to(corpus) and SUPPORT.digest(path) == digest
    incoming, = args.windows_results.resolve(strict=True).glob('run.*')
    recorded = json.loads((incoming / 'summary.json').read_text())
    assert recorded['status'] == 'WINDOWS_EXPORT_VALIDATED_GDB_PENDING' and recorded['protectedUnchanged']
    assert len(recorded['workloads']) == len(metadata['workloads']) == 2
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    protected = [p for directory in (incoming, corpus) for p in directory.rglob('*') if p.is_file()]
    before = {str(p): SUPPORT.digest(p) for p in protected}
    outcomes = []
    for workload in metadata['workloads']:
        summary, = [s for s in recorded['workloads'] if s['workload']['name'] == workload['name']]
        assert summary['workload'] == workload
        assert summary['status'] == 'WINDOWS_EXPORT_VALIDATED_GDB_PENDING'
        case = root / workload['name']
        case.mkdir()
        artifact_dir = incoming / workload['name']
        # Only map known corpus and artifact roles, never follow Windows paths.
        expected_name = Path(workload['binary']).name + '.dbg'
        assert summary['sidecar'] == expected_name
        sidecar = artifact_dir / expected_name
        source = Path(str(sidecar) + '.c')
        assert [SUPPORT.digest(p) for p in (sidecar, source)] == summary['artifactSha256']
        binary = case / 'original'
        reference = case / 'compiler-reference'
        for original, copied in ((corpus / workload['binary'], binary),
                (corpus / workload['compilerReference'], reference)):
            shutil.copyfile(original, copied)
            copied.chmod(0o755)
            assert SUPPORT.digest(original) == SUPPORT.digest(copied)
        compiler_sources = prepare_compiler_sources(workload, corpus, case, metadata)
        def run(name, command, **kwargs):
            return SUPPORT.run(command, case / (name + '.log'), **kwargs)
        validation = {}
        for name, command in [('llvm', ['llvm-dwarfdump', '--verify', sidecar]),
                ('strict', [sys.executable, SOURCE.parent / 'integration/check-dwarfdump.py', sidecar,
                    case / 'strict-checks.log', '--original', binary]),
                *[(view, ['readelf', '--debug-dump=' + view, sidecar])
                    for view in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc')],
                ('identity', ['readelf', '-h', '-SW', '-n', binary, sidecar])]:
            validation[name] = run(name, command, measured=True, timeout=600)
            SUPPORT.require_clean(case / (name + '.log'))
        assert 'No errors.' in (case / 'llvm.log').read_text()
        validation.update(validate_gdb(workload, corpus, case, artifact_dir, sidecar, binary, reference,
            compiler_sources=compiler_sources))
        outcomes.append({'workload': workload['name'], 'artifactSha256': summary['artifactSha256'],
            'validation': validation, 'strict': json.loads((case / 'strict-checks.log.check.json').read_text())})
    after = {str(p): SUPPORT.digest(p) for p in protected}
    assert before == after
    (root / 'summary.json').write_text(json.dumps({'status': 'PASS', 'outcomes': outcomes,
        'protectedUnchanged': True, 'scope': 'Untouched Windows DWARF, independent Linux validators and '
            'compiler/Forge GDB function/source/global/step/return/exit checks. Explicit source directory '
            'relocation and PIE load bias. Consumer time is not Windows exporter time.'}, indent=4) + '\n')
    print('windows-performance-consumer=PASS ' + str(root))


if __name__ == '__main__':
    main()
