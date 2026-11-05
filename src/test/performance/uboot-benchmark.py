#!/usr/bin/env python3
"""Measure and validate exports of a pinned, source-built U-Boot sandbox ELF."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import tempfile

SOURCE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('benchmark_support', SOURCE / 'export-benchmark.py')
SUPPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUPPORT)


def validate_behavior(case, reference, binary, dtb, sidecar, addresses):
    """Validate retained artifacts without rerunning expensive analysis/export."""
    def run(name, command, **kwargs):
        return SUPPORT.run(command, case / (name + ".log"), **kwargs)
    validation = {}
    # The source-built compiler reference independently proves the command's argc
    # and marker argument. Forge checks only evidence the uncurated program owns.
    for variant, executable in (('compiler', reference), ('forge', binary)):
        commands = ['set pagination off', 'set confirm off', 'set debuginfod enabled off',
            'set auto-solib-add off', 'set disable-randomization off', 'set startup-with-shell on',
            'file ' + json.dumps(str(executable)),
            'set args ' + shlex.join(['-d', str(dtb), '-c', 'echo forge-uboot-gdb=PASS']) +
                ' > ' + shlex.quote(str(case / (variant + '-inferior.log'))) + ' 2>&1']
        if variant == 'forge':
            commands += ['source ' + str(sidecar) + '.gdb.py', 'starti', 'forge-load']
        else:
            commands += ['starti']
        commands += ['python', 'exits = []',
            'gdb.events.exited.connect(lambda event: exits.append(getattr(event, "exit_code", None)))',
            'expected = ' + repr(addresses), 'bias = int(gdb.parse_and_eval("&main")) - expected["main"]',
            'assert bias > 0', 'end', 'ptype sandbox_main']
        if variant == 'forge':
            commands += ['python', 'for name in ("sandbox_main", "run_command", "simple_strtoul"):',
                '    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)',
                '    assert symbol and symbol.is_function and symbol.symtab and symbol.symtab.filename.endswith(".dbg.c"), name',
                '    assert int(symbol.value().address) == bias + expected[name], name', 'end']
        commands += ['python point = gdb.Breakpoint("do_echo")',
            'continue', 'python assert int(gdb.parse_and_eval("$pc")) == bias + expected["do_echo"]']
        if variant == 'compiler':
            commands += ['python assert int(gdb.parse_and_eval("argc")) == 2',
                'python assert gdb.parse_and_eval("argv[1]").string() == "forge-uboot-gdb=PASS"']
        else:
            commands += ['python', 'block = gdb.block_for_pc(int(gdb.parse_and_eval("$pc")))',
                'while block is not None and block.function is None: block = block.superblock',
                'assert block and block.function.symtab.filename.endswith(".dbg.c")',
                'assert gdb.find_pc_line(int(gdb.parse_and_eval("$pc"))).line > 0', 'end', 'list *$pc',
                'python assert int(gdb.parse_and_eval("*(unsigned long*)&gd")) != 0']
        commands += ['disable breakpoints', 'next', 'step', 'continue',
            'python assert exits == [0]', 'echo uboot-' + variant + '-gdb=PASS\\n', '']
        script = case / (variant + '.gdb')
        script.write_text('\n'.join(commands))
        validation[variant + '-gdb'] = run(variant + '-gdb',
            ['gdb-multiarch', '-q', '-nx', '-batch', '-x', script], cwd=case, timeout=180, measured=True)
        SUPPORT.require_clean(case / (variant + '-gdb.log'))
        assert 'uboot-' + variant + '-gdb=PASS' in (case / (variant + '-gdb.log')).read_text()
        assert 'forge-uboot-gdb=PASS' in (case / (variant + '-inferior.log')).read_text()
    return validation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('build_case', type=Path, help='Passing build-uboot.py result directory')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--profile', action='store_true')
    parser.add_argument('--jfr', default='jfr')
    args = parser.parse_args()
    if not 2 <= args.repeats <= 10:
        parser.error('repeats must be between 2 and 10')
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    built = args.build_case.resolve(strict=True)
    receipt = json.loads((built / 'build-result.json').read_text())
    assert receipt['status'] == 'PASS' and receipt['version'] == '2025.01'
    assert receipt['archiveSha256'] == 'cdef7d507c93f1bbd9f015ea9bc21fa074268481405501945abc6f854d5b686f'
    for name in ('u-boot.reference', 'u-boot.workload', 'u-boot.dtb', 'build.config'):
        assert SUPPORT.digest(built / name) == receipt['artifacts'][name]['sha256']
    binary, reference, dtb = (built / name for name in ('u-boot.workload', 'u-boot.reference', 'u-boot.dtb'))
    root = SOURCE.parents[2] / 'build/test-results/uboot-benchmark'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='run.', dir=root))
    print(case, flush=True)
    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')
    def run(name, command, **kwargs):
        return SUPPORT.run(command, case / (name + '.log'), **kwargs)
    protected = [built / name for name in ('u-boot.reference', 'u-boot.workload', 'u-boot.dtb',
        'build.config', 'build-result.json')]
    protected += [p for p in module.rglob('*') if p.is_file()]
    protected += [SOURCE / name for name in ('uboot-benchmark.py', 'export-benchmark.py',
        'headless-observations.py', 'jfr-phases.py')]
    before = {str(p): SUPPORT.digest(p) for p in protected}
    write('protected-before.json', before)
    write('environment.json', {'host': platform.platform(), 'cpuCount': os.cpu_count(),
        'loadAverageAtStart': os.getloadavg(), 'ghidra': str(ghidra), 'buildCase': str(built),
        'jarSha256': SUPPORT.digest(module / 'lib/GhidraDwarfForge.jar'),
        'scope': 'Linux host sandbox firmware code, x86-64 PIE; not bare-metal hardware validation.',
        'measurementBoundary': 'Import separate; exports use fresh JVMs and saved read-only programs. '
            'CPU includes process children; GNU time RSS is process-family high water, not concurrent aggregate. '
            'Validation/GDB and optional JFR run are outside unprofiled export population.'})
    run('symbols', ['nm', '-n', '--defined-only', reference])
    addresses = {}
    wanted = {'main', 'sandbox_main', 'run_command', 'simple_strtoul', 'do_echo'}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] in ('T', 't') and fields[2] in wanted:
            assert fields[2] not in addresses, 'ambiguous compiler function'
            addresses[fields[2]] = int(fields[0], 16)
    assert addresses.keys() == wanted
    write('function-addresses.json', addresses)
    project = case / 'project'
    project.mkdir()
    imported = run('import', [ghidra / 'support/analyzeHeadless', project, 'UBoot', '-import', binary,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '3600', '-max-cpu', '4'],
        timeout=3900, measured=True)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    imported['runtime'] = SUPPORT.verify_headless(case / 'import.log', module)
    project_before = {str(p.relative_to(project)): SUPPORT.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    sidecar = case / 'u-boot.dbg'
    command = [module / 'support/ghidra-dwarf-forge-headless', '--ghidra-dir=' + str(ghidra),
        '--project-dir=' + str(project), '--project-name=UBoot', '--program=' + binary.name,
        '--input=' + str(binary), '--output=' + str(sidecar), '--gdb-loader']
    samples, hashes = [], None
    for iteration in range(args.repeats + int(args.profile)):
        profiling = iteration == args.repeats
        name = 'profile' if profiling else 'export-' + str(iteration)
        print('uboot benchmark: ' + name, flush=True)
        previous = os.environ.get('JAVA_TOOL_OPTIONS')
        try:
            if profiling:
                os.environ['JAVA_TOOL_OPTIONS'] = (previous or '') + ' -Xlog:jfr+startup=off -XX:StartFlightRecording=filename=' + str(case / 'export.jfr') + ',settings=profile,dumponexit=true'
            sample = run(name, command, timeout=3900, measured=True)
        finally:
            if previous is None:
                os.environ.pop('JAVA_TOOL_OPTIONS', None)
            else:
                os.environ['JAVA_TOOL_OPTIONS'] = previous
        sample['runtime'] = SUPPORT.verify_headless(case / (name + '.log'), module, exported=True)
        reports = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in (case / (name + '.log')).read_text().splitlines() if 'GhidraDwarfForge report: {' in line]
        report, = reports
        assert report['failure'] is None and report['counts']['functionsExported'] >= len(wanted)
        # The pinned optimized main is endbr64 + jmp sandbox_main. The current
        # exporter deliberately omits uncurated imported thunks; its minimal ELF
        # symbol is a relocation anchor, not evidence of full DWARF coverage.
        assert {'name': 'main', 'reason': 'THUNK'} in report['skippedFunctions']
        write(name + '.report.json', report)
        observed = [SUPPORT.digest(Path(str(sidecar) + suffix)) for suffix in ('', '.c', '.gdb.py')]
        if hashes is not None:
            assert hashes == observed, 'nondeterministic firmware export'
        hashes = observed
        sample.update(counts=report['counts'], status=report['status'], profiled=profiling)
        if profiling:
            write('profile.metrics.json', sample)
        else:
            samples.append(sample)
        write('samples.json', samples)
    if args.profile:
        run('phases', [args.jfr, 'print', '--json', '--events', 'ghidradwarfforge.ExportPhase', case / 'export.jfr'])
        run('phase-summary', ['python3', SOURCE / 'jfr-phases.py', case / 'phases.log', case / 'phase-summary.json'])
    validation = {}
    for name, argv in [('llvm', ['llvm-dwarfdump', '--verify', sidecar]),
            ('strict', ['python3', SOURCE.parent / 'integration/check-dwarfdump.py', sidecar,
                case / 'strict-checks.log', '--original', binary]),
            *[(view, ['readelf', '--debug-dump=' + view, sidecar])
                for view in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc')],
            ('identity', ['readelf', '-h', '-SW', '-n', binary, sidecar])]:
        validation[name] = run(name, argv, timeout=600, measured=True)
        SUPPORT.require_clean(case / (name + '.log'))
    assert 'No errors.' in (case / 'llvm.log').read_text()
    validation.update(validate_behavior(case, reference, binary, dtb, sidecar, addresses))
    after = {str(p): SUPPORT.digest(p) for p in protected}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): SUPPORT.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys())
        if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'UBoot.rep/idata/~index.bak', 'UBoot.rep/idata/~journal.bak'}
    write('summary.json', {'status': 'PASS', 'buildCase': str(built), 'import': imported,
        'exports': samples, 'validation': validation, 'artifactSha256': hashes,
        'exportMedianSeconds': statistics.median(row['elapsedSeconds'] for row in samples),
        'exportMaximumResidentKiB': max(row['maximumResidentKiB'] for row in samples),
        'counts': samples[-1]['counts'], 'protectedUnchanged': True, 'projectBackupChanges': changes,
        'strict': json.loads((case / 'strict-checks.log.check.json').read_text()),
        'profilePhases': json.loads((case / 'phase-summary.json').read_text()) if args.profile else None,
        'scope': 'One Linux x86-64 sandbox PIE; compiler argc/argv reference; Forge function/source '
            'lookup, raw gd pointer, stepping and exit. No complete recovered types/locals or hardware claim.'})
    print('uboot-benchmark=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
