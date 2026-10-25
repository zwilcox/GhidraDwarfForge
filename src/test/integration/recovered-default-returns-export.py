#!/usr/bin/env python3
"""Actual default-signature recovery with independent compiler/GDB return oracles."""
import argparse
import importlib.util
import json
from pathlib import Path
import os
import shutil
import tempfile

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('benchmark_support', source.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--previous-ghidra', type=Path)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/recovered-default-returns'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='x86_64.', dir=root))
    print(case, flush=True)
    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')
    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result
    fixture = repository / 'src/test/fixtures/recovered-default-returns.c'
    protected = [fixture, Path(__file__).resolve(), source / 'recovered-default-returns-gdb.py',
        source / 'ghidra_scripts/ObserveRecoveredReturns.java',
        source / 'ghidra_scripts/CheckRecoveredReturnPass.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    reference, binary = case / 'returns.reference', case / 'returns.input'
    run('compile', ['gcc', '-O1', '-g3', '-gdwarf-5', '-fno-inline', '-fno-ipa-sra',
        '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-Wl,--build-id=none', fixture, '-o', reference])
    run('strip', ['objcopy', '--strip-debug', reference, binary])
    original = support.digest(binary)
    run('plain', [binary])
    project = case / 'project'
    project.mkdir()
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Returns', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        '-postScript', 'ObserveRecoveredReturns.java', 'curate', case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.insert(0, ('previous', args.previous_ghidra.resolve(strict=True)))
    artifact_hashes = None
    for variant, installation in variants:
        output = case / ('previous.dbg' if variant == 'previous' else 'returns.dbg')
        pass_check = [] if variant == 'previous' else ['-postScript', 'CheckRecoveredReturnPass.java']
        run(variant, [installation / 'support/analyzeHeadless', project, 'Returns', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'ObserveRecoveredReturns.java', 'observe', case / (variant + '.json'),
            *pass_check, '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], timeout=240)
        assert 'GhidraDwarfForge symbol export PASS' in (case / (variant + '.log')).read_text()
        if variant == 'previous':
            continue
        assert 'recovered-return-pass=PASS' in (case / (variant + '.log')).read_text()
        hashes = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        if artifact_hashes is not None:
            assert artifact_hashes == hashes
        artifact_hashes = hashes
        if variant == 'fixed':
            shutil.copyfile(output, case / 'first.dbg')
            shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
    metadata = json.loads((case / 'fixed.json').read_text())
    assert metadata == json.loads((case / 'repeat.json').read_text())
    assert metadata['functions'] == json.loads((case / 'import.json').read_text())['functions']
    by_name = {row['name']: row for row in metadata['functions']}
    for name, recovered, size in [('recovered_signed', 'int', 4), ('recovered_unsigned', 'ulong', 8), ('recovered_double', 'double', 8)]:
        row = by_name[name]
        assert row['signatureSource'] == row['returnSource'] == 'DEFAULT' and row['formalName'] == 'undefined', row
        assert row['recoveredName'] == recovered and row['recoveredBytes'] == size, row
        assert 'Using decompiler-recovered scalar return for ' + name + ':' in (case / 'fixed.log').read_text()
    for name in ('curated_pointer', 'curated_void'):
        assert by_name[name]['returnSource'] == 'USER_DEFINED'
        assert 'Using decompiler-recovered scalar return for ' + name + ':' not in (case / 'fixed.log').read_text()
    for variant, artifact in [('compiler', reference), ('forge', case / 'returns.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'returns.dbg', case / 'strict-checks.log', '--original', binary])
    for variant in ['compiler', 'forge'] + (['previous'] if args.previous_ghidra else []):
        artifact = reference if variant == 'compiler' else case / ('previous.dbg' if variant == 'previous' else 'returns.dbg')
        os.environ['RETURN_CASE'], os.environ['RETURN_VARIANT'] = str(case), variant
        run(variant + '-gdb', ['gdb-multiarch', '-q', '-nx', '-batch', '-ex', 'set pagination off',
            '-ex', 'set confirm off', '-ex', 'set python print-stack full', '-ex', 'set debuginfod enabled off', '-ex', 'set auto-solib-add off',
            '-ex', 'set disable-randomization off', '-ex', 'file ' + str(reference if variant == 'compiler' else binary),
            '-ex', 'symbol-file ' + str(artifact), '-x', source / 'recovered-default-returns-gdb.py'])
        assert 'recovered-return-gdb=' + variant + ' PASS' in (case / (variant + '-gdb.log')).read_text()
    after = {str(p): support.digest(p) for p in protected}
    write('protected-after.json', after)
    assert before == after and original == support.digest(binary)
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Returns.rep/idata/~index.bak', 'Returns.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'inputSha256': original, 'artifactSha256': artifact_hashes,
        'javaVersion': metadata['javaVersion'], 'projectBackupChanges': changes, 'protectedUnchanged': True,
        'previousPackageCompared': bool(args.previous_ghidra)})
    print('recovered-default-returns=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
