#!/usr/bin/env python3
"""Run the complete external-declaration oracle with optional per-analyzer coverage."""
import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

from integration_coverage import Collection, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    repository = source.parents[2]
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    results = repository / 'build/test-results/external-function-declarations'
    results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='x86_64.', dir=results))
    project = case / 'project'
    project.mkdir()
    (case / 'empty-debug').mkdir()
    environment = dict(os.environ, LC_ALL='C')
    measured = Collection('external-declarations', module / 'lib/GhidraDwarfForge.jar', 'headless')

    def run(label, command, *, timeout=90, stderr_empty=True, combined=False, env=None, headless=False):
        command = list(map(str, command))
        context = measured.session(command, label, headless=True) if headless else nullcontext(command)
        with context as actual:
            with (case / 'commands.log').open('a') as trace:
                trace.write(json.dumps({'label': label, 'command': actual, 'timeout': timeout}) + '\n')
            output = case / (label + ('.log' if combined else '.stdout'))
            errors = case / (label + '.stderr')
            with output.open('w') as stdout, errors.open('w') as stderr:
                process = subprocess.Popen(actual, stdout=stdout,
                    stderr=subprocess.STDOUT if combined else stderr,
                    env=environment if env is None else env, start_new_session=True)
                started = time.monotonic()
                try:
                    while process.poll() is None:
                        if time.monotonic() - started > timeout or output.stat().st_size + errors.stat().st_size > 16 * 1024 * 1024:
                            raise RuntimeError('external-declaration command exceeded time/output bound: ' + label)
                        time.sleep(.1)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            pass
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                if process.returncode != 0:
                    raise RuntimeError(f'{label} failed with {process.returncode}; see {output} and {errors}')
            if stderr_empty and errors.stat().st_size:
                raise AssertionError('unexpected stderr: ' + str(errors))
            if headless:
                assert output.read_text().count('GhidraDwarfForge symbol export PASS') == 1
                assert 'Unexpected Exception' not in output.read_text()

    def check(stage):
        run('check-' + stage, ['python3', source / 'external-function-declarations-check.py',
            stage, case, repository, module])

    def project_hashes():
        return {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}

    for tool in ('gcc', 'objcopy', 'objdump', 'readelf', 'llvm-dwarfdump', 'gdb-multiarch'):
        run(tool + '.version', [tool, '--version'], timeout=30, stderr_empty=False, combined=True)
    fixture = repository / 'src/test/fixtures/external-function-declarations.c'
    run('library', ['gcc', '-O0', '-fPIC', '-shared', '-DFORGE_DECL_LIBRARY', fixture, '-o', case / 'libexternal.so'])
    run('compile', ['gcc', '-O0', '-g3', '-gdwarf-5', '-fno-pie', '-no-pie', fixture,
        '-L' + str(case), '-lexternal', '-Wl,-rpath,' + str(case), '-Wl,--build-id=none', '-o', case / 'decl.reference'])
    run('strip', ['objcopy', '--strip-all', case / 'decl.reference', case / 'decl.stripped'])
    run('compiler-info', ['readelf', '--debug-dump=info', case / 'decl.reference'])
    run('compiler-disassembly', ['objdump', '-drwC', case / 'decl.reference'])
    check('labels')
    main_address, global_address = (case / 'labels.txt').read_text().split()
    run('plain', [case / 'decl.reference'], timeout=30)
    assert not (case / 'plain.stdout').stat().st_size
    pairs = []
    for phase in ('curate', 'reopen'):
        mode = ['-import', str(case / 'decl.stripped'), '-analysisTimeoutPerFile', '120'] if phase == 'curate' else [
            '-process', 'decl.stripped', '-noanalysis', '-readOnly']
        if phase == 'reopen':
            project_before = project_hashes()
        run('export-' + phase, [ghidra / 'support/analyzeHeadless', project, 'ExternalDeclarations', *mode,
            '-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareExternalDeclarations.java', phase,
            main_address, global_address, case / (phase + '.json'), '-postScript', 'GhidraDwarfForge.java',
            '--packaged-natives', '--output=' + str(case / 'decl.dbg')], timeout=240, combined=True, headless=True)
        assert (case / (phase + '.json')).is_file()
        pairs.append([digest(case / name) for name in ('decl.dbg', 'decl.dbg.c')])
        if phase == 'curate':
            for name in ('decl.dbg', 'decl.dbg.c'):
                shutil.copyfile(case / name, case / ('first.' + name))
    project_after = project_hashes()
    allowed = {'ExternalDeclarations.rep/idata/~index.bak', 'ExternalDeclarations.rep/idata/~journal.bak'}
    changes = {name: [project_before.get(name), project_after.get(name)] for name in project_before.keys() | project_after.keys()
        if project_before.get(name) != project_after.get(name)}
    assert changes.keys() <= allowed, changes
    assert pairs[0] == pairs[1]
    for view in ('header', 'sections', 'notes', 'info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
        option = {'header': '-h', 'sections': '-SW', 'notes': '-n'}.get(view, '--debug-dump=' + view)
        run('forge-' + view, ['readelf', option, case / 'decl.dbg'])
    run('llvm', ['llvm-dwarfdump', '--verify', case / 'decl.dbg'])
    assert 'No errors.' in (case / 'llvm.stdout').read_text()
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'decl.dbg', case / 'strict.log',
        '--original', case / 'decl.stripped'])
    check('observations')
    for variant in ('compiler', 'forge'):
        original = case / ('decl.reference' if variant == 'compiler' else 'decl.stripped')
        symbols = original if variant == 'compiler' else case / 'decl.dbg'
        env = dict(environment, DECL_CASE=str(case), DECL_VARIANT=variant, DECL_SOURCE=str(fixture))
        run(variant + '-gdb', ['gdb-multiarch', '-q', '-nx', '-batch', '-ex', 'set pagination off',
            '-ex', 'set confirm off', '-ex', 'set debuginfod enabled off', '-ex', 'set auto-solib-add off',
            '-ex', 'set disable-randomization off', '-ex', 'set debug-file-directory ' + str(case / 'empty-debug'),
            '-ex', 'file ' + str(original), '-ex', 'symbol-file ' + str(symbols),
            '-x', source / 'external-function-declarations-gdb.py'], env=env)
    check('finish')
    result = json.loads((case / 'result.json').read_text())
    assert result['status'] == 'PASS'
    evidence = {**result, 'status': 'PASS_EXTERNAL_DECLARATIONS_MEASUREMENT', 'target': 'x86_64', 'role': 'exec',
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'],
        'phaseOutputs': pairs, 'projectBefore': project_before, 'projectAfter': project_after,
        'projectMetadataChanges': changes}
    oracle = case / 'coverage-oracle.json'
    oracle.write_text(json.dumps(evidence, indent=4) + '\n')
    measured.finish(oracle)
    print('external-function-declarations=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()
