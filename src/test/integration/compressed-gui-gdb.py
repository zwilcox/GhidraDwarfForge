#!/usr/bin/env python3
"""Validate and execute an unchanged compressed GUI artifact, including Windows exports."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys


spec = importlib.util.spec_from_file_location('compression', Path(__file__).with_name('compression-export.py'))
compression = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compression)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--incoming', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    incoming = args.incoming.resolve(strict=True)
    cases = [p.parent.parent for p in incoming.glob('run.*/select/result.txt')
        if 'compression=true\n' in p.read_text() and 'result=PASS\n' in p.read_text()]
    compression.require(len(cases) == 1, 'expected one accepted compressed GUI journey')
    case, = cases
    files = [case / 'select/readonly/fixture', case / 'select/chosen/fixture.dbg',
        case / 'select/chosen/fixture.dbg.c']
    before = {str(p): compression.digest(p) for p in case.rglob('*') if p.is_file()}
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=False)
    for path in files:
        shutil.copyfile(path, results / path.name)
        compression.require(compression.digest(results / path.name) == before[str(path)], 'copy changed bytes')
    original, sidecar, source = [results / p.name for p in files]
    original.chmod(0o755)
    sections = compression.sections(sidecar)
    compression.require(sections['.debug_info']['compressed'], 'GUI artifact is not compressed')

    def run(label, command):
        result = subprocess.run(list(map(str, command)), cwd=results, capture_output=True, timeout=180)
        (results / (label + '.stdout')).write_bytes(result.stdout)
        (results / (label + '.stderr')).write_bytes(result.stderr)
        compression.require(result.returncode == 0 and not result.stderr, label + ' failed')
        return result.stdout.decode()

    run('gnu', ['readelf', '-h', '-SW', '-n', '--debug-dump=info', '--debug-dump=abbrev',
        '--debug-dump=decodedline', '--debug-dump=aranges', '--debug-dump=Ranges', '--debug-dump=loc', sidecar])
    run('llvm', ['llvm-dwarfdump', '--verify', sidecar])
    run('strict', [sys.executable, Path(__file__).with_name('check-dwarfdump.py').resolve(), sidecar,
        results / 'strict-checks.txt', '--original', original])
    commands = ['set pagination off', 'set confirm off', 'set debuginfod enabled off',
        'set auto-solib-add off', 'set auto-load off',
        'file ' + json.dumps(str(original)), 'symbol-file ' + json.dumps(str(sidecar)),
        'directory ' + str(results),
        'set substitute-path ' + json.dumps(str(case / 'select/chosen')) + ' ' + json.dumps(str(results)),
        'info functions gui_recovered_add', 'ptype gui_recovered_add', 'list gui_recovered_add',
        'break gui_recovered_add', 'python', 'import hashlib, os', 'exits=[]',
        'gdb.events.exited.connect(lambda event: exits.append(getattr(event, "exit_code", None)))', 'end', 'run',
        'python', 'frame=gdb.selected_frame()', 'assert frame.name() == "gui_recovered_add"',
        'symbol=gdb.lookup_global_symbol("gui_recovered_add") or gdb.lookup_static_symbol("gui_recovered_add")',
        'assert symbol and symbol.is_function and symbol.symtab',
        'path=frame.find_sal().symtab.fullname()',
        'assert os.path.isfile(path), path',
        'assert hashlib.sha256(open(path,"rb").read()).hexdigest() == ' + repr(compression.digest(source)),
        'before=int(gdb.parse_and_eval("$pc"))', 'end', 'next',
        'python assert int(gdb.parse_and_eval("$pc")) != before',
        'python before=int(gdb.parse_and_eval("$pc"))', 'step',
        'python assert int(gdb.parse_and_eval("$pc")) != before',
        'disable breakpoints', 'continue', 'python assert exits == [0], exits',
        'echo COMPRESSED_GUI_GDB_PASS\n']
    script = results / 'oracle.gdb'
    script.write_text('\n'.join(commands) + '\n')
    transcript = run('gdb', ['gdb', '-q', '-nx', '-batch', '-x', script])
    compression.require('COMPRESSED_GUI_GDB_PASS' in transcript, 'GDB did not complete')
    after = {str(p): compression.digest(p) for p in case.rglob('*') if p.is_file()}
    compression.require(before == after, 'consumer changed incoming files')
    (results / 'receipt.json').write_text(json.dumps({'status': 'PASS', 'sections': sections,
        'incomingSha256': before, 'scope': 'Unchanged GUI artifact; GNU/LLVM/strict and native Linux '
        'GDB function/type/source/next/step/exit. Explicit source directory after host transfer.'}, indent=4) + '\n')
    print('compressed-gui-gdb=PASS')


if __name__ == '__main__':
    main()
