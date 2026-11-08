#!/usr/bin/env python3
"""Validate perf's offline build-ID source/variable lookup on a floating fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(path):
    values = re.findall(r'Build ID: ([0-9a-f]+)',
        subprocess.check_output(['readelf', '-n', str(path)], text=True))
    value, = set(values)
    assert len(value) >= 4 and len(value) % 2 == 0
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--perf', default='perf')
    args = parser.parse_args()
    source, root = args.case.resolve(), args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    original = source / 'floating.stripped'
    reference = source / 'floating.reference'
    sidecar = source / 'artifacts/floating.dbg'
    generated_source = Path(str(sidecar) + '.c')
    protected = {str(p): digest(p) for p in (original, reference, sidecar, generated_source)}
    build_id = identity(original)
    assert identity(reference) == identity(sidecar) == build_id
    info = subprocess.check_output(['readelf', '--debug-dump=info', str(sidecar)], text=True)
    (root / 'forge-info.txt').write_text(info)
    # The CU's directory must name the actual generated source parent. A random
    # staging basename, original compiler path or debugger CWD is not suitable.
    cu = info.split('DW_TAG_compile_unit', 1)[1].split('DW_TAG_', 1)[0]
    comp_dir, = re.findall(r'DW_AT_comp_dir\s*:\s*(.*)', cu)
    assert comp_dir.endswith(str(generated_source.parent)), comp_dir
    env = dict(os.environ, DEBUGINFOD_URLS='', LC_ALL='C')
    version = subprocess.check_output([args.perf, 'version'], env=env, text=True).strip()
    results = []
    for mode, symbols in [('compiler', reference), ('forge', sidecar)]:
        for control in ('empty', 'matched'):
            case = root / (mode + '-' + control)
            case.mkdir()
            binary = case / 'original'
            shutil.copy2(original, binary)
            symfs = case / 'symfs'
            symfs.mkdir()
            mirror = symfs / str(binary).lstrip('/')
            mirror.parent.mkdir(parents=True)
            shutil.copy2(binary, mirror)
            installed = symfs / 'usr/lib/debug/.build-id' / build_id[:2] / (build_id[2:] + '.debug')
            if control == 'matched':
                installed.parent.mkdir(parents=True)
                shutil.copy2(symbols, installed)
            for label, option in [('lines', '-L'), ('variables', '-V')]:
                command = [args.perf, '--buildid-dir', str(case / 'cache'), 'probe',
                    '--symfs', str(symfs), '-x', str(binary), option, 'fp_float']
                process = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=30)
                log = case / (label + '.log')
                log.write_text(process.stdout)
                (case / (label + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
                assert process.returncode >= 0, (mode, control, label, process.returncode)
                if control == 'matched':
                    assert process.returncode == 0, process.stdout
                    if label == 'lines':
                        assert 'fp_float_first = first;' in process.stdout, process.stdout
                        assert 'fp_float_second = second;' in process.stdout, process.stdout
                        if mode == 'forge':
                            assert str(generated_source) in process.stdout, process.stdout
                    else:
                        assert re.search(r'float\s+first\b', process.stdout), process.stdout
                        assert re.search(r'float\s+second\b', process.stdout), process.stdout
                else:
                    assert process.returncode != 0, process.stdout
                    assert ('Failed to find debug information' in process.stdout or
                        'file has no debug information.' in process.stdout), process.stdout
                results.append({'producer': mode, 'control': control, 'check': label,
                    'exit': process.returncode, 'log': str(log.relative_to(root)), 'sha256': digest(log)})
            assert digest(binary) == protected[str(original)] == digest(mirror)
            if control == 'matched':
                assert digest(installed) == digest(symbols)
    assert protected == {p: digest(Path(p)) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_PERF_SOURCE_LOOKUP',
        'version': version, 'buildId': build_id, 'compilationDirectory': str(generated_source.parent),
        'cases': results, 'protectedSha256': protected,
        'scope': 'Offline perf probe through a test-owned symfs build-ID root; no event recording, '
            'running-process probe installation, production installer or cache-discovery claim.'}, indent=4) + '\n')
    print('perf-source-lookup=PASS ' + str(source))


if __name__ == '__main__':
    main()
