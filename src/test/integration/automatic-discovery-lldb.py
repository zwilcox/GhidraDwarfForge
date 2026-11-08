#!/usr/bin/env python3
"""Check fresh-session build-ID discovery independently of explicit symbol loading."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import lldb_consumer


def identity(path):
    values = re.findall(r'Build ID: ([0-9a-f]+)', subprocess.check_output(['readelf', '-n', str(path)], text=True))
    value, = set(values)
    assert len(value) >= 4 and len(value) % 2 == 0
    return value


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', required=True, choices=('x86_64', 'aarch64'))
    parser.add_argument('--lldb', default='lldb-18')
    args = parser.parse_args()
    source, root = args.case.resolve(), args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    original = source / 'floating.stripped'
    reference = source / 'floating.reference'
    sidecar = source / 'artifacts/floating.dbg'
    wrong = source.parent / ('pie' if source.name == 'exec' else 'exec')
    assert source.name in ('exec', 'pie')
    build_id = identity(original)
    assert identity(reference) == identity(sidecar) == build_id
    assert identity(wrong / 'floating.reference') != build_id
    protected_paths = [original, reference, sidecar, Path(str(sidecar) + '.c'), source / 'labels.txt',
        wrong / 'floating.reference', wrong / 'artifacts/floating.dbg']
    protected = {str(path): digest(path) for path in protected_paths}
    versions = lldb_consumer.versions(args.lldb, args.target)
    labels = {name: int(address, 16) for name, address in
        (line.split() for line in (source / 'labels.txt').read_text().splitlines())}
    scripts = Path(__file__).resolve().parent
    results = []
    for mode in ('compiler', 'forge'):
        symbols = reference if mode == 'compiler' else sidecar
        mismatch = wrong / ('floating.reference' if mode == 'compiler' else 'artifacts/floating.dbg')
        for control in ('unconfigured', 'mismatch', 'matched'):
            case = root / (mode + '-' + control)
            case.mkdir()
            binary = case / 'original'
            shutil.copy2(original, binary)
            installed = case / 'debug-root/.build-id' / build_id[:2] / (build_id[2:] + '.debug')
            installed.parent.mkdir(parents=True)
            shutil.copy2(mismatch if control == 'mismatch' else symbols, installed)
            empty = case / 'empty-root'
            empty.mkdir()
            selected_root = empty if control == 'unconfigured' else case / 'debug-root'
            output = case / 'consumer'
            config_path = case / 'config.json'
            config = {'mode': mode, 'target': args.target, 'control': control,
                'original': str(binary), 'symbolFile': str(installed), 'buildId': build_id,
                'source': str(sidecar) + '.c', 'labels': labels,
                'observations': str(output / 'observations.json'), 'lookup': str(output / 'lookup.json')}
            config_path.write_text(json.dumps(config, indent=4) + '\n')
            before = ['script exec(open(' + repr(str(scripts / 'automatic-discovery-lldb-observe.py')) + ').read())',
                'script discovery_lookup()']
            if control == 'matched':
                before += ['source list --name fp_float']
                before += ['breakpoint set --name ' + name + ' --skip-prologue false --one-shot true'
                    for name in ('fp_float', 'fp_double', 'fp_clobbered')]
                after = ['script exec(open(' + repr(str(scripts / 'floating-registers-lldb-observe.py')) + ').read())']
            else:
                after = ['script discovery_exit()']
            setup = ['settings set symbols.enable-external-lookup false',
                'settings set target.debug-file-search-paths ' + shlex.quote(str(selected_root))]
            transcript = lldb_consumer.run(binary, None, output, args.lldb, args.target, before, after,
                {'FORGE_LLDB_DISCOVERY_CONFIG': str(config_path), 'FORGE_LLDB_FP_CONFIG': str(config_path)},
                qemu_cpu='cortex-a53' if args.target == 'aarch64' else None, setup=setup)
            marker = 'FORGE_LLDB_FLOATING_PASS' if control == 'matched' else 'FORGE_LLDB_DISCOVERY_EXIT_PASS'
            assert marker in transcript
            lookup = json.loads((output / 'lookup.json').read_text())
            result = {'mode': mode, 'control': control, 'lookup': lookup}
            if control == 'matched':
                rows = json.loads((output / 'observations.json').read_text())
                assert len(rows) == 10
                result['observations'] = rows
            assert digest(binary) == digest(original)
            assert digest(installed) == digest(mismatch if control == 'mismatch' else symbols)
            assert protected == {path: digest(Path(path)) for path in protected}
            command = json.loads((output / 'command.json').read_text())
            assert not any('target symbols add' in token or 'target modules add' in token for token in command)
            results.append(result)
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_LLDB_AUTOMATIC_BUILD_ID',
        'target': args.target, 'role': source.name, 'versions': versions,
        'cases': results, 'protectedSha256': protected,
        'scope': 'Test-owned build-ID tree with explicit search-root setup; no production installer is implied.'}, indent=4) + '\n')
    print('lldb-automatic-discovery=PASS ' + args.target + ' ' + source.name)


if __name__ == '__main__':
    main()
