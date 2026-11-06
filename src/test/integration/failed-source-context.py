#!/usr/bin/env python3
"""Validate all-failed and mixed native source exports with zero invented line rows."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    return {str(p.relative_to(root)): digest(p) for p in root.rglob('*')
        if p.is_file() and not p.name.endswith('.lock')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra', 'curation', 'consumer', 'producer'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    harness = Path(__file__).resolve().parent
    reference = args.curation.parent
    prepared = json.loads((args.curation / 'result.json').read_text())
    assert prepared['status'] == 'PASS_SAVED_ANNOTATIONS'
    root = Path(tempfile.mkdtemp(prefix='failed-source-', dir=args.curation)).resolve()
    print('failed-source-results=' + str(root), flush=True)
    project = root / 'project'
    shutil.copytree(args.curation / 'project', project)
    saved = snapshot(args.curation / 'project')
    scripts = root / 'scripts'
    scripts.mkdir()
    helper = harness / 'ghidra_scripts/ExportFailedSourceContext.java'
    shutil.copy2(helper, scripts)
    jar = args.ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    protected = {str(p.resolve()): digest(p) for p in [helper, Path(__file__), jar,
        harness / 'failed-source-context-gdb.py', harness / 'failed-source-context-gdb.sh',
        reference / 'stripped', reference / 'reference', reference / 'labels.json', args.consumer, args.producer]}
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        assert result.returncode == 0, (label, result.returncode)
        return (root / (label + '.log')).read_text()

    states, generations = [snapshot(project)], []
    for phase in ('first', 'second'):
        log = run(phase, [args.ghidra / 'support/analyzeHeadless', project, 'Annotations',
            '-process', 'stripped', '-readOnly', '-noanalysis', '-scriptPath', scripts,
            '-postScript', helper.name, reference / 'labels.json', reference / 'stripped', root, args.consumer, args.producer])
        assert 'failed-source-context=PASS' in log and 'ERROR REPORT SCRIPT ERROR' not in log
        generations.append({p.name: digest(p) for p in root.iterdir() if p.suffix in ('.dbg', '.c') or p.name in ('all.json', 'mixed.json')})
        states.append(snapshot(project))
    assert generations[0] == generations[1]
    changed = {p for p in states[0].keys() | states[1].keys() if states[0].get(p) != states[1].get(p)}
    assert changed <= {'Annotations.rep/idata/~index.bak', 'Annotations.rep/idata/~journal.bak'}
    assert states[1] == states[2]
    spec = importlib.util.spec_from_file_location('emission', harness / 'emission-evidence.py')
    emission = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(emission)
    cases = []
    for mode in ('all', 'mixed'):
        artifact = root / (mode + '.dbg')
        metadata = json.loads((root / (mode + '.json')).read_text())
        assert Path(unquote(urlsplit(metadata['origin']).path)).resolve() == jar.resolve()
        assert metadata['recoveredSignatures'] == 3, 'fixture must retain curated signatures before failure filtering'
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'rawline'):
            text = run(mode + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
            assert not re.search(r'(?im)(warning:|error:)', text), view
        run(mode + '-identity', ['readelf', '-hSWn', reference / 'stripped', artifact])
        assert 'No errors.' in run(mode + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        run(mode + '-strict', ['python3', harness / 'check-dwarfdump.py', artifact, root / (mode + '-dwarfdump.log'),
            '--original', reference / 'stripped'])
        dies = emission.dies((root / (mode + '-info.log')).read_text())
        for name in metadata['nativeFailures']:
            die, = [d for d in dies.values() if d['tag'] == 'DW_TAG_subprogram' and d['name'] == name]
            assert not {'decl_file', 'decl_line', 'type'} & die['attributes'].keys()
            assert not die['children'], 'failed function acquired a signature or local'
        rows = [(int(m[2], 16), int(m[1])) for m in re.finditer(r'(?m)^\S+\s+(\d+)\s+(0x[0-9a-fA-F]+)\b',
            (root / (mode + '-decodedline.log')).read_text())]
        if mode == 'all':
            assert not rows and not metadata['mappedLines'] and not metadata['emittedLines']['sequences']
            hex_dump = run('all-line-bytes', ['readelf', '-x', '.debug_line', artifact])
            values = []
            for line in hex_dump.splitlines():
                parts = line.split()
                if not parts or not parts[0].startswith('0x'):
                    continue
                values.extend(part for part in parts[1:5] if re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,4}', part))
            data = bytes.fromhex(''.join(values))
            order = '<' if (reference / 'stripped').read_bytes()[5] == 1 else '>'
            header_length = struct.unpack_from(order + 'I', data, 8)[0]
            assert data[12 + header_length:] == b'\x04\x00', 'file-only program emitted extra operations'
        else:
            assert rows and len(metadata['nativeFailures']) == 1
            failed_ranges = next(f['ranges'] for f in metadata['functions'] if f['name'] == 'annotation_probe')
            assert not any(r['address'] <= address < r['address'] + r['size'] for address, _ in rows for r in failed_ranges)
        gdb = run(mode + '-gdb', ['bash', harness / 'failed-source-context-gdb.sh',
            root, reference, prepared['target'], mode])
        assert 'failed-source-context-gdb=PASS' in gdb
        warnings = re.findall(r'(?m)^warning:.*$', gdb)
        compiler_warnings = re.findall(r'(?m)^warning:.*$', (reference / 'gdb.stdout').read_text() +
            (reference / 'gdb.stderr').read_text())
        assert warnings == compiler_warnings, (mode, warnings, compiler_warnings)
        cases.append({'mode': mode, 'nativeFailures': metadata['nativeFailures'], 'rawRows': len(rows),
            'gdb': json.loads((root / (mode + '-gdb.json')).read_text()), 'corroboratedWarnings': warnings})
    assert snapshot(args.curation / 'project') == saved and snapshot(project) == states[-1]
    assert protected == {p: digest(Path(p)) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_NATIVE_FAILED_SOURCE_EXPORT',
        'target': prepared['target'], 'cases': cases, 'generations': generations,
        'protectedSha256': protected, 'firstReopenBackups': sorted(changed)}, indent=4) + '\n')
    print('failed-source-context-harness=PASS ' + prepared['target'])


if __name__ == '__main__':
    main()
