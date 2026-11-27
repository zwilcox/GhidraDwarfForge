#!/usr/bin/env python3
"""Bind real split-source exports and reject changed dependencies on owned Linux copies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from integration_coverage import Collection


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra', 'jar', 'report', 'original', 'sidecar', 'index', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--java', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[3]
    names = ('AttachmentBundleBindingProbe', 'AttachmentReceiptStoreSmoke', 'AttachmentProtocolSmoke', 'AttachmentPathBoundarySmoke')
    sources = [repo / 'src/test/java/ghidradwarfforge/output' / (name + '.java') for name in names]
    index = args.index.resolve(strict=True)
    manifest_name, = re.findall(r'^ \* Manifest: (forge-src-[0-9a-f]{64}\.json)$', index.read_text(), re.M)
    manifest = index.parent / manifest_name
    inventory = json.loads(manifest.read_text())
    parts = []
    for part in inventory['parts']:
        assert re.fullmatch(r'forge-src-[0-9]{6}-[0-9a-f]{64}\.c', part['name'])
        selected = index.parent / part['name']
        assert digest(selected) == part['sha256'] and selected.stat().st_size == part['bytes']
        parts.append(selected)
    selected_inputs = [args.report, args.original, args.sidecar, index, manifest, *parts]
    report = json.loads(args.report.read_text())
    for role, path in (('input', args.original), ('output', args.sidecar), ('source', index)):
        assert digest(path) == report['artifacts'][role + 'Sha256']
    assert inventory['inputSha256'] == digest(args.original)
    runtime = [args.jar.resolve(strict=True), args.ghidra / 'Ghidra/Framework/Generic/lib/gson-2.13.2.jar',
        args.ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar']
    protected = {str(path.resolve()): digest(path) for path in [*selected_inputs, *sources, *runtime,
        Path(__file__), Path(__file__).with_name('integration_coverage.py')]}
    (work / 'protected.json').write_text(json.dumps(protected, indent=4) + '\n')
    classes = work / 'classes'
    classes.mkdir()
    classpath = os.pathsep.join(map(str, [classes, *runtime]))
    java = args.java.resolve(strict=True)
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (work / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)

    run('compile', [java.with_name('javac'), '--release', '25', '-proc:none', '-cp', classpath,
        '-d', classes, *sources])
    collection = Collection('source-bundle-binding', args.jar, 'native-java',
        test_classes=tuple('ghidradwarfforge.output.' + name for name in names))
    command = [str(java), '-Djava.io.tmpdir=' + os.environ.get('TMPDIR', '/tmp'), '-cp', classpath,
        'ghidradwarfforge.output.AttachmentBundleBindingProbe', *map(str,
            (args.report.resolve(), args.original.resolve(), args.sidecar.resolve(), index, work / 'owned'))]
    with collection.session(command, 'source-bundle-boundaries') as measured:
        run('probe', measured)
    result = json.loads((work / 'owned/result.json').read_text())
    assert result['status'] == 'PASS_SOURCE_BUNDLE_BINDING'
    assert result['dependencies'] == len(parts) + 1 and result['checks'] == 6 * (len(parts) + 1) + 7
    assert result['inputSha256'] == digest(args.original) and result['productionHost'] is False
    assert protected == {path: digest(Path(path)) for path in protected}
    result.update(protectedInputs=protected, probeLogSha256=digest(work / 'probe.log'))
    (work / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    collection.finish(work / 'result.json')
    print('attachment-bundle-binding=PASS', flush=True)


if __name__ == '__main__':
    main()
