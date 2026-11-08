#!/usr/bin/env python3
"""Exercise derived provenance with real validators and an explicit test metadata host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    parser.add_argument('relocation', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--jar', required=True, type=Path)
    parser.add_argument('--test-classes', required=True)
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--strict-bundle', required=True, type=Path)
    parser.add_argument('--java', default='java')
    args = parser.parse_args()
    fixture, relocation, root = args.fixture.resolve(), args.relocation.resolve(), args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    jar, ghidra, bundle = args.jar.resolve(), args.ghidra.resolve(), args.strict_bundle.resolve()
    result = json.loads((relocation / 'result.json').read_text())
    candidate, = (relocation / 'debug root/.build-id').glob('*/*.debug')
    source = Path(result['sourceDirectory']) / 'floating.dbg.c'
    original, exported, export_source = fixture / 'floating.stripped', fixture / 'artifacts/floating.dbg', fixture / 'artifacts/floating.dbg.c'
    log = fixture / 'repeat/headless.txt'
    selected = [original, exported, export_source, candidate, source, jar, log]
    protected = {str(path): digest(path) for path in selected}
    reports = [line[line.index('{'):line.rindex('}') + 1] for line in log.read_text().splitlines()
        if 'GhidraDwarfForge report:' in line]
    assert len(reports) == 1
    report = root / 'reported-export.json'
    report.write_text(reports[0] + '\n')
    runtime = os.pathsep.join([str(jar), args.test_classes,
        str(ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar'),
        str(ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar')])
    java = shutil.which(args.java)
    assert java
    prefix = [java, '--enable-native-access=ALL-UNNAMED', '-Djava.io.tmpdir=' + str(root), '-cp', runtime]
    tools = [ghidra / 'Ghidra/Extensions/GhidraDwarfForge/os/linux_x86_64/forge-validator-supervisor',
        Path(shutil.which('readelf')), Path(shutil.which('llvm-dwarfdump')),
        bundle / 'libexec/dwarfdump', bundle / 'share/dwarfdump/dwarfdump.conf']

    def run(name, command):
        command = list(map(str, command))
        (root / (name + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (root / (name + '.log')).write_text(completed.stdout)
        assert completed.returncode == 0, completed.stdout[-5000:]
        return completed.stdout

    run('derived', prefix + ['ghidradwarfforge.output.DerivedArtifactValidatorProbe', report,
        original, exported, export_source, candidate, source, *tools, root / 'derived.json'])
    run('original', prefix + ['ghidradwarfforge.output.AttachmentValidatorProbe', report,
        original, exported, export_source, *tools, root / 'original.json'])
    controls = run('controls', prefix + ['ghidradwarfforge.output.ArtifactValidationBindingSmoke',
        report, original, exported, export_source, root / 'controls'])
    assert 'derived-binding-smoke=PASS' in controls
    derived = json.loads((root / 'derived.json').read_text())
    ordinary = json.loads((root / 'original.json').read_text())
    assert derived['schemaVersion'] == 3 and derived['artifactRelationship'] == 'exact-synthetic-source-relocation-v1'
    assert ordinary['schemaVersion'] == 2 and 'reportedExportInputs' not in ordinary
    assert derived['inputs']['sidecar']['sha256'] != derived['reportedExportInputs']['sidecar']['sha256']
    assert derived['inputs']['source']['sha256'] == derived['reportedExportInputs']['source']['sha256']
    assert derived['reportedExportInputs'] == ordinary['inputs']
    assert (derived['exportStatus'], derived['exportValidationStatus']) == (ordinary['exportStatus'], ordinary['exportValidationStatus'])
    assert protected == {path: digest(Path(path)) for path in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_DERIVED_VALIDATION',
        'target': result['target'], 'role': result['role'], 'protectedSha256': protected,
        'controls': controls.strip(), 'hostContract': derived['hostContract'],
        'scope': 'Production binding and GNU/LLVM/pinned strict policy; test-only metadata host; no installation or native host metadata acceptance.'}, indent=4) + '\n')
    print('derived-artifact-validation=PASS ' + result['target'] + ' ' + result['role'])


if __name__ == '__main__':
    main()
