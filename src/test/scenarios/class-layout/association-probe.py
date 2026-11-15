#!/usr/bin/env python3
"""Show preference-driven THIS type selection without changing a saved program."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    directory = Path(__file__).resolve().parent
    repository = directory.parents[3]
    source = repository / 'src/test/fixtures/object-parameter.cpp'
    protected = {str(p): digest(p) for p in [source, Path(__file__), directory / 'ProbeClassAssociation.java']}
    commands, cases = [], []

    def run(name, command):
        command = list(map(str, command))
        commands.append({'name': name, 'argv': command})
        (out / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (out / (name + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)

    for target, compiler in [('x86_64', 'g++'), ('aarch64', 'aarch64-linux-gnu-g++')]:
        original = out / (target + '.reference')
        run(target + '-compile', [compiler, '-O0', '-g', '-gdwarf-5', '-fno-pie', '-no-pie', source, '-o', original])
        protected[str(original)] = digest(original)
        project = out / (target + '-project')
        project.mkdir()
        run(target + '-ghidra', [ghidra / 'support/analyzeHeadless', project, 'Association',
            '-import', original, '-readOnly', '-analysisTimeoutPerFile', '120', '-scriptPath', directory,
            '-postScript', 'ProbeClassAssociation.java', out / (target + '.json')])
        log = (out / (target + '-ghidra.log')).read_text()
        assert 'class-association-probe=PASS' in log and 'Discarded file import due to readOnly option' in log
        observation = json.loads((out / (target + '.json')).read_text())
        assert observation['javaVersion'].startswith('21.')
        cases.append({'target': target, 'observation': observation, 'observationSha256': digest(out / (target + '.json'))})
    archive = ghidra / 'Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling-src.zip'
    with zipfile.ZipFile(archive) as zipped:
        apis = {name: hashlib.sha256(zipped.read(name)).hexdigest() for name in [
            'ghidra/program/database/function/FunctionDB.java',
            'ghidra/program/model/listing/VariableUtilities.java',
            'ghidra/program/database/data/DataTypeUtilities.java',
            'ghidra/program/database/data/DataTypeManagerDB.java']}
    assert protected == {p: digest(Path(p)) for p in protected}
    (out / 'acceptance.json').write_text(json.dumps({'status': 'CLASS_ASSOCIATION_RESEARCH_PASS',
        'exporterAcceptance': False, 'cases': cases, 'apiSourceHashes': apis,
        'apiArchiveSha256': digest(archive), 'protected': protected}, indent=4) + '\n')
    print('class-association-research=PASS; no exporter acceptance')


if __name__ == '__main__':
    main()
