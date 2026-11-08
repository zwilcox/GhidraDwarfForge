#!/usr/bin/env python3
"""Verify native failure/cancellation in an existing private annotation fixture.

This exercises Ghidra APIs, not production Forge failure isolation or publication.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from importlib.util import module_from_spec, spec_from_file_location


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('curation', type=Path)
    args = parser.parse_args()
    ghidra, curation = args.ghidra.resolve(strict=True), args.curation.resolve(strict=True)
    spec = spec_from_file_location('preparation', Path(__file__).with_name('analyst-annotations-prepare.py'))
    preparation = module_from_spec(spec)
    spec.loader.exec_module(preparation)
    digest, snapshot = preparation.digest, preparation.snapshot
    saved = json.loads((curation / 'result.json').read_text())
    assert saved['status'] == 'PASS_SAVED_ANNOTATIONS'
    case = curation.parent
    source = Path(__file__).with_name('ghidra_scripts') / 'VerifyAnalystAnnotationFailures.java'
    protected = {str(path): digest(path) for path in [source, Path(__file__),
        case / 'reference', case / 'stripped', case / 'labels.json', curation / 'result.json',
        curation / 'read1.json', curation / 'read2.json']}
    for path in ('reference', 'stripped', 'labels.json'):
        assert digest(case / path) == saved['protectedSha256'][str(case / path)]
    root = Path(tempfile.mkdtemp(prefix='native-failures-', dir=curation))
    print('analyst-annotation-failure-results=' + str(root), flush=True)
    scripts = root / 'scripts'
    scripts.mkdir()
    shutil.copy2(source, scripts / source.name)
    states = [snapshot(curation / 'project')]
    commands = []
    for name in ('read1', 'read2'):
        command = [str(ghidra / 'support/analyzeHeadless'), str(curation / 'project'), 'Annotations',
            '-process', 'stripped', '-readOnly', '-noanalysis', '-scriptPath', str(scripts),
            '-postScript', source.name, str(case / 'labels.json'), str(root / (name + '.json'))]
        commands.append(command)
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (name + '.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180)
        text = (root / (name + '.log')).read_text()
        assert result.returncode == 0 and 'analyst-annotation-failures=PASS instruction-limit cancellation recovery comments=5' in text
        assert 'ERROR REPORT SCRIPT ERROR' not in text and 'error: cannot find symbol' not in text
        states.append(snapshot(curation / 'project'))
    assert states[0] == states[1] == states[2], 'read-only failure probe changed saved project'
    assert (root / 'read1.json').read_bytes() == (root / 'read2.json').read_bytes()
    assert protected == {path: digest(Path(path)) for path in protected}
    observations = json.loads((root / 'read1.json').read_text())
    assert observations['normalBefore'] == observations['normalAfterFailure'] == observations['normalAfter']
    assert len(observations['failedFunctionComments']) == 5
    for index, state in enumerate(states):
        (root / ('project-' + str(index) + '.json')).write_text(json.dumps(state, indent=4) + '\n')
    receipt = {'status': 'PASS_NATIVE_FAILURE_FIXTURE', 'target': saved['target'], 'role': saved['role'],
        'protectedSha256': protected, 'readbackSha256': digest(root / 'read1.json'),
        'projectUnchanged': True, 'observations': observations,
        'limits': 'Native fixture API checks only. Cancellation is pre-cancelled, not an in-flight timing test. Production Forge failure isolation, cancellation cleanup and diagnostic source/line emission remain unverified by this harness.'}
    (root / 'result.json').write_text(json.dumps(receipt, indent=4) + '\n')
    print('analyst-annotation-failures=PASS ' + saved['target'] + ' ' + saved['role'])


if __name__ == '__main__':
    main()
