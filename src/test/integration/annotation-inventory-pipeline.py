#!/usr/bin/env python3
"""Build, curate and independently reopen the packaged annotation inventory fixture."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=['x86_64', 'aarch64', 'mips32be', 'mips32le'])
    parser.add_argument('--results', type=Path)
    parser.add_argument('--consumer', type=Path)
    parser.add_argument('--producer', type=Path)
    args = parser.parse_args()
    if bool(args.consumer) != bool(args.producer):
        parser.error('--consumer and --producer must be supplied together')
    harness = Path(__file__).resolve().parent
    parent = (args.results or harness.parents[2] / 'build/test-results/annotation-inventory').resolve()
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=args.target + '-', dir=parent))
    print('annotation-inventory-pipeline-results=' + str(root), flush=True)
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=900)

    role = 'pie' if args.target == 'aarch64' else 'exec'
    run('reference', ['python3', harness / 'analyst-annotations-reference.py', args.target,
        '--role', role, '--results', root])
    case, = root.glob(args.target + '-' + role + '-*')
    run('prepare', ['python3', harness / 'analyst-annotations-prepare.py', args.ghidra, case])
    curation, = case.glob('curation-*')
    run('inventory', ['python3', harness / 'annotation-inventory.py', args.ghidra, curation])
    inventory, = curation.glob('inventory-*')
    result = json.loads((inventory / 'result.json').read_text())
    assert result['status'] == 'PASS_PACKAGED_ANNOTATION_INVENTORY'
    run('equate-evidence', ['python3', harness / 'equate-evidence.py', args.ghidra, curation])
    equate_evidence, = curation.glob('equate-evidence-*')
    assert json.loads((equate_evidence / 'result.json').read_text())['status'] == 'PASS_PACKAGED_EQUATE_EVIDENCE'
    placement = None
    default_export = None
    constants = None
    retained_names = None
    if args.consumer:
        classes = root / 'classes'
        classes.mkdir()
        java_home = Path(os.environ['JAVA_HOME'])
        module = args.ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
        gson = args.ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar'
        jna = args.ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar'
        classpath = os.pathsep.join(map(str, [classes, module.resolve(strict=True), gson.resolve(strict=True), jna.resolve(strict=True)]))
        run('compile-constants', [java_home / 'bin/javac', '-cp', classpath, '-d', classes,
            harness.parent / 'java/ghidradwarfforge/nativeapi/EquateConstantsSmoke.java'])
        run('constants', ['python3', harness / 'equate-constants.py', case, equate_evidence / 'read1.json', root,
            '--classpath', classpath, '--java', java_home / 'bin/java',
            '--consumer', args.consumer.resolve(strict=True), '--producer', args.producer.resolve(strict=True),
            '--dwarfdump', os.environ.get('DWARFDUMP', 'dwarfdump')])
        constants, = root.glob('equate-constants-*')
        assert json.loads((constants / 'result.json').read_text())['status'] == 'PASS_ISOLATED_PRODUCTION_CONSTANTS'
        run('placement', ['python3', harness / 'annotation-placement.py', args.ghidra, curation,
            args.consumer.resolve(strict=True), args.producer.resolve(strict=True)])
        placement, = curation.glob('placement-*')
        assert json.loads((placement / 'result.json').read_text())['status'] == 'PASS_SAVED_COMMENT_PLACEMENT'
        run('default-export', ['python3', harness / 'annotation-default-export.py', args.ghidra, curation,
            args.consumer.resolve(strict=True), args.producer.resolve(strict=True),
            '--placement-control', placement, '--equate-evidence', equate_evidence / 'read1.json'])
        default_export, = curation.glob('default-export-*')
        assert json.loads((default_export / 'result.json').read_text())['status'] == 'PASS_INSTALLED_DEFAULT_COMMENTS'
        if args.target == 'x86_64':
            run('retained-names', ['python3', harness / 'equate-retained-names.py', args.ghidra,
                args.consumer.resolve(strict=True), args.producer.resolve(strict=True), root])
            retained_names, = root.glob('retained-equates-*')
            assert json.loads((retained_names / 'result.json').read_text())['status'] == 'PASS_RETAINED_DEMANGLED_EQUATES'
    (root / 'result.json').write_text(json.dumps({'status': result['status'], 'target': args.target,
        'role': role, 'case': str(case), 'curation': str(curation), 'inventory': str(inventory),
        'equateEvidence': str(equate_evidence),
        'constants': str(constants) if constants else None,
        'retainedNames': str(retained_names) if retained_names else None,
        'placement': str(placement) if placement else None,
        'defaultExport': str(default_export) if default_export else None}, indent=4) + '\n')
    print('annotation-inventory-pipeline=PASS ' + args.target + ' ' + role)


if __name__ == '__main__':
    main()
