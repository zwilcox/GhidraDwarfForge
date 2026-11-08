#!/usr/bin/env python3
"""Negative controls for the production combined policy, on owned files only."""
import hashlib
import json
import os
from pathlib import Path
import shutil


def exercise(java, runtime, report, original, sidecar, source, tools, root, run):
    root.mkdir()
    baseline = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in [report, original, sidecar, source, *tools]}
    results = []

    def require(condition, message):
        if not condition:
            raise AssertionError(message)

    def replay(name, role, body):
        path = root / (name + '-tool')
        version = 'GNU readelf (GNU Binutils) 2.42\n' if role == 'gnu' else 'LLVM version 18.1.3\n'
        path.write_text('#!/usr/bin/env python3\nimport os, signal, sys, time\nfrom pathlib import Path\n' +
                        'if sys.argv[1:] == ["--version"]:\n    sys.stdout.write(' + repr(version) +
                        ')\n    sys.exit(0)\n' + body + '\n')
        path.chmod(0o755)
        return path

    def rejected(name, selected_tools=None, selected_source=source, evidence=None, marker=None, expected=None):
        directory = root / name
        directory.mkdir()
        destination = directory / 'validation.json' if evidence is None else evidence
        selected = tools if selected_tools is None else selected_tools
        command = [java, '--enable-native-access=ALL-UNNAMED', '-cp', runtime,
                   'ghidradwarfforge.output.AttachmentValidatorProbe', report, original,
                   sidecar, selected_source, *selected, destination]
        if marker is not None:
            command.append(marker)
        outcome = run('policy-' + name, command, timeout=300, success=False)
        if expected is not None:
            require(expected in outcome.stderr, 'wrong rejection for ' + name)
        if evidence is None:
            require(not destination.exists(), 'failed validation published success for ' + name)
        results.append({'name': name, 'exit': outcome.returncode,
                        'stderrSha256': hashlib.sha256(outcome.stderr).hexdigest()})

    fake_gnu = replay('empty-gnu', 'gnu', 'pass')
    rejected('empty-gnu', [tools[0], fake_gnu, *tools[2:]], expected=b'GNU readelf report is missing')
    fake_gnu = replay('stderr-gnu', 'gnu', 'sys.stderr.write("warning: deliberate diagnostic\\n")')
    rejected('stderr-gnu', [tools[0], fake_gnu, *tools[2:]], expected=b'unexplained stderr')
    fake_llvm = replay('empty-llvm', 'llvm', 'pass')
    rejected('empty-llvm', [*tools[:2], fake_llvm, *tools[3:]], expected=b'LLVM report lacks complete')
    llvm_output = (root.parent / 'llvm.stdout').read_text()
    fake_llvm = replay('contradictory-llvm', 'llvm',
                       'sys.stdout.write(' + repr('error: deliberately inconsistent report\n' + llvm_output) + ')')
    rejected('contradictory-llvm', [*tools[:2], fake_llvm, *tools[3:]], expected=b'LLVM report lacks complete')
    wrong_configuration = root / 'wrong.conf'
    wrong_configuration.write_bytes(tools[4].read_bytes() + b'\n# changed\n')
    rejected('wrong-config', [*tools[:4], wrong_configuration], expected=b'configuration differs')
    require(not list((root / 'wrong-config').glob('.forge-*')), 'invalid configuration created a workspace')
    rejected('input-alias', evidence=original, expected=b'new attachment destination already exists')

    changed_source = root / 'private-source.c'
    shutil.copyfile(source, changed_source)
    fake_llvm = replay('source-change', 'llvm',
        'Path(' + repr(str(changed_source)) + ').write_text("concurrent source edit\\n")\n' +
        'sys.stdout.write(' + repr(llvm_output) + ')')
    rejected('source-change', [*tools[:2], fake_llvm, *tools[3:]], selected_source=changed_source,
             expected=b'attachment selection changed: source')

    collision = root / 'concurrent-evidence.json'
    fake_llvm = replay('evidence-change', 'llvm',
        'Path(' + repr(str(collision)) + ').write_text("concurrent user bytes\\n")\n' +
        'sys.stdout.write(' + repr(llvm_output) + ')')
    rejected('evidence-change', [*tools[:2], fake_llvm, *tools[3:]], evidence=collision,
             expected=b'new attachment destination already exists')
    require(collision.read_text() == 'concurrent user bytes\n', 'concurrent evidence was overwritten')

    marker = root / 'cancel.pid'
    fake_llvm = replay('cancel', 'llvm',
        'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n' +
        'Path(' + repr(str(marker)) + ').write_text(str(os.getpid()))\n' +
        'while True:\n    time.sleep(.01)')
    rejected('cancel', [*tools[:2], fake_llvm, *tools[3:]], marker=marker,
             expected=b'CancellationException: attachment validation cancelled')
    require(marker.exists(), 'cancellation never reached a running validator')
    try:
        os.kill(int(marker.read_text()), 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError('cancelled validator survived cleanup')
    for path, expected in baseline.items():
        require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected, 'protected policy input changed')
    (root / 'results.json').write_text(json.dumps({'status': 'PASS', 'cases': results,
        'protectedInputs': baseline}, indent=4) + '\n')
