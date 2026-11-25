"""Prepare the real Java report reader and shared launcher transcripts for both wrapper suites."""
import json
from pathlib import Path
import shutil
import sys


def prepare(ghidra, jar, fake):
    files = {'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar': jar}
    for path in ('Ghidra/Framework/Pty/lib/jna-5.14.0.jar', 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar'):
        files[path] = ghidra / path
    for relative, source in files.items():
        destination = fake / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    reports = fake / 'reports'
    reports.mkdir()
    # Ghidra 12.0.3 exports from a one-function x86-64 shared object and executable.
    # The three artifact paths were shortened to their basenames for portability.
    samples = Path(__file__).parent / 'fixtures' / 'headless-reports'
    completed = json.loads((samples / 'success.json').read_text(encoding='utf-8'))
    partial = json.loads((samples / 'partial.json').read_text(encoding='utf-8'))
    assert completed['status'] == 'SUCCESS' and partial['status'] == 'PARTIAL'
    terminal = dict(schemaVersion=2, target=None, artifacts=None, counts=None, sections=[],
                    failedFunctions=[], skippedFunctions=[], omittedLocations=[], unsupportedConstructs=[],
                    diagnostics=[], validation={'status': 'NOT_RUN'}, native={'libdwarfVersion': None},
                    failure={'type': 'fixture', 'message': 'fixture'}, coverage=None)
    incomplete = dict(schemaVersion=2, status='SUCCESS', artifacts={'outputPath': 'fixture.dbg'},
                      counts={'functionsExported': 1}, coverage={}, failure=None)
    marker = 'INFO  GhidraDwarfForge.java> GhidraDwarfForge report: '

    def record(document):
        prefix = marker.replace('INFO', 'ERROR') if document['status'] in ('CANCELLED', 'FATAL') else marker
        return prefix + json.dumps(document, separators=(',', ':')) + ' (GhidraScript)\n'

    success = record(completed)
    logs = {'SUCCESS': success, 'PARTIAL': record(partial), 'NONE': '', 'MULTIPLE': success * 2,
            'FATAL': record(dict(terminal, status='FATAL')), 'CANCELLED': record(dict(terminal, status='CANCELLED')),
            'INCOMPLETE': record(incomplete), 'TRUNCATED': marker + '{"schemaVersion":2,"status":"SUCCESS","counts":',
            'TRAILING_SUCCESS': success.rstrip() + ' unexpected\n',
            'PATH_MARKER': 'INFO  GhidraDwarfForge.java> input: /tmp/GhidraDwarfForge report: filename\n' + success}
    for group in ('artifacts', 'coverage'):
        logs['MISSING_' + group] = record({k: value for k, value in completed.items() if k != group})
        for key in completed[group]:
            fields = completed[group].copy()
            del fields[key]
            logs[f'MISSING_{group}_{key}'] = record({**completed, group: fields})
    for name, contents in logs.items():
        (reports / (name + '.log')).write_text(contents, encoding='utf-8')


if __name__ == '__main__':
    prepare(*(Path(argument) for argument in sys.argv[1:]))
