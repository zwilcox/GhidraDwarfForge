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
    fields = ('functionsExported functionsDecompiled functionsFailed functionsSkipped functionSignatures '
              'parameters localVariables globalVariables functionStaticVariables canonicalTypes '
              'defensibleVariableLocations omittedLocationRanges mappedSourceLines unsupportedConstructs diagnostics')
    completed = dict(schemaVersion=1, status='SUCCESS', target=dict(architecture='x86_64', addressBits=64,
                     byteOrder='LITTLE_ENDIAN'), counts=dict.fromkeys(fields.split(), 0), sections=[],
                     failedFunctions=[], skippedFunctions=[], omittedLocations=[], unsupportedConstructs=[],
                     diagnostics=[], validation={'status': 'NOT_RUN'}, native={'libdwarfVersion': 'fixture'},
                     artifacts={k + suffix: value for k in ('input', 'output', 'source')
                                for suffix, value in [('Path', k + '.elf'), ('Sha256', 'a' * 64)]}, failure=None)
    partial = dict(completed, status='PARTIAL', diagnostics=['fixture diagnostic'],
                   counts=dict(completed['counts'], diagnostics=1))
    terminal = dict(completed, target=None, artifacts=None, counts=None, native={'libdwarfVersion': None},
                    failure={'type': 'fixture', 'message': 'fixture'})
    incomplete = dict(schemaVersion=2, status='SUCCESS', artifacts={'outputPath': 'fixture.dbg'},
                      counts={'functionsExported': 1}, coverage={}, failure=None)
    marker = 'INFO  GhidraDwarfForge.java> GhidraDwarfForge report: '

    def record(document):
        prefix = marker.replace('INFO', 'ERROR') if document['status'] in ('CANCELLED', 'FATAL') else marker
        return prefix + json.dumps(document, separators=(',', ':')) + ' (GhidraScript)\n'

    success = record(completed)
    artifacts_without_hash = completed['artifacts'].copy()
    del artifacts_without_hash['sourceSha256']
    logs = {'SUCCESS': success, 'PARTIAL': record(partial), 'NONE': '', 'MULTIPLE': success * 2,
            'FATAL': record(dict(terminal, status='FATAL')), 'CANCELLED': record(dict(terminal, status='CANCELLED')),
            'INCOMPLETE': record(incomplete), 'TRUNCATED': marker + '{"schemaVersion":2,"status":"SUCCESS","counts":',
            'MISSING_HASH': record(dict(completed, artifacts=artifacts_without_hash)),
            'TRAILING_SUCCESS': success.rstrip() + ' unexpected\n',
            'PATH_MARKER': 'INFO  GhidraDwarfForge.java> input: /tmp/GhidraDwarfForge report: filename\n' + success}
    for name, contents in logs.items():
        (reports / (name + '.log')).write_text(contents, encoding='utf-8')


if __name__ == '__main__':
    prepare(*(Path(argument) for argument in sys.argv[1:]))
