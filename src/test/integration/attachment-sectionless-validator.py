#!/usr/bin/env python3
"""Exercise live attachment validation without a header-bearing original oracle."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--report-log', type=Path, required=True)
    parser.add_argument('--strict-validator', type=Path, required=True)
    parser.add_argument('--supervised-validator-helper', type=Path, required=True)
    parser.add_argument('--result-dir', type=Path, required=True)
    args = parser.parse_args()
    work = args.result_dir.absolute()
    work.mkdir(parents=True, exist_ok=False)
    provenance = work / 'provenance'
    provenance.mkdir()
    retained = work / 'inputs'
    retained.mkdir()
    reports = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
        for line in args.report_log.read_text().splitlines() if 'GhidraDwarfForge report: ' in line]
    require(len(reports) == 1, 'expected exactly one export report')
    report = reports[0]
    report_path = work / 'export-report.json'
    report_path.write_text(json.dumps(report, indent=4) + '\n')
    artifact = report['artifacts']
    inputs = [Path(artifact[key]).resolve(strict=True) for key in ('inputPath', 'outputPath', 'sourcePath')]
    for path, key in zip(inputs, ('inputSha256', 'outputSha256', 'sourceSha256')):
        require(digest(path) == artifact[key], 'export input no longer matches its report')
        shutil.copyfile(path, retained / path.name)
    original = inputs[0].read_bytes()
    require(original[:4] == b'\x7fELF' and original[4] in (1, 2) and original[5] in (1, 2), 'invalid ELF identity')
    wide = original[4] == 2
    order = '<' if original[5] == 1 else '>'

    def field(data, offset, fmt):
        return struct.unpack_from(order + fmt, data, offset)[0]

    require(field(original, 40 if wide else 32, 'Q' if wide else 'I') == 0 and
        field(original, 60 if wide else 48, 'H') == 0 and field(original, 62 if wide else 50, 'H') == 0,
        'fixture must have no section-header table')
    ghidra = args.ghidra.resolve()
    runtime = [args.jar.resolve(strict=True), ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar',
               ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar']
    sources = [ROOT / 'src/test/java/ghidradwarfforge/output' / (name + '.java') for name in
        ('AttachmentProtocolSmoke', 'AttachmentReceiptStoreSmoke', 'AttachmentElfTransactionProbe', 'AttachmentValidatorProbe')]
    bundle = args.strict_validator.resolve(strict=True).parents[1]
    tools = [args.supervised_validator_helper.resolve(strict=True), Path(shutil.which('readelf')).resolve(),
             Path(shutil.which('llvm-dwarfdump')).resolve(), bundle / 'libexec/dwarfdump',
             bundle / 'share/dwarfdump/dwarfdump.conf']
    oracle = ROOT / 'src/test/integration/check-dwarfdump.py'
    protected = {str(path): digest(path) for path in [*inputs, args.report_log, report_path, *runtime, *sources,
                                                   *tools, Path(__file__), oracle]}
    for path in [*runtime, *sources, Path(__file__), oracle]:
        shutil.copyfile(path, provenance / path.name)
        require(digest(provenance / path.name) == protected[str(path)], 'retained provenance differs')
    (provenance / 'origin.json').write_text(json.dumps(protected, indent=4) + '\n')
    commands = []

    def run(label, command, success=True):
        command = list(map(str, command))
        result = subprocess.run(command, capture_output=True, timeout=180)
        (work / (label + '.stdout')).write_bytes(result.stdout)
        (work / (label + '.stderr')).write_bytes(result.stderr)
        commands.append({'label': label, 'command': command, 'exitCode': result.returncode})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        require((result.returncode == 0) == success, label + ': ' + result.stderr.decode(errors='replace'))
        return result

    classes = work / 'classes'
    classes.mkdir()
    dependencies = os.pathsep.join(str(provenance / path.name) for path in runtime)
    run('compile', [os.environ.get('JAVAC', 'javac'), '--release', '21', '-cp', dependencies, '-d', classes,
                    *[provenance / path.name for path in sources]])
    java = os.environ.get('JAVA', 'java')
    require(b'version "21.' in run('java-version', [java, '-version']).stderr, 'actual Java 21 required')
    evidence = work / 'validation.json'
    command = [java, '-cp', str(classes) + os.pathsep + dependencies,
               'ghidradwarfforge.output.AttachmentValidatorProbe', report_path, *inputs, *tools, evidence]
    run('live-validator', command)
    record = json.loads(evidence.read_text())
    require(record['policy'] == 'gnu-llvm-libdwarf-2.3.2-v1' and record['status'] == 'PASS' and
        record['exportStatus'] == report['status'] and
        record['exportValidationStatus'] == report['validation']['status'], 'validator rewrote export status')
    expected_checks = {'gnuReadelfVersion', 'llvmDwarfdumpVersion', 'strictDwarfdumpVersion',
                       'gnuReadelf', 'llvmDwarfdump', 'strictSidecar'}
    if record['corroboratedFrameDiagnostics']:
        expected_checks.update(('strictOriginal', 'originalFrameViewGnu', 'originalFrameViewLlvm'))
    require(set(record['checks']) == expected_checks, 'missing live checks')
    for role, tool in zip(('validatorHelper', 'gnuReadelf', 'llvmDwarfdump', 'strictDwarfdump', 'strictConfiguration'), tools):
        require(record['tools'][role]['sha256'] == protected[str(tool)] and
            record['tools'][role]['path'] == str(tool), 'validator used a different tool')
    for role, path in zip(('exportOriginal', 'sidecar', 'source', 'exportReport'), [*inputs, report_path]):
        require(record['inputs'][role]['sha256'] == protected[str(path)] and
            record['inputs'][role]['path'] == str(path), 'validation bound a different input')
    for check in record['checks'].values():
        require(check['cleanupComplete'] and check['exitCode'] == 0 and check['reason'] == 'completed',
            'checker process did not finish cleanly')
        for raw in check['logs'].values():
            path = Path(raw['path'])
            require(path.stat().st_size == raw['bytes'] and digest(path) == raw['sha256'], 'raw log changed')
        require(check['logs']['tool.stderr']['bytes'] == 0, 'checker emitted unexplained stderr')
    spec = importlib.util.spec_from_file_location('strict_oracle', provenance / oracle.name)
    strict = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(strict)

    def stdout(name):
        return Path(record['checks'][name]['logs']['tool.stdout']['path']).read_text()

    diagnostics = record['corroboratedFrameDiagnostics']
    strict.validate_output(stdout('strictSidecar'), diagnostics)
    if diagnostics:
        frame = record['inheritedFrame']
        view_record = record['originalFrameView']
        view_path = Path(view_record['path'])
        view = view_path.read_bytes()
        require(frame['fromProgramHeaders'] and digest(view_path) == view_record['sha256'], 'view proof missing')
        require(field(view, 32 if wide else 28, 'Q' if wide else 'I') == 0 and
            field(view, 54 if wide else 42, 'H') == 0 and field(view, 56 if wide else 44, 'H') == 0,
            'frame view still loadable')
        mutable = ((32, 48), (54, 64)) if wide else ((28, 36), (42, 52))
        require(len(view) > len(original), 'view lacks appended table')
        copied = bytearray(view[:len(original)])
        for begin, end in mutable:
            copied[begin:end] = original[begin:end]
        require(copied == original, 'view changed original payload')
        require(field(view, 60 if wide else 48, 'H') == 3 and field(view, 62 if wide else 50, 'H') == 2,
            'unexpected view sections')
        offset, size = frame['originalOffset'], frame['bytes']
        require(0 <= offset < offset + size <= len(original) and
            hashlib.sha256(original[offset:offset + size]).hexdigest() == frame['sha256'], 'original frame bytes differ')
        section = field(view, 40 if wide else 32, 'Q' if wide else 'I') + (64 if wide else 40)
        require(field(view, section + 4, 'I') == 1 and
            field(view, section + (16 if wide else 12), 'Q' if wide else 'I') == frame['address'] and
            field(view, section + (24 if wide else 16), 'Q' if wide else 'I') == offset and
            field(view, section + (32 if wide else 20), 'Q' if wide else 'I') == size,
            'view section does not identify original frames')
        strict.validate_output(stdout('strictOriginal'), diagnostics, original=True)
        require('Contents of the .eh_frame section:' in stdout('originalFrameViewGnu') and
            stdout('originalFrameViewLlvm').rstrip().endswith('\nNo errors.'), 'view independent checks missing')
        shutil.copyfile(view_path, retained / view_path.name)
    else:
        require('originalFrameView' not in record, 'unneeded original frame view')
    published_hash = digest(evidence)
    refusal = run('exclusive-evidence', command, success=False)
    require(b'new attachment destination already exists' in refusal.stderr, 'unexpected exclusive-publication rejection')
    require(digest(evidence) == published_hash, 'second validation overwrote evidence')
    require(all(digest(path) == value for path, value in protected.items()), 'protected input changed')
    (work / 'result.json').write_text(json.dumps({'status': 'PASS', 'scope': 'live policy; limited Linux test host',
        'validationSha256': published_hash, 'frameDiagnostics': len(diagnostics)}, indent=4) + '\n')
    print('attachment-sectionless-validator=PASS')


if __name__ == '__main__':
    main()
