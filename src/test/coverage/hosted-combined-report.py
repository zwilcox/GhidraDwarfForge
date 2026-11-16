#!/usr/bin/env python3
"""Verify one CI cohort, union its Java probes, and enforce the accepted coverage targets."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('combined_report', HERE / 'combined-report.py')
combined = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(combined)
changed = combined.module('changed_code', HERE / 'changed-code.py')
files = combined.javaexec
call_sites = combined.module('call_site_admission', HERE / 'call-site-admission.py')
REQUIRED = {
    'linux': ('target-preflight', {'headless', 'native-java'}, {
        'gdb-companion', 'source-relocation', 'derived-validation', 'build-id-installation',
        'instruction-context', 'source-context', 'annotation-inventory', 'equate-evidence',
        'annotation-export', 'failed-source-export', 'class-scopes', 'inheritance-producer',
        'inheritance-names', 'build-id-command', 'cfi-encoder', 'cfi-composition-explicit',
        'cfi-composition-plain', 'cfi-composition-gabi', 'cfi-composition-gnu',
        'linux-attachment-exec', 'linux-attachment-pie', 'linux-attachment-exec-no-build-id',
        'gui-script-manager', 'gui-script-manager-loader', 'gui-script-manager-compressed',
        'gui-script-manager-unwind', 'lexical-shadow', 'object-parameter', 'object-return', 'formatter-export',
        'calling-convention', 'custom-call-storage', 'call-site-packaged'}),
    'linux_host': ('extension-build', {'native-java'}, {
        'linux-file-metadata', 'linux-directory-sync', 'linux-metadata-visibility'}),
    'firmware': ('cortex-m-profile', {'headless'}, {'raw-firmware'}),
    'windows': ('windows-host', {'windows'}, {
        'windows-attachment', 'windows-build-id-installation', 'windows-host-primitives'}),
}


def tools_classpath(bundle):
    metadata = files.read(bundle / 'tools.json')
    libraries = metadata.get('files', {})
    if (metadata.get('schema') != 1 or metadata.get('jacocoVersion') != '0.8.16'
            or not isinstance(libraries, dict) or not 0 < len(libraries) <= 16):
        raise ValueError('invalid JaCoCo report dependency manifest')
    files.exact_files(bundle / 'tools', libraries)
    paths, size = [], 0
    for name, digest in sorted(libraries.items()):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.jar', name) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('invalid report dependency name or digest')
        path = files.regular(bundle / 'tools' / name, 16 * 1024 * 1024)
        size += path.stat().st_size
        if size > 64 * 1024 * 1024 or files.digest(path) != digest:
            raise ValueError('changed or excessive report dependencies')
        paths.append(str(path.resolve()))
    return os.pathsep.join(paths)


def attachment_oracle(record, oracle):
    expected_role = record['suite'].removeprefix('linux-attachment-').replace('-no-build-id', '.no-build-id')
    if (oracle.get('host') != 'production Linux ext4 host' or oracle.get('target') != 'x86_64'
            or expected_role not in ('exec', 'pie', 'exec.no-build-id') or oracle.get('role') != expected_role
            or oracle.get('entryPoint') != 'AttachmentHelper'
            or oracle.get('validator') != 'production-live' or oracle.get('runtime') is not True):
        raise ValueError('hosted attachment coverage requires the real privileged host and debugger oracle')
    expected_cases = sorted(mode + '-' + boundary for mode in ('initial', 'refresh')
        for boundary in ('PREPARED', 'TARGET_REPLACED', 'BEFORE_COMMIT', 'COMMITTED')) if expected_role == 'exec' else []
    children = oracle.get('unmeasuredNestedChildren')
    halts = record.get('unmeasuredForcedHalts', [])
    if (not isinstance(children, list) or len(children) != len(expected_cases)
            or any(not isinstance(row, dict) or row.get('crashExit') != 89
                   or row.get('recoveryHelperMeasured') is not False for row in children)
            or sorted(row.get('case', '') for row in children) != expected_cases
            or sorted(row['label'] for row in halts) != expected_cases
            or any(row['exitCode'] != 89 for row in halts)):
        raise ValueError('hosted attachment coverage must disclose unmeasured recovery children')


def gui_oracle(record, oracle):
    suffix = record['suite'].removeprefix('gui-script-manager')
    mode = suffix.removeprefix('-') if suffix else 'default'
    required = {'installed-unwind-chooser=PASS', 'choices=7', 'exports=4', 'cancellations=3'} if mode == 'unwind' else {
        'script-manager-export-selection=PASS', 'script-manager-export-cancellation=PASS',
        'script-manager-structural-validation=PASS', 'script-manager-gdb=PASS'}
    if (mode not in ('default', 'loader', 'compressed', 'unwind')
            or oracle.get('status') != 'PASS_INTERACTIVE_GUI_MEASUREMENT' or oracle.get('mode') != mode
            or oracle.get('mainJvmSessions') != 1 or len(record['sessions']) != 1
            or oracle.get('desktop') != 'owned Xvfb and Openbox; actual Swing interactions'
            or not required.issubset(oracle.get('outcome', {}).get('requiredChecks', []))
            or oracle.get('unmeasuredNestedJvmKinds') != ['geometry calibration', 'report CLI', 'attachment helper']):
        raise ValueError('hosted GUI measurement requires actual interactive completion and nested-process disclosure')


def lexical_oracle(record, oracle):
    role = oracle.get('role')
    gap, calls, lines = (oracle.get(key) for key in ('discontiguous', 'calls', 'sourceLines'))
    labels = ['import', *(['export-baseline'] if lines is not None else []), 'export-first', 'export-repeat']
    nested = []
    if lines is None and gap:
        if oracle.get('controls') != ['stale', 'coalesced', 'native-decompiler-failure', 'copy-cancellation']:
            raise ValueError('lexical measurement lacks existing negative controls')
        nested = ['negative', 'failure']
    elif lines is None and role == 'pie-rebased':
        if oracle.get('coverageCuration') != 'PASS' or oracle.get('coverageStaging') != 'PASS':
            raise ValueError('lexical measurement lacks coverage publication controls')
        nested = ['coverage-staging', 'coverage-limit', 'coverage-byte-limit', 'coverage-curation']
    pair = oracle.get('outputPair')
    protected = oracle.get('protected')
    if (oracle.get('status') != 'PASS_LEXICAL_SHADOW_MEASUREMENT'
            or oracle.get('oracleStatus') != 'LEXICAL_SHADOW_PASS' or oracle.get('target') != 'x86_64'
            or oracle.get('javaRuntime') != 21 or role not in ('exec', 'pie', 'pie-rebased')
            or type(gap) is not bool or type(calls) is not bool
            or (lines is not None and type(lines) is not int)
            or (gap, calls, lines) not in ((False, False, None), (True, False, None), (True, True, None), (True, True, 8))
            or [row.get('label') for row in record['sessions']] != labels
            or oracle.get('measurement') != {'directAnalyzerSessions': len(labels), 'unmeasuredNestedDrivers': nested}
            or type(oracle.get('observations')) is not int or oracle['observations'] <= 0
            or not isinstance(pair, list) or len(pair) != 2
            or any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value) for value in pair)
            or not isinstance(protected, dict) or not protected
            or any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value) for value in protected.values())
            or (lines is not None and not oracle.get('sourceInventory'))):
        raise ValueError('lexical measurement lacks exact runtime, preservation or session evidence')
    return role, gap, calls, lines


def lexical_cohort(cases):
    expected = {(role, gap, calls, lines) for role in ('exec', 'pie', 'pie-rebased')
        for gap, calls, lines in ((False, False, None), (True, False, None), (True, True, None), (True, True, 8))}
    if len(cases) != len(expected) or set(cases) != expected:
        raise ValueError('lexical coverage requires every existing role, gap, call and partitioned-source case')


def object_oracle(record, oracle):
    suite, role = record['suite'], oracle.get('role')
    returning = suite == 'object-return'
    marker = 'OBJECT_RETURN' if returning else 'OBJECT_PARAMETER'
    pair, protected = oracle.get('outputPair'), oracle.get('protected')
    if (suite not in ('object-parameter', 'object-return') or record.get('layer') != 'headless'
            or oracle.get('status') != 'PASS_' + marker + '_MEASUREMENT'
            or oracle.get('oracleStatus') != marker + '_PASS'
            or oracle.get('target') != 'x86_64' or oracle.get('javaRuntime') != 21
            or role not in ('exec', 'pie', 'pie-rebased')
            or [row.get('label') for row in record['sessions']] != ['import', 'export-first', 'export-repeat']
            or not isinstance(pair, list) or len(pair) != 2
            or any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value) for value in pair)
            or not isinstance(protected, dict) or not protected
            or any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value) for value in protected.values())):
        raise ValueError('object measurement lacks exact analyzer, preservation or cohort evidence')
    observations = oracle.get('observations')
    if not isinstance(observations, list) or len(observations) != 2 or any(not isinstance(row, dict) for row in observations):
        raise ValueError('object measurement lacks both debugger observations')
    if returning:
        if any(row.get('status') != 'PASS' or row.get('aggregate') != [10, 4, 21]
                or row.get('ordinaryReturn') != 42 or row.get('exitCodes') != [0]
                or (role != 'exec' and (type(row.get('bias')) is not int or row['bias'] == 0)) for row in observations):
            raise ValueError('object-return measurement lacks compiler-correlated aggregate values')
        mode, children = 'return', []
    else:
        explicit, control = oracle.get('explicitBinding'), oracle.get('bindingControl')
        if type(explicit) is not bool or control not in (None, 'stale', 'conflict') or (explicit and control is not None):
            raise ValueError('object parameter measurement has invalid binding profile')
        mode = control or ('explicit' if explicit else 'inferred')
        children = ['failure'] if explicit else ['cancellation'] if control else []
        if (observations[0].get('objectValue') != 7 or observations[0].get('amount') != 3
                or observations[1].get('ordinaryValue') != 41 or observations[1].get('ordinaryName') != 'this'):
            raise ValueError('object parameter measurement lacks real object and ordinary-name values')
    if oracle.get('measurement') != {'directAnalyzerSessions': 3, 'unmeasuredNestedDrivers': children}:
        raise ValueError('object measurement must disclose its unmeasured failure/cancellation drivers')
    return suite, role, mode


def object_cohort(cases):
    expected = {('object-parameter', role, mode) for role in ('exec', 'pie', 'pie-rebased')
        for mode in ('inferred', 'explicit', 'stale', 'conflict')}
    expected.update(('object-return', role, 'return') for role in ('exec', 'pie', 'pie-rebased'))
    if len(cases) != len(expected) or set(cases) != expected:
        raise ValueError('object coverage requires every existing return, binding and ELF role case')


def formatter_oracle(record, oracle):
    labels = ['prepare', 'default-before', 'enabled', 'repeat', 'default-after',
        'restored-enabled', 'cancellation', 'missing-key', 'wrong-kind']
    wrapper_labels = [label for label in labels if label not in ('prepare', 'cancellation')]
    if (record.get('suite') != 'formatter-export' or record.get('layer') != 'headless'
            or oracle.get('status') != 'PASS_BASIC_PRODUCTION_FORMATTERS'
            or oracle.get('target') != 'x86_64' or oracle.get('lldb') is not True
            or type(oracle.get('allCompanions')) is not bool
            or oracle.get('role') not in ('exec', 'pie') or oracle.get('compression') not in ('none', 'zlib')
            or (oracle.get('sourceLines') is not None and type(oracle['sourceLines']) is not int)
            or [row.get('label') for row in record['sessions']] != labels
            or oracle.get('measurement') != {'directAnalyzerSessions': 2, 'wrapperAnalyzerSessions': 7,
                'exportRoute': 'production-wrapper'}):
        raise ValueError('formatter coverage requires production wrapper, cancellation and both debuggers')
    invocations = record.get('launcherInvocations', [])
    by_label = {row['label']: row['session'] for row in record['sessions']}
    if ([row.get('label') for row in invocations] != wrapper_labels
            or any(row.get('sessions') != [by_label[row['label']]] for row in invocations)):
        raise ValueError('formatter wrapper sessions do not match the actual analyzer invocations')
    enabled, default = oracle.get('enabledSha256'), oracle.get('defaultSha256')
    protected = oracle.get('testedSources')
    if (not isinstance(enabled, list) or len(enabled) < 3
            or not isinstance(default, list) or len(default) < 2 or enabled[1] != default[1]
            or not isinstance(protected, dict) or not protected
            or any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
                for value in [*enabled, *default, *protected.values(),
                    oracle.get('originalSha256'), oracle.get('selectionSha256')])
            or not isinstance(oracle.get('gdbVersion'), str) or not oracle['gdbVersion'].startswith('GNU gdb')):
        raise ValueError('formatter coverage lacks artifact preservation and debugger evidence')
    return (oracle.get('role'), oracle.get('compression'), oracle['allCompanions'], oracle.get('sourceLines'))


def formatter_cohort(cases):
    expected = {('exec', 'none', True, None), ('pie', 'zlib', False, None), ('pie', 'zlib', True, 8)}
    if len(cases) != len(expected) or set(cases) != expected:
        raise ValueError('formatter coverage requires all three production wrapper profiles')


def call_abi_oracle(record, oracle):
    custom = record.get('suite') == 'custom-call-storage'
    profile = oracle.get('compilerProfile') if custom else 'gcc'
    role = oracle.get('role')
    hashes, protected = oracle.get('hashes'), oracle.get('protected')
    if (record.get('suite') not in ('calling-convention', 'custom-call-storage')
            or record.get('layer') != 'headless' or oracle.get('status') != 'PASS_CALL_ABI_MEASUREMENT'
            or oracle.get('target') != 'x86_64' or role not in ('exec', 'pie', 'pie-rebased')
            or profile not in ('gcc', 'windows') or oracle.get('previousPackageCompared') is not False
            or oracle.get('protectedUnchanged') is not True
            or type(oracle.get('rebaseDelta')) is not int
            or (role == 'pie-rebased' and oracle['rebaseDelta'] < 0x2000000)
            or [row.get('label') for row in record['sessions']] != ['import', 'fixed', 'repeat']
            or oracle.get('measurement') != {'directAnalyzerSessions': 3, 'unmeasuredPreviousComparisons': []}
            or not isinstance(hashes, list) or len(hashes) != 2
            or not isinstance(protected, dict) or not protected
            or any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
                for value in [*hashes, *protected.values(), oracle.get('inputSha256')])):
        raise ValueError('call ABI coverage lacks exact current-package analyzer and preservation evidence')
    observations = oracle.get('observations')
    if (not isinstance(observations, list) or len(observations) != 2
            or any(not isinstance(row, dict) for row in observations)
            or [row.get('variant') for row in observations] != ['compiler', 'fixed']):
        raise ValueError('call ABI coverage requires both debugger observations')
    for observed in observations:
        fixed = observed['variant'] == 'fixed'
        expected = {'sysv_function', 'microsoft_function'} | ({'custom_return'} if custom else set())
        calls = observed.get('ordinaryCalls')
        if (observed.get('status') != 'PASS' or observed.get('exitCodes') != [0]
                or not isinstance(calls, list) or len(calls) != len(expected)
                or any(not isinstance(row, dict) for row in calls)
                or {row.get('name') for row in calls} != expected):
            raise ValueError('call ABI coverage lacks successful ordinary execution')
        for call in calls:
            name = call['name']
            blocked = fixed and (name != 'sysv_function' or profile == 'windows')
            if (call.get('entryValues') != ([1227] if name == 'custom_return' else [1, 2, 3, 4])
                    or call.get('returnedRegisterValue') != 1234 or call.get('gdbReturnUnavailable') is not blocked):
                raise ValueError('call ABI coverage lost arguments, return value or honest debugger restriction')
        injections = [('Microsoft', fixed, 4389)]
        if custom:
            injections += [('Sysv', fixed and profile == 'windows', 1234), ('Return', fixed, 7)]
        for name, blocked, value in injections:
            error, actual = observed.get('injected' + name + 'Error'), observed.get('injected' + name + 'Value')
            if ((blocked and (actual is not None or not isinstance(error, str)
                    or 'does not follow the target calling convention' not in error))
                    or (not blocked and (error is not None or actual != value))):
                raise ValueError('call ABI coverage lacks rejected injected-call and compiler-reference controls')
    return record['suite'], role, profile


def call_abi_cohort(cases):
    expected = {(suite, role, profile) for role in ('exec', 'pie', 'pie-rebased')
        for suite, profile in [('calling-convention', 'gcc'), ('custom-call-storage', 'gcc'),
            ('custom-call-storage', 'windows')]}
    if len(cases) != len(expected) or set(cases) != expected:
        raise ValueError('call ABI coverage requires all nine existing ELF and compiler profiles')


def load_job(root, jar, kind, commit, run):
    job, expected_layers, expected_suites = REQUIRED[kind]
    files.exact_files(root, {'collections', 'report'})
    summary = files.read(root / 'report/summary.json')
    if (summary.get('schema') != 1 or summary.get('status') != 'PASS' or summary.get('fixtureOnly')
            or summary.get('commit') != commit or summary.get('productionJarSha256') != files.digest(jar)
            or summary.get('cohort') != {'commit': commit, 'run': run, 'job': job}
            or set(summary.get('layers', {})) != expected_layers):
        raise ValueError('missing or mismatched CI integration cohort: ' + kind)
    rows, suites, known, unmeasured, lexical_cases, object_cases, formatter_cases = [], set(), set(), [], [], [], []
    call_abi_cases, call_site_cases = [], []
    for layer, measured in sorted(summary['layers'].items()):
        xml = files.regular(root / 'report' / (layer + '.xml'), 32 * 1024 * 1024)
        if files.digest(xml) != measured.get('xmlSha256'):
            raise ValueError('CI integration layer report changed')
        layer_rows, layer_suites, layer_halts = [], set(), []
        receipts = measured.get('receipts', {})
        if not isinstance(receipts, dict) or not 0 < len(receipts) <= 1000:
            raise ValueError('invalid CI integration collection inventory')
        for name, digest in sorted(receipts.items()):
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', name) or name in known:
                raise ValueError('invalid or duplicate CI integration collection')
            known.add(name)
            directory = root / 'collections' / name
            if directory.is_symlink() or files.digest(files.regular(directory / 'receipt.json', 1024 * 1024)) != digest:
                raise ValueError('CI integration receipt changed')
            record = combined.integration.validate_collection(directory, jar)
            if (record['layer'] != layer or record['host'] != ('nt' if kind == 'windows' else 'posix')
                    or record['productionClasses'] != measured['productionClasses']):
                raise ValueError('integration execution host, layer or class population mismatch')
            if record['suite'] == 'linux-metadata-visibility':
                oracle = files.read(directory / 'oracle.json')
                if oracle.get('privileged') != 'PASS' or oracle.get('unprivileged') != 'PASS':
                    raise ValueError('hosted visibility coverage requires both real privilege modes')
            if record['suite'].startswith('linux-attachment-'):
                attachment_oracle(record, files.read(directory / 'oracle.json'))
            if record['suite'].startswith('gui-script-manager'):
                gui_oracle(record, files.read(directory / 'oracle.json'))
            if record['suite'] == 'lexical-shadow':
                lexical_cases.append(lexical_oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] in ('object-parameter', 'object-return'):
                object_cases.append(object_oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] == 'formatter-export':
                formatter_cases.append(formatter_oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] in ('calling-convention', 'custom-call-storage'):
                call_abi_cases.append(call_abi_oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] == 'call-site-packaged':
                call_site_cases.append(call_sites.oracle(record, files.read(directory / 'oracle.json')))
            layer_suites.add(record['suite'])
            layer_rows.extend((layer, row['session'], directory / row['file']) for row in record['sessions'])
            layer_halts.extend({'suite': record['suite'], **row} for row in record.get('unmeasuredForcedHalts', []))
        if (len(layer_rows) != measured.get('sessions') or sorted(layer_suites) != measured.get('suites')
                or layer_halts != measured.get('unmeasuredForcedHalts', [])):
            raise ValueError('CI integration report omits or changes recorded sessions')
        rows.extend(layer_rows)
        suites.update(layer_suites)
        unmeasured.extend(layer_halts)
    files.exact_files(root / 'collections', known)
    if suites != expected_suites:
        raise ValueError('missing or unexpected required CI integration suite: ' + kind)
    if kind == 'linux':
        lexical_cohort(lexical_cases)
        object_cohort(object_cases)
        formatter_cohort(formatter_cases)
        call_abi_cohort(call_abi_cases)
        call_sites.cohort(call_site_cases)
    return rows, {'kind': kind, 'commit': commit, 'run': run, 'job': job,
        'summarySha256': files.digest(root / 'report/summary.json'),
        'receipts': {name: files.digest(root / 'collections' / name / 'receipt.json') for name in sorted(known)},
        'sessions': len(rows), 'suites': sorted(suites), 'unmeasuredForcedHalts': unmeasured}


def targets_met(summary):
    metrics = list(summary['overall'].values())
    for group in ('binaryAndLocationCorrectness', 'fileTransactionsAndValidation'):
        metrics.extend(summary['groups'][group]['metrics'].values())
    return all(value['targetMet'] is True for value in metrics)


def report(args):
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit) or not re.fullmatch(r'[1-9][0-9]*', args.run_id):
        raise ValueError('invalid CI coverage cohort')
    files.exact_files(args.bundle, {'production.jar', 'collection', 'tools', 'tools.json'})
    jar = files.regular(args.bundle / 'production.jar', 64 * 1024 * 1024).resolve()
    args.javaexec = args.bundle / 'collection'
    manifest = files.validate_collection(args.javaexec, jar, files.read(args.expected_tasks), args.commit, args.run_id)
    rows = [('javaexec', row['session'], args.javaexec / 'execution' / (row['task'] + '.exec'))
        for row in manifest['sessions']]
    origins = [{'kind': 'javaexec', 'commit': args.commit, 'run': args.run_id, 'job': 'extension-build',
        'manifestSha256': files.digest(args.javaexec / 'manifest.json'), 'sessions': len(rows)}]
    for kind in REQUIRED:
        executions, origin = load_job(getattr(args, kind), jar, kind, args.commit, args.run_id)
        rows.extend(executions)
        origins.append(origin)
    classpath = tools_classpath(args.bundle)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='combined-report-', dir=args.output.parent) as temporary:
        args.jacoco_classpath = Path(temporary) / 'classpath.txt'
        args.jacoco_classpath.write_text(classpath)
        result = combined.write_combined(args, jar, rows, origins,
            cohort={'commit': args.commit, 'run': args.run_id})
    result['changedCode'] = changed.report(args.sources.resolve().parents[2], args.base_commit,
        args.commit, args.output / 'xml/combined.xml', files.read(args.inventory)['targets']['changedCode'])
    result['targetsMet'] = targets_met(result) and result['changedCode']['targetsMet']
    files.save(args.output / 'summary.json', result)
    renderer = combined.module('combined_public_report', HERE.parents[2] / 'support/combined-coverage-report.py')
    renderer.generate(args.output, args.output / 'public', args.inventory, args.sources,
        args.repository, args.commit, int(args.run_id))
    # Preserve diagnostics when targets fail. An unmet goal is never a passing gate.
    print(json.dumps({'status': 'COVERAGE_TARGETS_MET' if result['targetsMet'] else 'COVERAGE_TARGETS_UNMET'}))
    return 0 if result['targetsMet'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'expected-tasks', 'linux', 'linux-host', 'firmware', 'windows',
            'inventory', 'sources', 'java', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--base-commit', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--repository', required=True)
    raise SystemExit(report(parser.parse_args()))


if __name__ == '__main__':
    main()
