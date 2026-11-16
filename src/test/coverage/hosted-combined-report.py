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
static_scopes = combined.module('static_scope_admission', HERE / 'static-scope-admission.py')
stack_flow = combined.module('stack_flow_admission', HERE / 'stack-flow-admission.py')
saved_inheritance = combined.module('saved_inheritance_admission', HERE / 'saved-inheritance-admission.py')
external_declarations = combined.module('external_declaration_admission', HERE / 'external-declaration-admission.py')
recovered_signatures = combined.module('recovered_signature_admission', HERE / 'recovered-signature-admission.py')
stack_transitions = combined.module('stack_transition_admission', HERE / 'stack-transition-admission.py')
producer_failures = combined.module('producer_failure_admission', HERE / 'producer-failure-admission.py')
qualified_types = combined.module('qualified_type_admission', HERE / 'qualified-type-admission.py')
metadata_failures = combined.module('metadata_failure_admission', HERE / 'linux-metadata-failure-admission.py')
windows_metadata_failures = combined.module('windows_metadata_failure_admission', HERE / 'windows-metadata-failure-admission.py')
windows_directory_failures = combined.module('windows_directory_failure_admission', HERE / 'windows-directory-failure-admission.py')
REQUIRED = {
    'linux': ('target-preflight', {'headless', 'native-java'}, {
        'gdb-companion', 'source-relocation', 'derived-validation', 'build-id-installation', 'build-id-identity',
        'instruction-context', 'source-context', 'annotation-inventory', 'equate-evidence',
        'equate-constants', 'equate-retained-names', 'bitfield-values',
        'annotation-export', 'failed-source-export', 'class-scopes', 'inheritance-producer',
        'inheritance-names', 'build-id-command', 'cfi-encoder', 'cfi-composition-explicit',
        'cfi-composition-plain', 'cfi-composition-gabi', 'cfi-composition-gnu',
        'linux-attachment-exec', 'linux-attachment-pie', 'linux-attachment-exec-no-build-id',
        'sectionless-validation',
        'gui-script-manager', 'gui-script-manager-loader', 'gui-script-manager-compressed',
        'gui-script-manager-unwind', 'lexical-shadow', 'object-parameter', 'object-return', 'formatter-export',
        'calling-convention', 'custom-call-storage', 'call-site-packaged',
        'lexical-statics', 'lexical-statics-controls', 'recovered-statics-positive', 'recovered-statics-controls',
        'stack-control-flow', 'saved-inheritance', 'external-declarations', 'recovered-returns', 'recovered-parameters',
        'stack-value-transitions', 'producer-failures', 'qualified-type-producer'}),
    'linux_aarch64': ('target-preflight', {'headless'}, {'stack-value-transitions', 'bitfield-values'}),
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


def build_id_identity_oracle(record, oracle):
    expected = {
        'absent': 'original has no build ID',
        'malformed': 'GNU build-ID size',
        'ambiguous': 'conflicting GNU build IDs',
        'baseline': None,
        'different-original': 'different original bytes',
        'hardlink': 'hardlink',
        'selected-alias': 'alias',
        **{'invalid-id-' + str(index): 'build ID must be canonical' for index in range(6)},
    }
    checks = oracle.get('checks')
    protected = oracle.get('protectedInputs')
    if (record.get('suite') != 'build-id-identity' or record.get('layer') != 'native-java'
            or oracle.get('status') != 'PASS' or oracle.get('host') != 'linux'
            or not isinstance(checks, list) or len(checks) != len(expected)
            or any(not isinstance(row, dict) for row in checks)
            or [row.get('name') for row in checks] != list(expected)
            or [row.get('label') for row in record.get('sessions', [])] != list(expected)
            or any(type(row.get('exit')) is not int or row['exit'] != (0 if error is None else 1)
                or row.get('expectedError') != error for row, error in zip(checks, expected.values()))
            or not isinstance(protected, dict) or len(protected) != 4
            or any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
                for value in protected.values())):
        raise ValueError('build-ID identity coverage requires every measured Linux refusal and preserved input')


def equate_oracle(record, oracle):
    suite = record.get('suite')
    retained = suite == 'equate-retained-names'
    expected_labels = ['setup', 'read1', 'read2'] if retained else ['one', 'two']
    protected = oracle.get('protected')
    def sha(value):
        return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None
    if (suite not in ('equate-constants', 'equate-retained-names')
            or record.get('layer') != ('headless' if retained else 'native-java')
            or [row.get('label') for row in record.get('sessions', [])] != expected_labels
            or not sha(oracle.get('gdbSha256'))
            or type(oracle.get('gdbChecks')) is not int
            or not isinstance(protected, dict) or len(protected) != (7 if retained else 4)
            or not all(sha(value) for value in protected.values())):
        raise ValueError('equate coverage requires measured exports, GDB checks and preserved inputs')
    if not retained:
        if (oracle.get('status') != 'PASS_ISOLATED_PRODUCTION_CONSTANTS'
                or oracle.get('constants') != 52 or oracle['gdbChecks'] != 104
                or oracle.get('deterministic') is not True or not sha(oracle.get('artifactSha256'))):
            raise ValueError('equate constants require deterministic production output and all GDB lookups')
        return
    generations = oracle.get('generations')
    changes = oracle.get('projectBackupChanges')
    if (oracle.get('status') != 'PASS_RETAINED_DEMANGLED_EQUATES' or oracle['gdbChecks'] != 20
            or oracle.get('runtime') != {'exitCodes': [0],
                'stoppedFunctions': ['curated_retained_function', 'curated_type_named_function']}
            or not isinstance(generations, list) or len(generations) != 2
            or not all(isinstance(row, dict) and set(row) == {'forge.dbg', 'forge.dbg.c'}
                and all(sha(value) for value in row.values()) for row in generations)
            or generations[0] != generations[1]
            or not isinstance(changes, list)
            or any(value not in ('Retained.rep/idata/~index.bak', 'Retained.rep/idata/~journal.bak')
                for value in changes)):
        raise ValueError('retained equates require repeatable exports, preserved project and live GDB stops')


def bitfield_oracle(record, oracle, *, require_lldb=True):
    def sha(value):
        return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None
    observations = oracle.get('gdb')
    protected = oracle.get('protected')
    if (record.get('suite') != 'bitfield-values' or record.get('layer') != 'headless'
            or [row.get('label') for row in record.get('sessions', [])] != ['export', 'repeat']
            or oracle.get('status') != 'PASS_MEASURED_BITFIELDS'
            or oracle.get('target') not in ('x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le')
            or oracle.get('deterministic') is not True
            or type(oracle.get('strictUncorroboratedErrors')) is not int
            or oracle['strictUncorroboratedErrors'] != 0
            or not all(sha(oracle.get(name)) for name in ('inputSha256', 'artifactSha256', 'sourceSha256'))
            or not isinstance(protected, dict) or len(protected) != 6
            or not all(sha(value) for value in protected.values())
            or not isinstance(observations, list) or len(observations) != 2
            or any(not isinstance(row, dict) or row.get('values') != ['word={a=5,b=17}', 'byte={a=5,b=17}']
                or row.get('exit') != 'normal' or not sha(row.get('logSha256')) for row in observations)):
        raise ValueError('bitfield coverage requires repeated measured exports and compiler/Forge GDB values')
    if require_lldb:
        lldb = oracle.get('lldb')
        expected = [{'name': name, 'size': size, 'fields': [
            {'name': 'a', 'value': 5, 'bits': 3, 'offset': 0},
            {'name': 'b', 'value': 17, 'bits': 5, 'offset': 3}]}
            for name, size in [('word_value', 4), ('byte_value', 1)]]
        if (not isinstance(lldb, dict) or lldb.get('status') != 'PASS_LLDB_BITFIELDS'
                or lldb.get('target') != oracle['target']
                or not isinstance(lldb.get('cases'), list) or len(lldb['cases']) != 2
                or any(not isinstance(row, dict) for row in lldb['cases'])
                or [row.get('mode') for row in lldb['cases']] != ['compiler', 'forge']
                or any(row.get('observations') != expected for row in lldb['cases'])):
            raise ValueError('hosted bitfield coverage requires matching real LLDB observations')


def attachment_oracle(record, oracle):
    expected_role = record['suite'].removeprefix('linux-attachment-').replace('-no-build-id', '.no-build-id')
    if (oracle.get('host') != 'production Linux ext4 host' or oracle.get('target') != 'x86_64'
            or expected_role not in ('exec', 'pie', 'exec.no-build-id') or oracle.get('role') != expected_role
            or oracle.get('entryPoint') != 'AttachmentHelper'
            or oracle.get('validator') != 'production-live' or oracle.get('runtime') is not True):
        raise ValueError('hosted attachment coverage requires the real privileged host and debugger oracle')
    expected_cases = sorted(mode + '-' + boundary for mode in ('initial', 'refresh')
        for boundary in ('PREPARED', 'TARGET_REPLACED', 'BEFORE_COMMIT', 'COMMITTED')) if expected_role == 'exec' else []
    children = oracle.get('recoveryChildren')
    halts = record.get('unmeasuredForcedHalts', [])
    if (not isinstance(children, list) or len(children) != len(expected_cases)
            or any(not isinstance(row, dict) or row.get('crashExit') != 89
                   or row.get('recoveryHelperMeasured') is not True
                   or type(row.get('recoveryHelperExit')) is not int or row['recoveryHelperExit'] != 0
                   or row.get('recoveryOutcome') != 'ROLLED_BACK' for row in children)
            or sorted(row.get('case', '') for row in children) != expected_cases
            or sorted(row['label'] for row in halts) != expected_cases
            or any(row['exitCode'] != 89 for row in halts)):
        raise ValueError('hosted attachment coverage requires measured recovery helpers and disclosed crashes')
    prefix = 'native-recovery-helper-'
    sessions = [row for row in record.get('sessions', []) if row.get('label', '').startswith(prefix)]
    launchers = [row for row in record.get('launcherInvocations', []) if row.get('label', '').startswith(prefix)]
    parents = [row for row in record.get('sessions', []) if row.get('label') == 'native-recovery']
    labels = sorted(prefix + case for case in expected_cases)
    if (sorted(row['label'] for row in sessions) != labels or sorted(row['label'] for row in launchers) != labels
            or len(parents) != (1 if expected_cases else 0)
            or any(row.get('status') != 'ORACLE_PASSED' for row in [*sessions, *launchers, *parents])):
        raise ValueError('recovery helpers lack distinct completed launcher/process sessions')
    identities = []
    for child in children:
        label = prefix + child['case']
        session = next(row for row in sessions if row['label'] == label)
        launcher = next(row for row in launchers if row['label'] == label)
        identity = child.get('recoverySession')
        if (not isinstance(identity, str) or not re.fullmatch(r'forge-integration-[0-9a-f]{32}', identity)
                or identity != session.get('session') or launcher.get('sessions') != [identity]):
            raise ValueError('recovery oracle is not bound to its measured child session')
        identities.append(identity)
    if len(set(identities)) != len(identities) or any(row.get('session') in identities for row in parents):
        raise ValueError('recovery children reuse another process session')


def sectionless_validation_oracle(record, oracle):
    checks = {'gnuReadelfVersion', 'llvmDwarfdumpVersion', 'strictDwarfdumpVersion',
        'gnuReadelf', 'llvmDwarfdump', 'strictSidecar'}
    diagnostics = oracle.get('frameDiagnostics')
    if (oracle.get('status') != 'PASS_SECTIONLESS_VALIDATION'
            or oracle.get('scope') != 'live policy; limited Linux test host'
            or oracle.get('machine') != 62
            or type(diagnostics) is not int or diagnostics < 0
            or oracle.get('originalUnchanged') is not True
            or oracle.get('exclusiveEvidenceRefused') is not True
            or not re.fullmatch(r'[0-9a-f]{64}', oracle.get('validationSha256', ''))
            or [row['label'] for row in record['sessions']] != ['live-validator', 'exclusive-evidence']):
        raise ValueError('sectionless validation lacks measured live checks, refusal or preservation')
    if diagnostics:
        checks.update(('strictOriginal', 'originalFrameViewGnu', 'originalFrameViewLlvm'))
        if (oracle.get('fromProgramHeaders') is not True
                or not re.fullmatch(r'[0-9a-f]{64}', oracle.get('originalFrameViewSha256') or '')):
            raise ValueError('sectionless validation lacks independent original-frame corroboration')
    elif oracle.get('fromProgramHeaders') is not None or oracle.get('originalFrameViewSha256') is not None:
        raise ValueError('sectionless validation has an unneeded original-frame claim')
    if oracle.get('checks') != sorted(checks):
        raise ValueError('sectionless validation omitted a required independent checker')


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
    call_abi_cases, call_site_cases, static_cases = [], [], []
    stack_flow_cases = []
    saved_inheritance_cases = []
    external_declaration_cases = []
    recovered_signature_cases = []
    stack_transition_cases = []
    producer_failure_cases = []
    qualified_type_cases = []
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
            if record['suite'] == 'linux-file-metadata':
                metadata_failures.oracle(record, files.read(directory / 'oracle.json'))
            if record['suite'] == 'build-id-identity':
                build_id_identity_oracle(record, files.read(directory / 'oracle.json'))
            if record['suite'] in ('equate-constants', 'equate-retained-names'):
                equate_oracle(record, files.read(directory / 'oracle.json'))
            if record['suite'] == 'bitfield-values':
                oracle = files.read(directory / 'oracle.json')
                bitfield_oracle(record, oracle)
                if oracle['target'] != ('aarch64' if kind == 'linux_aarch64' else 'x86_64'):
                    raise ValueError('bitfield target differs from hosted lane')
            if record['suite'] == 'windows-host-primitives':
                windows_metadata_failures.oracle(record, files.read(directory / 'oracle.json'))
                windows_directory_failures.oracle(record, files.read(directory / 'oracle.json'))
            if record['suite'].startswith('linux-attachment-'):
                attachment_oracle(record, files.read(directory / 'oracle.json'))
            if record['suite'] == 'sectionless-validation':
                sectionless_validation_oracle(record, files.read(directory / 'oracle.json'))
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
            if record['suite'] in static_scopes.SUITES:
                static_cases.append(static_scopes.oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] == 'stack-control-flow':
                stack_flow_cases.append(stack_flow.oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] == 'saved-inheritance':
                saved_inheritance_cases.append(saved_inheritance.oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] == 'external-declarations':
                external_declaration_cases.append(external_declarations.oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] in ('recovered-returns', 'recovered-parameters'):
                recovered_signature_cases.append(recovered_signatures.oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] == 'producer-failures':
                producer_failure_cases.append(producer_failures.oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] == 'qualified-type-producer':
                qualified_type_cases.append(qualified_types.oracle(record, files.read(directory / 'oracle.json')))
            if record['suite'] == 'stack-value-transitions':
                stack_transition_cases.append(stack_transitions.oracle(record, files.read(directory / 'oracle.json')))
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
        static_scopes.cohort(static_cases)
        stack_flow.cohort(stack_flow_cases)
        saved_inheritance.cohort(saved_inheritance_cases)
        external_declarations.cohort(external_declaration_cases)
        recovered_signatures.cohort(recovered_signature_cases)
        producer_failures.cohort(producer_failure_cases)
        qualified_types.cohort(qualified_type_cases)
    if kind in ('linux', 'linux_aarch64'):
        stack_transitions.cohort(stack_transition_cases, ['x86_64' if kind == 'linux' else 'aarch64'])
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
    return finish_report(args, result)


def finish_report(args, result):
    """Apply the checked-in policy and retain diagnostics even when its gate fails."""
    result['changedCode'] = changed.report(args.sources.resolve().parents[2], args.base_commit,
        args.commit, args.output / 'xml/combined.xml', files.read(args.inventory)['targets']['substantialChangedLogic'])
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
    for name in ('bundle', 'expected-tasks', 'linux', 'linux-host', 'linux-aarch64', 'firmware', 'windows',
            'inventory', 'sources', 'java', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--base-commit', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--repository', required=True)
    raise SystemExit(report(parser.parse_args()))


if __name__ == '__main__':
    main()
