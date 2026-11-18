"""Require packaged call-site behavior before admitting its Java coverage."""
from pathlib import Path
import re
import runpy


RECOVERED = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'integration/call-site-recovered.py'))
REFERENCE = RECOVERED['reference']


def hashes(values):
    return bool(values) and all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value)
        for value in values)


def runtime(rows, view_key):
    expected = {(view, scenario) for view in ('original', 'rebased') for scenario in range(8)}
    if (not isinstance(rows, list) or len(rows) != 16
            or any(not isinstance(row, dict) for row in rows)
            or {(row.get(view_key), row.get('scenario')) for row in rows} != expected):
        raise ValueError('call-site coverage requires all sixteen debugger observations')
    for row in rows:
        try:
            if row['status'] != 'PASS' or row['observation']['status'] != 'OBSERVED':
                raise ValueError('call-site debugger observation failed')
            RECOVERED['check'](row['observation'], row['scenario'])
        except (AssertionError, KeyError, TypeError, IndexError) as error:
            raise ValueError('call-site debugger frames, tails or entry values differ') from error


def compiler_runtime(rows, role):
    expected = {(mode, scenario) for mode in ('compiler', 'absent') for scenario in range(8)}
    if (not isinstance(rows, list) or len(rows) != 16
            or any(not isinstance(row, dict) for row in rows)
            or {(row.get('mode'), row.get('scenario')) for row in rows} != expected):
        raise ValueError('call-site coverage requires compiler and absent-debug controls')
    for row in rows:
        scenario, compiler = row['scenario'], row['mode'] == 'compiler'
        intermediate = REFERENCE['EXPECTED_FRAMES'][scenario] if compiler else (
            ('cs_normal',) if scenario == 0 else ('cs_recursive',) * 3 if scenario == 4 else ())
        frames = ['cs_checkpoint', 'cs_leaf', *intermediate, 'cs_driver', 'main']
        tails = [name for index, name in enumerate(frames) if compiler and 2 <= index < len(frames) - 2
            and (scenario in (1, 5, 7) or scenario == 4 and index == 2)]
        try:
            bias = int(row['runtimeBias'], 16)
        except (KeyError, ValueError, TypeError) as error:
            raise ValueError('call-site compiler control lacks runtime bias') from error
        if (row.get('frames') != frames or row.get('tailFrames') != tails
                or row.get('sink') != REFERENCE['EXPECTED_SINK'][scenario] or row.get('exitCode') != 0
                or (bias != 0) != (role == 'pie')):
            raise ValueError('call-site compiler or absent-debug behavior differs')
        if compiler:
            entries = row.get('entryValues')
            expected_entries = REFERENCE['EXPECTED_ENTRY'][scenario]
            if not isinstance(entries, list) or len(entries) != len(expected_entries):
                raise ValueError('call-site compiler control lost entry values')
            for entry, value in zip(entries, expected_entries):
                if (not isinstance(entry, dict) or entry.get('available') is not (value is not None)
                        or value is not None and entry.get('value') != value):
                    raise ValueError('call-site compiler entry value differs')


def oracle(record, evidence):
    role = evidence.get('role')
    inventory, saved = evidence.get('installedInventory'), evidence.get('savedProgramSha256')
    if (record.get('suite') != 'call-site-packaged' or record.get('layer') != 'headless'
            or evidence.get('status') != 'PASS_PACKAGED_CALL_SITES' or evidence.get('failures') != []
            or evidence.get('target') != 'x86_64' or role not in ('exec', 'pie')
            or evidence.get('probeReport') != 'switch-plan'
            or [row.get('label') for row in record['sessions']] != ['original-headless', 'rebased-headless']
            or evidence.get('measurement') != {'directAnalyzerSessions': 2, 'exportsPerSession': 2,
                'prerequisitesMeasured': False}
            or not isinstance(inventory, dict) or not hashes(list(inventory.values()))
            or inventory.get('lib/GhidraDwarfForge.jar') != record.get('productionJarSha256')
            or not isinstance(saved, dict) or not hashes(list(saved.values()))
            or not hashes([evidence.get('packageSha256'), evidence.get('inputSha256')])):
        raise ValueError('call-site coverage lacks packaged analyzer and preservation evidence')
    sources = evidence.get('testedSources')
    if not isinstance(sources, dict) or not hashes(list(sources.values())):
        raise ValueError('call-site coverage lacks tested source identities')
    exports = evidence.get('exports')
    if not isinstance(exports, list) or len(exports) != 2:
        raise ValueError('call-site coverage requires both exported program views')
    for export in exports:
        if (not isinstance(export, dict) or export.get('status') != 'PASS_PACKAGED_CALL_SITE_EXPORT'
                or export.get('readOnlyProject') is not True or export.get('correctedDriverBody') is not True
                or set(export.get('analystNamedThunks', [])) != {'cs_indirect', 'cs_forward'}
                or export.get('inputSha256') != evidence['inputSha256']
                or export.get('jarSha256') != record['productionJarSha256']
                or export.get('scriptSha256') != inventory.get('ghidra_scripts/GhidraDwarfForge.java')
                or not hashes([export.get(name) for name in ('jarSha256', 'scriptSha256',
                    'consumerSha256', 'producerSha256', 'sidecarSha256', 'sourceSha256')])
                or type(export.get('rebaseDelta')) is not int):
            raise ValueError('call-site export package, curated program or artifact evidence differs')
        for library, field in [('libdwarf.so.', 'consumerSha256'), ('libdwarfp.so.', 'producerSha256')]:
            if export[field] not in [value for name, value in inventory.items()
                    if name.startswith('os/linux_x86_64/' + library)]:
                raise ValueError('call-site export native library differs from installed package')
    if exports[1]['rebaseDelta'] - exports[0]['rebaseDelta'] != 0x400000:
        raise ValueError('call-site coverage lacks the rebased export')
    prerequisites = evidence.get('prerequisites', {})
    for name, status in [('compiler', 'PASS_COMPILER_REFERENCE'), ('structural', 'PASS_RECOVERED_PLAN_STRUCTURAL'),
            ('runtime', 'PASS_RECOVERED_RUNTIME')]:
        prerequisite = prerequisites.get(name, {})
        if (prerequisite.get('status') != status or prerequisite.get('target') != 'x86_64'
                or prerequisite.get('role') != role):
            raise ValueError('call-site coverage lacks matching prerequisite evidence')
    structural, compiler, recovered = (prerequisites[name] for name in ('structural', 'compiler', 'runtime'))
    if (structural.get('inputSha256') != evidence['inputSha256']
            or structural.get('savedProgramSha256') != saved or recovered.get('failures') != []):
        raise ValueError('call-site prerequisites refer to a different input or project')
    protected = compiler.get('preservedSha256', {})
    if (not isinstance(protected, dict) or not hashes(list(protected.values()))
            or [value for name, value in protected.items() if Path(name).name == 'input'] != [evidence['inputSha256']]):
        raise ValueError('call-site compiler reference is not bound to the exported input')
    compiler_runtime(compiler.get('runtime'), role)
    runtime(recovered.get('sessions'), 'variant')
    runtime(evidence.get('sessions'), 'view')
    return role


def cohort(cases):
    if len(cases) != 2 or set(cases) != {'exec', 'pie'}:
        raise ValueError('call-site coverage requires both existing ELF roles')
