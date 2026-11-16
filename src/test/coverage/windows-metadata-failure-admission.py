"""Require actual Windows host probes and their controlled native metadata failures."""
CASES = (
    'open-error', 'open-null', 'disk-type', 'info-0-error', 'info-1-error', 'info-18-error',
    'info-9-error', 'info-7-error', 'delete-pending', 'directory', 'reparse-attribute',
    'reparse-tag', 'attribute-change', 'negative-size', 'security-error', 'descriptor-missing',
    'descriptor-invalid', 'descriptor-short', 'descriptor-long', 'control-error',
    'descriptor-revision', 'descriptor-absolute', 'owner-missing', 'owner-before',
    'owner-after', 'sid-invalid', 'sid-short', 'sid-long', 'stream-empty-name',
    'stream-odd-name', 'stream-long-name', 'stream-negative-size', 'stream-duplicate',
    'stream-unaligned', 'stream-short-next', 'stream-long-next', 'stream-excess-count',
    'stream-invalid-utf16', 'free-error-after-release', 'close-error-after-release')
NO_ALLOCATION = frozenset(CASES[:7] + CASES[8:16])
SESSIONS = frozenset(('privilege', 'host', 'transactions', 'lock', 'controlled-native-failures'))


def oracle(record, evidence):
    if (record.get('suite') != 'windows-host-primitives' or record.get('layer') != 'windows'
            or record.get('host') != 'nt' or evidence.get('status') != 'PASS_NATIVE_WINDOWS_HOST_PRIMITIVES'
            or any(type(evidence.get(key)) is not int or evidence[key] <= 0
                   for key in ('hostChecks', 'transactionChecks'))):
        raise ValueError('metadata failures require the real Windows host primitive suite')
    result = evidence.get('controlledFailures')
    if not isinstance(result, dict):
        raise ValueError('Windows metadata coverage lacks complete controlled failures')
    rows = result.get('cases')
    if (result.get('status') != 'PASS_CONTROLLED_WINDOWS_FAILURES' or not isinstance(rows, list)
            or any(not isinstance(row, dict) for row in rows)
            or [row.get('name') for row in rows] != list(CASES)):
        raise ValueError('Windows metadata coverage lacks complete controlled failures')
    for row in rows:
        opened = 0 if row['name'].startswith('open-') else 2 if row['name'] == 'close-error-after-release' else 1
        allocated = 0 if row['name'] in NO_ALLOCATION else 1
        expected = {'faultHits': 1, 'opened': opened, 'closed': opened,
            'allocated': allocated, 'freed': allocated}
        if (any(type(row.get(key)) is not int or row[key] != value for key, value in expected.items())
                or row.get('sourceUnchanged') is not True
                or not isinstance(row.get('diagnostic'), str) or not row['diagnostic'].strip()):
            raise ValueError('Windows metadata fault lacks hit, cleanup or preservation evidence')
    if (any(type(result.get(key)) is not int or result[key] <= 0 for key in ('handlesBefore', 'handlesAfter'))
            or result['handlesBefore'] != result['handlesAfter']):
        raise ValueError('Windows metadata fault lacks stable process handle count')
    sessions = record.get('sessions', [])
    if (not isinstance(sessions, list) or len(sessions) != len(SESSIONS)
            or any(not isinstance(row, dict) or row.get('status') != 'ORACLE_PASSED' for row in sessions)
            or {row.get('label') for row in sessions} != SESSIONS
            or record.get('unmeasuredForcedHalts') or record.get('launcherInvocations')):
        raise ValueError('Windows metadata failures lack the five completed isolated sessions')
    children = evidence.get('unmeasuredNestedChildren')
    if (not isinstance(children, list) or len(children) != 8
            or any(not isinstance(row, dict) or type(row.get('exitCode')) is not int or row['exitCode'] != 89
                   or not isinstance(row.get('case'), str) or not row['case'] for row in children)
            or len({row['case'] for row in children}) != 8 or evidence.get('lockContendersMeasured') is not False):
        raise ValueError('Windows host primitives must retain their nested-process disclosure')
