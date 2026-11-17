"""Require complete actual-Windows privilege readback failure, preservation and cleanup evidence."""
CASES = (
    'sizing-success',
    'sizing-error',
    'sizing-short',
    'sizing-large',
    'sizing-negative',
    'read-error',
    'returned-short',
    'returned-large',
    'returned-negative',
    'count-negative',
    'count-excess',
    'duplicate-privilege',
    'missing-privilege',
)


def oracle(record, evidence):
    if (record.get('suite') != 'windows-host-primitives' or record.get('layer') != 'windows'
            or record.get('host') != 'nt' or evidence.get('status') != 'PASS_NATIVE_WINDOWS_HOST_PRIMITIVES'):
        raise ValueError('privilege readback failures require actual Windows host probes')
    result = evidence.get('privilegeReadback')
    if not isinstance(result, dict):
        raise ValueError('Windows privilege readback coverage lacks complete controlled failures')
    rows = result.get('cases')
    if (result.get('status') != 'PASS_WINDOWS_PRIVILEGE_READBACK_FAILURES' or not isinstance(rows, list)
            or any(not isinstance(row, dict) for row in rows)
            or [row.get('name') for row in rows] != list(CASES)):
        raise ValueError('Windows privilege readback coverage lacks complete controlled failures')
    for row in rows:
        if (type(row.get('faultHits')) is not int or row['faultHits'] != 1
                or any(row.get(key) is not True
                       for key in ('tokenUnchanged', 'retryPassed', 'scopeRestored'))
                or not isinstance(row.get('diagnostic'), str) or not row['diagnostic'].strip()):
            raise ValueError('Windows privilege readback fault lacks cleanup, preservation or retry evidence')
    if (any(type(result.get(key)) is not int or result[key] <= 0 for key in ('handlesBefore', 'handlesAfter'))
            or result['handlesBefore'] != result['handlesAfter']):
        raise ValueError('Windows privilege readback faults lack stable process handle count')
    sessions = record.get('sessions')
    if (not isinstance(sessions, list) or any(not isinstance(row, dict) for row in sessions)
            or len([row for row in sessions if row.get('label') == 'privilege'
                    and row.get('status') == 'ORACLE_PASSED']) != 1):
        raise ValueError('Windows privilege readback failures lack their completed isolated session')
