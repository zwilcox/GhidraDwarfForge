"""Require complete actual-Windows security failure, preservation and cleanup evidence."""
CASES = (
    ('sizing-success', 1),
    ('sizing-error', 1),
    ('capacity-small', 1),
    ('capacity-large', 1),
    ('capacity-unsigned', 1),
    ('read-error', 1),
    ('returned-small', 1),
    ('returned-large', 1),
    ('returned-unsigned', 1),
    ('descriptor-invalid', 1),
    ('length-small', 1),
    ('length-large', 1),
    ('control-error', 1),
    ('revision', 1),
    ('absolute', 1),
    ('sacl-error', 1),
    ('sacl-presence', 1),
    ('readback-change', 2),
)


def oracle(record, evidence):
    if (record.get('suite') != 'windows-host-primitives' or record.get('layer') != 'windows'
            or record.get('host') != 'nt' or evidence.get('status') != 'PASS_NATIVE_WINDOWS_HOST_PRIMITIVES'):
        raise ValueError('security failures require actual Windows host probes')
    result = evidence.get('securityFailures')
    if not isinstance(result, dict):
        raise ValueError('Windows security coverage lacks complete controlled failures')
    rows = result.get('cases')
    if (result.get('status') != 'PASS_CONTROLLED_WINDOWS_SECURITY_FAILURES' or not isinstance(rows, list)
            or any(not isinstance(row, dict) for row in rows)
            or [row.get('name') for row in rows] != [name for name, _ in CASES]):
        raise ValueError('Windows security coverage lacks complete controlled failures')
    for row, (_, opens) in zip(rows, CASES):
        if (any(type(row.get(key)) is not int or row[key] != count
                for key, count in (('faultHits', 1), ('opened', opens), ('closed', opens)))
                or any(row.get(key) is not True
                       for key in ('sourceUnchanged', 'retryPassed'))
                or not isinstance(row.get('diagnostic'), str) or not row['diagnostic'].strip()):
            raise ValueError('Windows security fault lacks cleanup, preservation or retry evidence')
    if (any(type(result.get(key)) is not int or result[key] <= 0 for key in ('handlesBefore', 'handlesAfter'))
            or result['handlesBefore'] != result['handlesAfter']):
        raise ValueError('Windows security faults lack stable process handle count')
    sessions = record.get('sessions')
    if (not isinstance(sessions, list) or any(not isinstance(row, dict) for row in sessions)
            or len([row for row in sessions if row.get('label') == 'controlled-security-failures'
                    and row.get('status') == 'ORACLE_PASSED']) != 1):
        raise ValueError('Windows security failures lack their completed isolated session')
