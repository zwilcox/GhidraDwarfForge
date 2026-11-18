"""Require complete actual-Windows directory failure, preservation and cleanup evidence."""
CASES = (
    ('open-error', 0), ('open-null', 0), ('disk-type', 1), ('tag-error', 1), ('id-error', 1),
    ('non-directory', 1), ('reparse-attribute', 1), ('reparse-tag', 1), ('volume-error', 1),
    ('filesystem-empty', 1), ('filesystem-unterminated', 1), ('filesystem-invalid-utf16', 1),
    ('maximum-zero', 1), ('maximum-large', 1), ('maximum-unsigned', 1), ('path-query-error', 1),
    ('path-capacity-small', 1), ('path-capacity-large', 1), ('path-capacity-unsigned', 1),
    ('path-read-error', 1), ('path-length-short', 1), ('path-length-capacity', 1),
    ('path-length-unsigned', 1), ('path-terminator', 1), ('path-embedded-null', 1),
    ('path-prefix', 1), ('path-brace', 1), ('path-slash', 1), ('path-guid', 1),
    ('path-invalid-utf16', 1), ('drive-low', 1), ('drive-high', 1), ('root-open-error', 1),
    ('root-disk-type', 2), ('root-tag-error', 2), ('root-id-error', 2), ('root-non-directory', 2),
    ('root-reparse-attribute', 2), ('root-reparse-tag', 2), ('root-identity', 2),
    ('identity-1', 2), ('identity-2', 4), ('identity-3', 6), ('identity-4', 7), ('identity-5', 9),
    ('flush-error', 6), ('close-error-after-release', 2))


def oracle(record, evidence):
    if (record.get('suite') != 'windows-host-primitives' or record.get('layer') != 'windows'
            or record.get('host') != 'nt' or evidence.get('status') != 'PASS_NATIVE_WINDOWS_HOST_PRIMITIVES'):
        raise ValueError('directory failures require actual Windows host probes')
    result = evidence.get('directoryFailures')
    if not isinstance(result, dict):
        raise ValueError('Windows directory coverage lacks complete controlled failures')
    rows = result.get('cases')
    if (result.get('status') != 'PASS_CONTROLLED_WINDOWS_DIRECTORY_FAILURES' or not isinstance(rows, list)
            or any(not isinstance(row, dict) for row in rows)
            or [row.get('name') for row in rows] != [name for name, _ in CASES]):
        raise ValueError('Windows directory coverage lacks complete controlled failures')
    for row, (_, opens) in zip(rows, CASES):
        if (any(type(row.get(key)) is not int or row[key] != count
                for key, count in (('faultHits', 1), ('opened', opens), ('closed', opens)))
                or any(row.get(key) is not True
                       for key in ('directoryUnchanged', 'sentinelUnchanged', 'retryPassed'))
                or not isinstance(row.get('diagnostic'), str) or not row['diagnostic'].strip()):
            raise ValueError('Windows directory fault lacks cleanup, preservation or retry evidence')
    if (any(type(result.get(key)) is not int or result[key] <= 0 for key in ('handlesBefore', 'handlesAfter'))
            or result['handlesBefore'] != result['handlesAfter']):
        raise ValueError('Windows directory faults lack stable process handle count')
    sessions = record.get('sessions')
    if (not isinstance(sessions, list) or any(not isinstance(row, dict) for row in sessions)
            or len([row for row in sessions if row.get('label') == 'controlled-directory-failures'
                    and row.get('status') == 'ORACLE_PASSED']) != 1):
        raise ValueError('Windows directory failures lack their completed isolated session')
