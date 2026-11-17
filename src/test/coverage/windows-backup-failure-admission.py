"""Require complete actual-Windows backup failure, preservation and cleanup evidence."""
CASES = (
    ('open-error', 0),
    ('open-null', 0),
    ('read-error', 1),
    ('read-negative', 1),
    ('read-excess', 1),
    ('header-zero-kind', 1),
    ('header-negative-size', 1),
    ('header-name-large', 1),
    ('header-name-odd', 1),
    ('header-name-unsigned', 1),
    ('name-zero-count', 1),
    ('name-nul', 1),
    ('name-invalid-utf16', 1),
    ('partial-header-eof', 1),
    ('seek-error', 1),
    ('seek-low-mismatch', 1),
    ('seek-high-mismatch', 1),
    ('abort-error-after-release', 1),
    ('close-error-after-release', 1),
    ('cancel-after-header', 1),
)


def oracle(record, evidence):
    if (record.get('suite') != 'windows-host-primitives' or record.get('layer') != 'windows'
            or record.get('host') != 'nt' or evidence.get('status') != 'PASS_NATIVE_WINDOWS_HOST_PRIMITIVES'):
        raise ValueError('backup failures require actual Windows host probes')
    result = evidence.get('backupFailures')
    if not isinstance(result, dict):
        raise ValueError('Windows backup coverage lacks complete controlled failures')
    rows = result.get('cases')
    if (result.get('status') != 'PASS_CONTROLLED_WINDOWS_BACKUP_FAILURES' or not isinstance(rows, list)
            or any(not isinstance(row, dict) for row in rows)
            or [row.get('name') for row in rows] != [name for name, _ in CASES]):
        raise ValueError('Windows backup coverage lacks complete controlled failures')
    for row, (_, opens) in zip(rows, CASES):
        if (any(type(row.get(key)) is not int or row[key] != count
                for key, count in (('faultHits', 1), ('opened', opens), ('closed', opens), ('aborts', opens)))
                or any(row.get(key) is not True
                       for key in ('contextReleased', 'sourceUnchanged', 'retryPassed'))
                or not isinstance(row.get('diagnostic'), str) or not row['diagnostic'].strip()):
            raise ValueError('Windows backup fault lacks cleanup, preservation or retry evidence')
    if any(result.get(key) is not True for key in ('fragmentedReadPassed', 'emptyDataPassed', 'namedStreamObserved')):
        raise ValueError('Windows backup failures lack positive native controls')
    if (any(type(result.get(key)) is not int or result[key] <= 0 for key in ('handlesBefore', 'handlesAfter'))
            or result['handlesBefore'] != result['handlesAfter']):
        raise ValueError('Windows backup faults lack stable process handle count')
    sessions = record.get('sessions')
    if (not isinstance(sessions, list) or any(not isinstance(row, dict) for row in sessions)
            or len([row for row in sessions if row.get('label') == 'controlled-backup-failures'
                    and row.get('status') == 'ORACLE_PASSED']) != 1):
        raise ValueError('Windows backup failures lack their completed isolated session')
