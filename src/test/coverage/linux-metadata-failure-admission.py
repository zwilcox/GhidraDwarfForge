"""Require the controlled libc failures in addition to real-file metadata oracles."""
CASES = (
    'open-error', 'stat-error', 'opened-stat-error', 'list-error', 'get-error',
    'flags-error', 'extended-error', 'close-error-after-release', 'missing-stat-fields',
    'nonregular-stat', 'negative-size', 'negative-mtime-nanos', 'excess-mtime-nanos',
    'negative-ctime-nanos', 'excess-ctime-nanos', 'opened-identity-change',
    'observed-identity-change', 'path-identity-change', 'inode-policy-change',
    'reserved-inode-field', 'excess-list-size', 'empty-attribute-name',
    'unterminated-attribute-name', 'long-attribute-name', 'duplicate-attribute-name',
    'excess-value-size', 'excess-attribute-count', 'excess-attribute-bytes')


def oracle(record, evidence):
    if (record.get('suite') != 'linux-file-metadata' or record.get('layer') != 'native-java'
            or record.get('host') != 'posix' or evidence.get('status') != 'PASS'
            or not isinstance(evidence.get('observations'), list) or not evidence['observations']):
        raise ValueError('metadata failures require the real Linux native-Java metadata suite')
    result = evidence.get('controlledFailures', {})
    if not isinstance(result, dict):
        raise ValueError('metadata coverage lacks the complete controlled failure cases')
    rows = result.get('cases', [])
    if (result.get('status') != 'PASS_CONTROLLED_LIBC_FAILURES' or not isinstance(rows, list)
            or any(not isinstance(row, dict) for row in rows)
            or [row.get('name') for row in rows] != list(CASES)):
        raise ValueError('metadata coverage lacks the complete controlled failure cases')
    for row in rows:
        opened = 0 if row['name'] in ('open-error', 'stat-error') else 1
        if (type(row.get('faultHits')) is not int or row['faultHits'] != 1
                or type(row.get('opened')) is not int or row['opened'] != opened
                or type(row.get('closed')) is not int or row['closed'] != opened
                or row.get('sourceUnchanged') is not True
                or not isinstance(row.get('diagnostic'), str) or not row['diagnostic'].strip()):
            raise ValueError('metadata fault was not reached, released or preservation-checked')
    sessions = [row for row in record.get('sessions', []) if row.get('label') == 'controlled-native-failures']
    if (len(sessions) != 1 or sessions[0].get('status') != 'ORACLE_PASSED'
            or record.get('unmeasuredForcedHalts') or record.get('launcherInvocations')):
        raise ValueError('metadata failures lack one completed isolated process')
