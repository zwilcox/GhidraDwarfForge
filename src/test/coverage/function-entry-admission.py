"""Admission for real function-entry exports; receipt tests do not prove execution."""
import re


LABELS = [role + '-' + name for role in ('exec', 'pie') for name in ('baseline', 'rebased', 'repeat')]
RECEIPTS = {'result.txt', 'gdb.txt', 'headless.txt', 'header.txt', 'sections.txt', 'notes.txt',
    'info.txt', 'abbrev.txt', 'aranges.txt', 'decodedline.txt', 'Ranges.txt', 'loc.txt',
    'llvm.txt', 'dwarfdump.txt', 'dwarfdump.txt.check.json', 'address-index.json'}


def sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def oracle(record, evidence):
    suite = record.get('suite')
    aliases = suite == 'function-entry-alias-export'
    cases = evidence.get('cases')
    protected = evidence.get('protected')
    if (suite not in ('function-entry-export', 'function-entry-alias-export')
            or record.get('layer') != 'headless' or record.get('host') != 'posix'
            or [row.get('label') for row in record.get('sessions', [])] != LABELS
            or evidence.get('status') != 'PASS_FUNCTION_ENTRY_MEASUREMENT' or evidence.get('target') != 'x86_64'
            or evidence.get('aliases') is not aliases
            or evidence.get('productionJarSha256') != record.get('productionJarSha256')
            or not sha(evidence.get('productionJarSha256')) or not sha(evidence.get('oracleLogSha256'))
            or evidence.get('validators') != ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer']
            or not isinstance(protected, dict) or len(protected) < 18
            or not all(sha(value) for value in protected.values())
            or not isinstance(cases, list) or len(cases) != 6
            or any(not isinstance(case, dict) for case in cases)
            or [case.get('label') for case in cases] != LABELS):
        raise ValueError('entry coverage requires six measured Linux exports and complete native/GDB evidence')
    for index, case in enumerate(cases):
        hashes = case.get('receipts')
        if (type(case.get('rebaseDelta')) is not int or case['rebaseDelta'] != (0x2000000 if index % 3 == 1 else 0)
                or case.get('checks') != ['static-entry-ranges-and-gap=PASS',
                    'true-entry-breakpoints-backward-bodies-values-stepping=PASS']
                or case.get('strictStatus') != 'PASS' or type(case.get('uncorroboratedErrors')) is not int
                or case['uncorroboratedErrors'] != 0
                or not all(sha(case.get(key)) for key in ('inputSha256', 'sidecarSha256', 'sourceSha256'))
                or (not sha(case.get('aliasSha256')) if aliases else case.get('aliasSha256') is not None)
                or not isinstance(hashes, dict) or set(hashes) != RECEIPTS
                or not all(sha(value) for value in hashes.values())):
            raise ValueError('entry case omits required range, alias, validator or debugger checks')
    for offset in (0, 3):
        if (any(cases[offset][key] != cases[offset + 2][key]
                for key in ('inputSha256', 'sidecarSha256', 'sourceSha256'))
                or cases[offset]['inputSha256'] != cases[offset + 1]['inputSha256']):
            raise ValueError('entry rerun or rebase original is inconsistent')
