#!/usr/bin/env python3
"""Recognize only an exact source prefix followed by non-executable listing catalog rows."""
import hashlib
import re

HEADER = b'/* Ghidra listing comment encoding */\n'
EXPLANATION = (b'/* Payloads preserve stored text: backslash escapes encode backslashes, controls and unsafe comment delimiters. '
    b'Each displayed payload row retains its original LF as an explicit escape. '
    b'Addresses identify Ghidra spaces; catalog rows are not executable source. Authorship is unknown. */\n')
LABEL = re.compile(r'Ghidra listing comment (?:EOL|PRE|POST|PLATE|REPEATABLE) at .+:0x[0-9a-f]+ '
    r'\[(?:NON_DEFAULT_SPACE|NO_INSTRUCTION|OUTSIDE_EXPORTED_FUNCTION|INSTRUCTION_OUTSIDE_BODY|'
    r'NO_TOKEN_LINE|AMBIGUOUS_TOKEN_LINES|UNTRANSLATABLE_ADDRESS)\]')


def compare(baseline, candidate):
    baseline_hash = hashlib.sha256(baseline).hexdigest()
    if baseline == candidate:
        return {'relation': 'IDENTICAL', 'baselineSourceSha256': baseline_hash, 'catalogBytes': 0, 'catalogRecords': 0}
    assert baseline.endswith(b'\n') and candidate.startswith(baseline), 'non-catalog source bytes changed'
    suffix = candidate[len(baseline):]
    assert suffix.startswith(HEADER + EXPLANATION), 'unrecognized source suffix'
    text = suffix[len(HEADER + EXPLANATION):].decode('utf-8', errors='strict')
    assert text and text.endswith('\n') and '\r' not in text, 'incomplete catalog'
    rows = text.splitlines(keepends=True)
    records, payloads = 0, 0
    for row in rows:
        assert row.startswith('/* ') and row.endswith(' */\n'), 'non-comment catalog row'
        payload = row[3:-4]
        assert not any(token in payload for token in ('/*', '*/', '??')), 'unsafe comment delimiters'
        assert not any(ord(char) < 32 or ord(char) == 127 for char in payload), 'unescaped control character'
        if LABEL.fullmatch(payload):
            assert records == 0 or payloads > 0, 'catalog entry lacks payload'
            records += 1
            payloads = 0
        else:
            assert records > 0, 'catalog payload lacks identity'
            payloads += 1
    assert records > 0 and payloads > 0, 'incomplete final catalog entry'
    return {'relation': 'EXACT_PREFIX_WITH_LISTING_CATALOG', 'baselineSourceSha256': baseline_hash,
        'catalogBytes': len(suffix), 'catalogRecords': records, 'catalogSha256': hashlib.sha256(suffix).hexdigest()}
