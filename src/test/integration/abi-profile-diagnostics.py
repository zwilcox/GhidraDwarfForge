#!/usr/bin/env python3
"""Account for a compiler-corroborated missing OS handler in the deliberately non-Linux fixture."""
import json
from pathlib import Path
import sys

MISSING_FREEBSD = ('warning: A handler for the OS ABI "FreeBSD" is not built into this configuration\n'
    'of GDB.  Attempting to continue with the default aarch64 settings.\n')


def normalize(text, compiler_text, osabi, target='aarch64'):
    assert target in ('aarch64', 'i386')
    warning = MISSING_FREEBSD.replace('aarch64', target)
    count, reference_count = text.count(warning), compiler_text.count(warning)
    if count or reference_count:
        # Both file and symbol-file cause exactly this diagnostic on GDB 15.
        # Any additional/changed warning remains subject to the shared strict gate.
        assert osabi == 9 and count == reference_count == 2, 'unmatched missing-OS-handler diagnostic'
    return text.replace(warning, ''), count


def main():
    case, variant = Path(sys.argv[1]), sys.argv[2]
    assert variant in ('compiler', 'fixed')
    metadata = json.loads((case / 'metadata.json').read_text())
    target = metadata.get('target', 'aarch64')
    for filename in ('call.reference', 'call.input', 'fixed.dbg'):
        with (case / filename).open('rb') as stream:
            header = stream.read(64)
        expected_header = b'\x7fELF' + bytes((1 if target == 'i386' else 2, 1, 1))
        assert header[:7] == expected_header and header[7] == metadata['osabi']
    text, count = normalize((case / (variant + '-gdb.log')).read_text(),
        (case / 'compiler-gdb.log').read_text(), metadata['osabi'], target)
    (case / (variant + '-gdb-accounted.log')).write_text(text)
    (case / (variant + '-os-handler.json')).write_text(json.dumps({
        'matchedMissingOsHandlerWarnings': count, 'osabi': metadata['osabi'],
        'nativeFreeBsdSupportClaimed': False}, indent=4) + '\n')


if __name__ == '__main__':
    main()
