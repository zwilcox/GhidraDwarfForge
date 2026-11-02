#!/usr/bin/env python3
"""Account for a compiler-corroborated missing OS handler in the deliberately non-Linux fixture."""
import json
from pathlib import Path
import sys

MISSING_FREEBSD = ('warning: A handler for the OS ABI "FreeBSD" is not built into this configuration\n'
    'of GDB.  Attempting to continue with the default aarch64 settings.\n')


def normalize(text, compiler_text, osabi):
    count, reference_count = text.count(MISSING_FREEBSD), compiler_text.count(MISSING_FREEBSD)
    if count or reference_count:
        # Both file and symbol-file cause exactly this diagnostic on GDB 15.
        # Any additional/changed warning remains subject to the shared strict gate.
        assert osabi == 9 and count == reference_count == 2, 'unmatched missing-OS-handler diagnostic'
    return text.replace(MISSING_FREEBSD, ''), count


def main():
    case, variant = Path(sys.argv[1]), sys.argv[2]
    assert variant in ('compiler', 'fixed')
    metadata = json.loads((case / 'metadata.json').read_text())
    for filename in ('call.reference', 'call.input', 'fixed.dbg'):
        with (case / filename).open('rb') as stream:
            header = stream.read(64)
        assert header[:7] == b'\x7fELF\x02\x01\x01' and header[7] == metadata['osabi']
    text, count = normalize((case / (variant + '-gdb.log')).read_text(),
        (case / 'compiler-gdb.log').read_text(), metadata['osabi'])
    (case / (variant + '-gdb-accounted.log')).write_text(text)
    (case / (variant + '-os-handler.json')).write_text(json.dumps({
        'matchedMissingOsHandlerWarnings': count, 'osabi': metadata['osabi'],
        'nativeFreeBsdSupportClaimed': False}, indent=4) + '\n')


if __name__ == '__main__':
    main()
