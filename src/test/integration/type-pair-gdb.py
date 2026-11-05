"""Check the debugger consequences of actual resolved/opaque/unattached type exports."""
import os

import gdb

phase = os.environ['FORGE_TYPE_PAIR_PHASE']
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('info functions observed')
gdb.Breakpoint('*observed', temporary=True)
gdb.execute('run')
if phase == 'unattached':
    for name in ('x', 'payload_a', 'payload_b'):
        assert gdb.lookup_symbol(name)[0] is None, name
else:
    gdb.execute('list observed')
    resolved = 'payload_a' if phase == 'before' else 'payload_b'
    opaque = 'payload_b' if phase == 'before' else 'payload_a'
    symbol = gdb.lookup_symbol(resolved)[0]
    assert symbol is not None and symbol.type.code == gdb.TYPE_CODE_STRUCT
    assert symbol.type.sizeof == 8
    fields = symbol.type.fields()
    assert len(fields) == 1 and fields[0].name == 'value' and fields[0].bitpos == 0
    assert fields[0].type.sizeof == 8
    opaque_symbol = gdb.lookup_symbol(opaque)[0]
    assert opaque_symbol is not None and opaque_symbol.type.code != gdb.TYPE_CODE_STRUCT
    # GDB may display DW_TAG_unspecified_type as an integer fallback. Raw DIE
    # inspection proves opacity; this check only proves no invented member access.
    for name in (resolved, opaque):
        gdb.execute('ptype ' + name)
        gdb.execute('print ' + name)
        assert gdb.parse_and_eval(name).is_optimized_out, name
    try:
        gdb.parse_and_eval(opaque + '.value')
    except gdb.error:
        pass
    else:
        raise AssertionError('opaque payload unexpectedly exposes a recovered member')
gdb.execute('continue')
assert exits == [0], exits
print('type-pair-gdb=PASS phase=' + phase)
