"""Assertions executed inside actual debuggers against production companions."""
import os


EXPECTED = {
    'forge_flags': 'FORGE_READ=FORGE_READ_ALIAS | unknown=0x4 (raw: 5 / 0x00000005)',
    'forge_zero': 'FORGE_NONE (raw: 0 / 0x00000000)',
    'forge_combined': 'FORGE_READ=FORGE_READ_ALIAS | FORGE_WRITE | FORGE_BOTH (raw: 3 / 0x00000003)',
    'forge_high': 'FORGE_READ=FORGE_READ_ALIAS | FORGE_HIGH (raw: 2147483649 / 0x80000001)',
    'forge_signed8': 'SIGNED8_LOW | SIGNED8_HIGH (raw: -127 / 0x81)',
    'forge_unsigned16': 'UNSIGNED16_LOW | UNSIGNED16_HIGH | unknown=0x4 (raw: 32773 / 0x8005)',
    'forge_unsigned64': 'UNSIGNED64_LOW | UNSIGNED64_HIGH | unknown=0x8000000000000004 (raw: 13835058055282163717 / 0xc000000000000005)',
    'forge_signed64': 'SIGNED64_LOW | SIGNED64_HIGH (raw: -9223372036854775807 / 0x8000000000000001)',
}


def stale_bytes(fmt, register, displayed):
    """Only called on the harness-owned sidecar, never an analyst's file."""
    path = fmt.MANIFEST['sidecar']['path']
    length = os.stat(path).st_size
    try:
        with open(path, 'ab') as stream:
            stream.write(b'formatter stale-generation negative control')
        assert not fmt._unchanged()
        assert displayed() is None, 'a stale formatter still displays recovered names'
        try:
            register()
        except ValueError as error:
            assert 'stale or mismatched' in str(error), error
        else:
            raise AssertionError('stale companion registered')
    finally:
        with open(path, 'r+b') as stream:
            stream.truncate(length)
    register()
    assert displayed() == EXPECTED['forge_flags']


def check_label(summary):
    assert summary is not None and 'raw: 16 / 0x00000010' in summary, summary
    assert '\\n' in summary and '\\u03bb' in summary and '\\u001b' in summary, summary
    assert '\n' not in summary and '\x1b' not in summary, summary
    assert "raise RuntimeError('analyst text executed')" in summary, summary


def gdb_checks(reference):
    import gdb
    registry = gdb._forge_formatters
    assert len(registry) == 1
    fmt = next(iter(registry.values()))
    fmt.register_gdb()
    assert len(registry) == 1 and fmt._gdb_owner.pretty_printers.count(fmt._gdb_lookup) == 1
    for name, expected in EXPECTED.items():
        value = gdb.parse_and_eval(name)
        printer = gdb.default_visualizer(value)
        assert printer is not None and printer.to_string() == expected, (name, printer.to_string())
    check_label(gdb.default_visualizer(gdb.parse_and_eval('forge_text')).to_string())
    choice = gdb.default_visualizer(gdb.parse_and_eval('forge_choice'))
    assert choice is not None and choice.to_string() == '{selected=7}'
    assert gdb.default_visualizer(gdb.parse_and_eval('forge_other_choice')) is None
    assert gdb.default_visualizer(gdb.parse_and_eval('forge_ambiguous')) is None
    assert gdb.default_visualizer(gdb.parse_and_eval('forge_other_ambiguous')) is None
    node = gdb.parse_and_eval('forge_node')
    children = list(gdb.default_visualizer(node).children())
    assert [name for name, _ in children] == ['a', 'b', 'value', 'next', 'unreadable']
    assert [int(value) for _, value in children[:3]] == [5, 17, 42]
    assert int(node['next']) == int(node.address)
    envelope = gdb.parse_and_eval('forge_envelope')
    assert len(list(gdb.default_visualizer(envelope).children())) == 3
    assert int(envelope['octets'][11]) == 11, 'summary clipping hid a native array element'
    unreadable_summary = fmt._summary(fmt._GdbView(gdb.parse_and_eval('*(struct ForgeNode *)1')))
    assert '<unavailable>' in unreadable_summary, unreadable_summary
    bound_flags = gdb.parse_and_eval('forge_flags')
    def displayed():
        printer = gdb.default_visualizer(bound_flags)
        return printer.to_string() if printer is not None else None
    stale_bytes(fmt, fmt.register_gdb, displayed)
    # A second symbol module contains the same enum/struct names. Matching must
    # check objfile identity even when GDB equates the two type definitions.
    import json
    # The only required runtime stop is complete. Adding another definition of
    # the marker must not ask GDB to relocate a live PIE breakpoint ambiguously.
    gdb.execute('delete breakpoints')
    gdb.execute('add-symbol-file ' + json.dumps(reference, ensure_ascii=False))
    others = [obj for obj in gdb.objfiles() if fmt._same_path(obj.filename, reference)]
    assert len(others) == 1
    other = fmt._gdb_type(others[0], 'forge_flags_witness')
    assert fmt._gdb_lookup(gdb.Value(5).cast(other)) is None
    assert displayed() == EXPECTED['forge_flags']
    print('formatter-gdb-controls=PASS')


def lldb_checks(debugger, reference):
    import lldb
    registry = lldb._forge_formatters[debugger.GetID()]
    assert len(registry) == 1
    fmt = next(iter(registry.values()))
    fmt.register_lldb(debugger)
    assert len(registry) == 1
    target = debugger.GetSelectedTarget()
    for name, expected in EXPECTED.items():
        value = target.FindFirstGlobalVariable(name)
        assert value.IsValid() and value.GetSummary() == expected, (name, value.GetSummary())
    check_label(target.FindFirstGlobalVariable('forge_text').GetSummary())
    assert target.FindFirstGlobalVariable('forge_choice').GetSummary() == '{selected=7}'
    assert target.FindFirstGlobalVariable('forge_other_choice').GetSummary() is None
    assert target.FindFirstGlobalVariable('forge_ambiguous').GetSummary() is None
    assert target.FindFirstGlobalVariable('forge_other_ambiguous').GetSummary() is None
    node = target.FindFirstGlobalVariable('forge_node').GetNonSyntheticValue()
    assert node.GetNumChildren() == 5
    assert [node.GetChildAtIndex(i).GetValueAsUnsigned() for i in range(3)] == [5, 17, 42]
    assert node.GetChildMemberWithName('next').GetValueAsUnsigned() == node.GetLoadAddress()
    envelope = target.FindFirstGlobalVariable('forge_envelope')
    assert envelope.GetNumChildren() == 3
    assert envelope.GetChildMemberWithName('octets').GetChildAtIndex(11).GetValueAsUnsigned() == 11
    unreadable = node.GetChildMemberWithName('unreadable').Dereference()
    unreadable_summary = fmt._summary(fmt._LldbView(unreadable))
    assert '<unavailable>' in unreadable_summary, unreadable_summary
    def displayed():
        return target.FindFirstGlobalVariable('forge_flags').GetSummary()
    stale_bytes(fmt, lambda: fmt.register_lldb(debugger), displayed)
    # A separate target's compiler type must not match this module's callback.
    other = debugger.CreateTarget(reference)
    typed = other.FindFirstType('forge_flags_witness').GetCanonicalType().GetUnqualifiedType()
    assert typed.IsValid()
    assert not fmt.lldb_matches(typed, {})
    value = other.FindFirstGlobalVariable('forge_flags')
    assert value.IsValid() and fmt.lldb_summary(value, {}) is None
    debugger.SetSelectedTarget(target)
    assert displayed() == EXPECTED['forge_flags']
    print('formatter-lldb-controls=PASS')
