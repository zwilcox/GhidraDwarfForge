"""Actual packed/ordinary bitfield values and layouts at inspect_flags."""
import json
import os
from pathlib import Path
import lldb


target = lldb.debugger.GetSelectedTarget()
process = target.GetProcess()
assert process.GetState() == lldb.eStateStopped
assert process.GetSelectedThread().GetFrameAtIndex(0).GetFunctionName() == 'inspect_flags'
observations = []
for name, size in [('word_value', 4), ('byte_value', 1)]:
    value = target.FindFirstGlobalVariable(name)
    assert value.IsValid() and value.GetByteSize() == size
    dtype = value.GetType().GetUnqualifiedType()
    assert dtype.GetNumberOfFields() == 2
    fields = []
    for index, (member, expected, bits, offset) in enumerate([('a', 5, 3, 0), ('b', 17, 5, 3)]):
        field = dtype.GetFieldAtIndex(index)
        assert field.GetName() == member and field.GetBitfieldSizeInBits() == bits
        assert field.GetOffsetInBits() == offset
        child = value.GetChildMemberWithName(member)
        error = lldb.SBError()
        actual = child.GetValueAsUnsigned(error)
        assert child.IsValid() and error.Success() and actual == expected, (name, member, str(error), actual)
        fields.append({'name': member, 'value': actual, 'bits': bits, 'offset': offset})
    observations.append({'name': name, 'size': size, 'fields': fields})
Path(os.environ['FORGE_LLDB_OBSERVATION']).write_text(json.dumps(observations, indent=4) + '\n')
print('FORGE_LLDB_BITFIELDS_PASS')
