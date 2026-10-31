"""Actual argument/return transfer and rejection-before-execution, with integer controls."""
import gdb
import json
import os
from pathlib import Path

case = Path(os.environ['MIPS_CALL_CASE'])
variant = os.environ['MIPS_CALL_VARIANT']
metadata = json.loads((case / 'metadata.json').read_text())
profile, scalar = metadata['profile'], metadata['scalar']
gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('set auto-solib-add off')
exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
gdb.execute('break marker')
gdb.execute('continue')

def state():
    return {'a': float(gdb.parse_and_eval('seen_a')), 'b': float(gdb.parse_and_eval('seen_b')),
        'floatingCalls': int(gdb.parse_and_eval('floating_calls')), 'integerCalls': int(gdb.parse_and_eval('integer_calls')),
        'integer': int(gdb.parse_and_eval('seen_integer')), 'pc': int(gdb.parse_and_eval('$pc')),
        'sr': int(gdb.parse_and_eval('$sr'))}

before = state()
assert before['a'] == 21.5 and before['b'] == -9.25 and before['floatingCalls'] == before['integerCalls'] == 1
assert before['integer'] == 5
integer_return = int(gdb.parse_and_eval('integer_call(19)'))
assert integer_return == 26
integer_after = state()
assert integer_after == {**before, 'integer': 19, 'integerCalls': 2}
ptype = gdb.execute('ptype fp_call', to_string=True)
signature = gdb.parse_and_eval('fp_call').type
expected_size = 4 if scalar == 'float' else 8
assert signature.target().strip_typedefs().code == gdb.TYPE_CODE_FLT
assert signature.target().sizeof == expected_size
assert len(signature.fields()) == 2
assert all(field.type.strip_typedefs().code == gdb.TYPE_CODE_FLT and field.type.sizeof == expected_size
    for field in signature.fields())
listing = gdb.execute('list fp_call', to_string=True)
assert 'fp_call' in listing and ('seen_a' in listing or 'a' in listing)
entry = int(gdb.parse_and_eval('(void *)&fp_call'))
bias = entry - metadata['symbols']['fp_call']
if metadata['role'] != 'exec':
    assert bias != 0
result = {'variant': variant, 'before': before, 'integerReturn': integer_return, 'integerAfter': integer_after,
    'ptype': ptype, 'listing': listing, 'entry': entry, 'bias': bias}
try:
    result['returned'] = float(gdb.parse_and_eval('fp_call(19.5, -3.25)'))
except gdb.error as error:
    result['error'] = str(error)
result['after'] = state()
if variant == 'fixed' and profile == 'fpxx':
    assert 'does not follow the target calling convention' in result.get('error', '')
    assert result['after'] == integer_after
elif profile == 'fp32':
    assert result.get('returned') == 16.25 and result['after'] == {
        **integer_after, 'a': 19.5, 'b': -3.25, 'floatingCalls': 2}
else:
    # A compiler reference can expose the same debugger transport defect. Do not
    # require every debugger version to reproduce it; record correctness separately.
    assert 'error' not in result and result['after']['floatingCalls'] == 2
    result['floatingTransferCorrect'] = result.get('returned') == 16.25 and result['after']['a'] == 19.5 and result['after']['b'] == -3.25
    print('compiler-or-previous-fpxx-transfer=' + str(result['floatingTransferCorrect']))
gdb.execute('continue')
assert exits == [0], exits
result['exitCodes'] = exits
result['status'] = 'PASS'
(case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')
print('mips-floating-call-gdb=' + variant + ' PASS')
