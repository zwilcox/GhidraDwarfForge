"""Observe GDB class/object lookup without treating synthetic layouts as acceptance."""
import json
import os
from pathlib import Path
import gdb

queries = ["show language", "info functions inspect_scope", "ptype 'recovered::Counter'",
    "ptype Counter", "ptype struct Counter", "ptype struct 'recovered::Counter'",
    "ptype 'recovered::Counter::inspect_scope'", "ptype inspect_scope",
    "info address 'recovered::Counter::inspect_scope'", "info address inspect_scope"]
observations = {}
for command in queries:
    try:
        observations[command] = {'result': gdb.execute(command, to_string=True)}
    except gdb.error as error:
        observations[command] = {'error': str(error)}
remote = os.environ.get('CLASS_LAYOUT_REMOTE', '')
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*' + os.environ['CLASS_LAYOUT_STOP'], temporary=True)
gdb.execute('continue' if remote else 'run')
if os.environ['CLASS_LAYOUT_VARIANT'] != 'compiler':
    assert gdb.execute('show language', to_string=True).strip() == 'The current source language is "auto; currently c".'
for command in ["show language", "info args", "bt 1", "print this", "print this->value", "print amount",
        "print first_object.member", "print second_object.other", "ptype 'recovered::Counter'",
        "break 'recovered::Counter::inspect_scope'"]:
    try:
        observations['stopped: ' + command] = {'result': gdb.execute(command, to_string=True)}
    except gdb.error as error:
        observations['stopped: ' + command] = {'error': str(error)}
assert int(gdb.parse_and_eval('this->value')) == 7
assert int(gdb.parse_and_eval('amount')) == 3
assert int(gdb.parse_and_eval('first_object.member')) == 5
assert int(gdb.parse_and_eval('second_object.other')) == 9
variant = os.environ['CLASS_LAYOUT_VARIANT']
qualified = "ptype 'recovered::Counter::inspect_scope'"
breakpoint_query = "stopped: break 'recovered::Counter::inspect_scope'"
if variant in ('c11', 'c11-no-linkage'):
    assert 'error' in observations[qualified]
    assert 'not defined' in observations[breakpoint_query]['result']
else:
    assert 'error' not in observations[qualified]
    assert 'Breakpoint ' in observations[breakpoint_query]['result']
    assert 'not defined' not in observations[breakpoint_query]['result']
if variant in ('c11-root-display', 'c11-root-and-class-display'):
    type_query = 'ptype struct Counter' if variant == 'c11-root-display' else "ptype struct 'recovered::Counter'"
    class_text = observations[type_query]['result']
    assert 'int value;' in class_text and 'int inspect_scope(int);' in class_text
    assert 'recovered::Counter::inspect_scope' not in class_text
    assert 'error' in observations['ptype inspect_scope']
    absent = "ptype struct 'recovered::Counter'" if variant == 'c11-root-display' else 'ptype struct Counter'
    assert 'error' in observations[absent]
for breakpoint in gdb.breakpoints():
    breakpoint.delete()
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
Path(os.environ['CLASS_LAYOUT_OUT']).write_text(json.dumps(observations, indent=4) + '\n')
print('class-layout-probe=PASS')
