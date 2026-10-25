"""Unlocated declaration metadata must not invent executable symbols."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['DECL_CASE'])
variant = os.environ['DECL_VARIANT']
assert variant in ('compiler', 'forge')
model = json.loads((case / 'model.json').read_text())
result = {'status': 'STARTED', 'variant': variant, 'exitCodes': []}
gdb.events.exited.connect(lambda event: result['exitCodes'].append(getattr(event, 'exit_code', None)))
try:
    name = 'main' if variant == 'compiler' else 'recovered_main'
    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)
    assert symbol is not None and symbol.type.code == gdb.TYPE_CODE_FUNC and symbol.type.target().sizeof == 4
    source = Path(os.environ['DECL_SOURCE']) if variant == 'compiler' else case / 'decl.dbg.c'
    assert Path(symbol.symtab.fullname()).resolve() == source.resolve()
    result['prototype'] = gdb.execute('ptype ' + name, to_string=True)
    result['source'] = gdb.execute('list ' + name, to_string=True)
    # GDB ignores DW_AT_declaration even in the independent compiler oracle.
    names = ['imported_adjust'] if variant == 'compiler' else model['declarationNames']
    for declaration in names:
        assert gdb.lookup_global_symbol(declaration) is None and gdb.lookup_static_symbol(declaration) is None
    result['unlocatedDeclarations'] = names
    entry = gdb.Breakpoint(name)
    gdb.execute('run')
    assert model['start'] <= int(gdb.parse_and_eval('$pc')) < model['end']
    entry.delete()
    at_return = gdb.Breakpoint('*' + hex(model['mainReturn']))
    result['sourceSteps'] = ['next']
    gdb.execute('next')
    if int(gdb.parse_and_eval('$pc')) != model['mainReturn']:
        result['sourceSteps'].append('step')
        gdb.execute('step')
    if int(gdb.parse_and_eval('$pc')) != model['mainReturn']:
        gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == model['mainReturn']
    result['observed'] = int(gdb.parse_and_eval('observed_result'))
    assert result['observed'] == 12
    at_return.delete()
    gdb.execute('continue')
    assert result['exitCodes'] == [0]
    result['status'] = 'PASS'
except BaseException as error:
    result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')
