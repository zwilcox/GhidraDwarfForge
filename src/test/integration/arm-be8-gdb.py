"""Source-known scalar BE8 values; this checkpoint does not certify call/return ABI."""
import gdb
import json
import os
from pathlib import Path

root = Path(os.environ['BE8_CASE'])
variant = os.environ['BE8_VARIANT']
phase = os.environ['BE8_PHASE']
result = {'status': 'FAILED', 'observations': [], 'exits': []}
gdb.events.exited.connect(lambda event: result['exits'].append(getattr(event, 'exit_code', None)))


def integer(expression):
    return int(gdb.parse_and_eval(expression))


try:
    assert 'big endian' in gdb.execute('show endian', to_string=True)
    name = 'be8_probe' if variant == 'compiler' else 'recovered_be8_probe'
    start = integer('&' + name)
    assert start == 0x100b8
    assert integer('&be8_global') == 0x110ec
    assert name in gdb.execute('info functions ' + name, to_string=True)
    global_type = gdb.parse_and_eval('&be8_global').type.target().strip_typedefs()
    assert global_type.code == gdb.TYPE_CODE_INT and global_type.sizeof == 4
    assert int(gdb.Value(-1).cast(global_type)) == 0xffffffff
    result['globalType'] = gdb.execute('ptype be8_global', to_string=True)
    result['listing'] = gdb.execute('list ' + name, to_string=True)
    assert 'be8_global' in result['listing'] and 'No such file' not in result['listing']
    arch = gdb.selected_inferior().architecture()
    result['static'] = arch.disassemble(start, start + 51)
    assert [row['addr'] - start for row in result['static']] == list(range(0, 52, 4))
    assert all(row['length'] == 4 for row in result['static'])
    gdb.execute('target remote ' + os.environ['BE8_REMOTE'])
    bp = gdb.Breakpoint('*' + name)
    gdb.execute('continue')
    bp.delete()
    if phase == 'instructions':
        for offset in range(0, 52, 4):
            pc = integer('$pc')
            assert pc == start + offset
            assert integer('$r0') == (7 if offset < 40 else 0x1122334b)
            if offset >= 28:
                assert integer('$r2') == 0x11223344
            if offset >= 32:
                assert integer('$r3') == (7 if offset == 32 else 0x1122334b)
            assert bytes(gdb.selected_inferior().read_memory(0x110ec, 4)).hex() == '11223344'
            assert integer('be8_global') == 0x11223344
            assert not integer('$cpsr') & 32
            row = {'offset': offset, 'r0': integer('$r0'),
                'codeBytes': bytes(gdb.selected_inferior().read_memory(pc, 4)).hex(),
                'instruction': arch.disassemble(pc, count=1)[0]['asm']}
            # Compiler O0 storage names the stack slot before its initialization.
            # Require its typed value only after the source-known store executes.
            # Forge must show the incoming register correctly before that store.
            if (variant == 'compiler' and 16 <= offset < 48) or (variant == 'curated' and offset < 40):
                row['value'] = integer('value')
                assert row['value'] == 7
            elif variant == 'curated':
                try:
                    row['value'] = integer('value')
                    assert row['value'] == 7
                except gdb.error as error:
                    row['unavailable'] = str(error)
                    assert 'optimized out' in str(error) or 'not available' in str(error)
            result['observations'].append(row)
            gdb.execute('stepi')
        assert integer('$pc') == 0x1009c
        assert integer('$r0') == 0x1122334b
    elif phase in ('next', 'step'):
        # Synthetic caller lines need not begin at the machine return address.
        # A common return breakpoint checks the result before caller execution.
        returned = gdb.Breakpoint('*0x1009c', temporary=True)
        for _ in range(12):
            pc = integer('$pc')
            if not start <= pc < start + 52:
                break
            sal = gdb.find_pc_line(pc)
            assert sal.symtab is not None and sal.line > 0
            result['observations'].append({'pc': pc, 'line': sal.line, 'file': sal.symtab.fullname()})
            gdb.execute(phase)
        assert result['observations'] and integer('$pc') == 0x1009c
        assert integer('$r0') == 0x1122334b
    else:
        raise AssertionError('unknown phase ' + phase)
    gdb.execute('continue')
    assert result['exits'] == [0]
    result['status'] = 'PASS_SCALAR_CHECKPOINT'
finally:
    (root / (variant + '-' + phase + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')
