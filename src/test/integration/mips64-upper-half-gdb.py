"""Check recovered addresses and values while the original MIPS ELF runs on Malta."""
import os
from pathlib import Path

import gdb


case = Path(os.environ['FORGE_MIPS64_CASE'])
symbols = {}
for row in (case / 'symbols.txt').read_text().splitlines():
    address, _, name = row.split()
    symbols[name] = int(address, 16)
low, high = symbols['low_entry'], symbols['high_add']
assert low < 1 << 63 < high and high - low >= 1 << 63
original = case / 'original.elf'
gdb.execute(f'file "{original}"')
gdb.execute(f'symbol-file "{original}.dbg"')
for name, address in [('curated_low', low), ('curated_high', high), ('curated_word', symbols['high_word'])]:
    assert int(gdb.parse_and_eval('(unsigned long long)&' + name)) == address
for pc in (low, high):
    line = gdb.find_pc_line(pc)
    assert line.line > 0 and line.symtab.fullname() == str(original) + '.dbg.c'
assert gdb.find_pc_line(1 << 63).symtab is None


def register(name):
    return int(gdb.selected_frame().read_register(name)) & ((1 << 64) - 1)


gdb.execute('target remote ' + os.environ['FORGE_MIPS64_SOCKET'])
assert register('pc') == symbols['boot_case']
entry = gdb.Breakpoint('*curated_high', temporary=True)
assert entry.locations[0].address == high
gdb.execute('continue')
assert register('pc') == high and gdb.selected_frame().name() == 'curated_high'
assert [int(gdb.parse_and_eval(name)) for name in ('left', 'right')] == [19, 23]
assert [register(name) for name in ('a0', 'a1')] == [19, 23]
assert int(gdb.parse_and_eval('curated_word')) == 0
assert 'curated_high' in gdb.execute('list curated_high', to_string=True)
gdb.execute('stepi')
assert register('pc') == high + 4 and register('v0') == 42
assert gdb.selected_frame().find_sal().symtab.fullname() == str(original) + '.dbg.c'
gdb.Breakpoint('*' + hex(symbols['stop_case']), temporary=True)
gdb.execute('continue')
assert register('pc') == symbols['stop_case'] and int(gdb.parse_and_eval('curated_word')) == 42
gdb.execute('disconnect')
print('mips64-upper-half-gdb=PASS')
