"""Load recovered CFI through the actual companion, including rejected wrong bias."""
import json
from pathlib import Path
import gdb


def image_bias(original):
    header = Path(original).read_bytes()[:64]
    assert header[:4] == b'\x7fELF'
    width = {1: 4, 2: 8}[header[4]]
    order = {1: 'little', 2: 'big'}[header[5]]
    entry = int.from_bytes(header[24:24 + width], order)
    rows = gdb.execute('info auxv', to_string=True).splitlines()
    entries = [int(row.split()[-1], 0) for row in rows if 'AT_ENTRY' in row.split()]
    assert len(entries) == 1
    return entries[0] - entry


def load_companion(symbols, bias):
    companion = Path(str(symbols) + '.gdb.py')
    evidence = json.loads(Path(str(symbols) + '.unwind.json').read_text())
    assert evidence['hasPlan']
    gdb.execute('source ' + str(companion))
    original_objects = list(gdb.objfiles())
    automatic = False
    try:
        gdb.execute('forge-load')
    except gdb.error as error:
        assert 'mappings unavailable' in str(error), str(error)
        assert list(gdb.objfiles()) == original_objects
    else:
        automatic = True
        state, = gdb._forge_loader_registry_v1.loaded.values()
        assert state['bias'] == bias
        gdb.execute('forge-unload')
        assert list(gdb.objfiles()) == original_objects
    try:
        gdb.execute('forge-load --bias ' + hex(bias + 1))
    except gdb.error as error:
        assert any(word in str(error) for word in ('mismatch', 'contradicts', 'unreadable')), str(error)
    else:
        raise AssertionError('companion accepted a wrong runtime bias')
    assert list(gdb.objfiles()) == original_objects
    gdb.execute('forge-load --bias ' + hex(bias))
    state, = gdb._forge_loader_registry_v1.loaded.values()
    assert state['bias'] == bias
    gdb.write('unwind-companion=PASS automatic=' + str(automatic) + ' bias=' + hex(bias) + '\n')
