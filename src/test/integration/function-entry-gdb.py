"""GDB oracle for exact function entries, body coverage and backward execution."""

import os

import gdb


labels = {}
with open(os.environ["FORGE_ENTRY_LABELS"], encoding="utf-8") as stream:
    for line in stream:
        name, address = line.split()
        labels[name] = int(address, 16)


def value(expression):
    return int(gdb.parse_and_eval(expression))


def function_at(address):
    block = gdb.block_for_pc(address)
    while block is not None:
        if block.function is not None:
            return block.function.name
        block = block.superblock
    return None


def source_at(address):
    line = gdb.find_pc_line(address)
    assert line.symtab is not None and line.line > 0, hex(address)
    assert line.symtab.filename.endswith("entry.dbg.c"), line.symtab.filename


assert value("&recovered_below") == labels["below_entry"]
assert value("&recovered_middle") == labels["middle_entry"]
for begin, end, name in [
    ("below_start", "below_end", "recovered_below"),
    ("below_entry", "below_entry_end", "recovered_below"),
    ("middle_start", "middle_end", "recovered_middle"),
]:
    for address in range(labels[begin], labels[end]):
        assert function_at(address) == name, (hex(address), function_at(address))
    source_at(labels[begin])
for address in range(labels["below_end"], labels["below_entry"]):
    assert function_at(address) is None, hex(address)
    assert gdb.find_pc_line(address).symtab is None, hex(address)
print("static-entry-ranges-and-gap=PASS")

for name in ["recovered_below", "recovered_middle"]:
    text = gdb.execute("ptype " + name, to_string=True)
    assert "int (int, int)" in text, text
    gdb.execute("list " + name)
    gdb.execute("break " + name)

exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
gdb.execute("run")
runtime_bias = value("&recovered_below") - labels["below_entry"]
assert value("$pc") == labels["below_entry"] + runtime_bias
assert value("left") == 19 and value("right") == 23
assert value("below_sink") == -1
gdb.execute("info args")
# The two real instructions compute the sum, then branch below the entry.
gdb.execute("stepi")
gdb.execute("stepi")
assert value("$pc") == labels["below_start"] + runtime_bias
assert function_at(value("$pc")) == "recovered_below"
assert value("left") == 19 and value("right") == 23
source_at(value("$pc"))
gdb.execute("next")
assert value("below_sink") == 42
gdb.execute("step")
gdb.execute("continue")
assert value("$pc") == labels["middle_entry"] + runtime_bias
assert value("left") == 17 and value("right") == 25
assert value("middle_sink") == -1
gdb.execute("info args")
gdb.execute("stepi")
gdb.execute("stepi")
assert value("$pc") == labels["middle_start"] + runtime_bias
assert function_at(value("$pc")) == "recovered_middle"
assert value("left") == 17 and value("right") == 25
source_at(value("$pc"))
gdb.execute("next")
assert value("below_sink") == 42 and value("middle_sink") == 42
gdb.execute("step")
gdb.execute("continue")
assert exits == [0], exits
print("true-entry-breakpoints-backward-bodies-values-stepping=PASS")
print("runtime-load-bias=" + hex(runtime_bias))
