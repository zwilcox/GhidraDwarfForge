"""Compare compiler and Forge values through the proven direct register copy."""

import os

import gdb


labels = {}
with open(os.environ["FORGE_PREFIX_LABELS"], encoding="utf-8") as stream:
    for line in stream:
        name, address = line.split()
        labels[name] = int(address, 16)
compiler = os.environ["FORGE_PREFIX_MODE"] == "compiler"
assert int(gdb.parse_and_eval("&prefix_value")) == labels["prefix_value"]
assert "int (int)" in gdb.execute("ptype prefix_value", to_string=True)
gdb.execute("list prefix_value")
remote = os.environ.get("FORGE_PREFIX_REMOTE", "")
if remote:
    gdb.execute("target remote :" + remote)
gdb.Breakpoint("*prefix_value")
gdb.execute("continue" if remote else "run")
entry = int(gdb.parse_and_eval("&prefix_value"))
assert int(gdb.parse_and_eval("$pc")) == entry
assert int(gdb.parse_and_eval("value")) == 19
if not compiler:
    assert gdb.selected_frame().find_sal().symtab.filename.endswith("prefix.dbg.c")
print("entry-value=19")
for marker in ["prefix_before", "prefix_write", "prefix_after"]:
    address = entry + labels[marker] - labels["prefix_value"]
    gdb.Breakpoint("*" + hex(address))
    gdb.execute("continue")
    assert int(gdb.parse_and_eval("$pc")) == address
    value = gdb.parse_and_eval("value")
    assert not value.is_optimized_out and int(value) == 19
    print(marker + "-value=19")
gdb.execute("disable breakpoints")
return_address = entry + labels["prefix_return"] - labels["prefix_value"]
gdb.Breakpoint("*" + hex(return_address))
for command in ["next", "step"]:
    if int(gdb.parse_and_eval("$pc")) != return_address:
        gdb.execute(command)
if int(gdb.parse_and_eval("$pc")) != return_address:
    gdb.execute("continue")
assert int(gdb.parse_and_eval("$pc")) == return_address
value = gdb.parse_and_eval("value")
assert not value.is_optimized_out and int(value) == 19
print("prefix_return-value=19")
assert int(gdb.parse_and_eval("prefix_sink")) == 19
print("sink-value=19")
gdb.execute("continue")
assert int(gdb.parse_and_eval("$_exitcode")) == 0
print("register-prefix-gdb=" + ("compiler" if compiler else "forge") + " PASS")
