"""Check unsupported stack-start omission against real compiler scopes."""

import json
import os
from pathlib import Path

import gdb


labels = json.loads(Path(os.environ["FORGE_STACK_LABELS"]).read_text())
storage_path = Path(os.environ["FORGE_STACK_STORAGE"])
compiler = os.environ["FORGE_STACK_MODE"] == "compiler"
baseline = os.environ.get("FORGE_STACK_EXPECTATION", "fixed") == "baseline-reproducer"
storage = {} if compiler else json.loads(storage_path.read_text())
remote = os.environ.get("FORGE_STACK_REMOTE", "")
for name in ["stack_scope", "zero_stack"]:
    assert int(gdb.parse_and_eval("&" + name)) == labels[name]["entry"]
    assert "void (void)" in gdb.execute("ptype " + name, to_string=True)
    gdb.execute("list " + name)
if remote:
    gdb.execute("target remote " + remote)
gdb.Breakpoint("*stack_scope", temporary=True)
gdb.execute("continue" if remote else "run")
entry = int(gdb.parse_and_eval("&stack_scope"))
bias = entry - labels["stack_scope"]["entry"]
assert int(gdb.parse_and_eval("$pc")) == entry
entry_stack = int(gdb.parse_and_eval("$sp"))


def stop(address):
    gdb.Breakpoint("*" + hex(address), temporary=True)
    gdb.execute("continue")
    assert int(gdb.parse_and_eval("$pc")) == address


def missing(name):
    try:
        value = gdb.parse_and_eval(name)
    except gdb.error as error:
        assert 'No symbol "' + name + '" in current context.' in str(error), str(error)
        print(name + "=out-of-scope")
        return
    raise AssertionError((name, "unexpected compiler scope", str(value)))


def typed(name, expected=None):
    value = gdb.parse_and_eval(name)
    assert value.type.strip_typedefs().code == gdb.TYPE_CODE_INT and value.type.sizeof == 4
    if expected is None:
        assert value.is_optimized_out, (name, str(value))
        print(name + "=unavailable")
    else:
        assert not value.is_optimized_out and int(value) == expected, (name, str(value))
        print(name + "=" + str(expected))


for marker, expected in [("first_live", 11), ("between_scopes", 11),
                         ("second_live", 22), ("after_scopes", 22)]:
    stop(labels["stack_scope"][marker] + bias)
    if compiler:
        if marker == "first_live":
            typed("first", 11)
            storage["scope_offset"] = int(gdb.parse_and_eval("&first")) - entry_stack
        if marker == "second_live":
            typed("second", 22)
            missing("first")
            assert int(gdb.parse_and_eval("&second")) - entry_stack == storage["scope_offset"]
        else:
            missing("second")
            if marker != "first_live":
                missing("first")
    else:
        typed("second", expected if baseline else None)
        assert gdb.selected_frame().find_sal().symtab.filename.endswith("stack.dbg.c")
    address = entry_stack + storage["scope_offset"]
    assert int(gdb.parse_and_eval("*(int*)" + hex(address))) == expected
    print("stack-scope-point=" + marker + " PASS raw=" + str(expected))
assert int(gdb.parse_and_eval("scope_sink")) == 22
gdb.execute("print/a &scope_sink")
gdb.execute("print &scope_sink")

# The next function is also a stopping point for source stepping out of the
# scoped fixture; symbolic breakpoints keep PIE relocation explicit.
gdb.Breakpoint("*zero_stack", temporary=True)
for command in ["next", "step"]:
    if int(gdb.parse_and_eval("$pc")) != int(gdb.parse_and_eval("&zero_stack")):
        gdb.execute(command)
if int(gdb.parse_and_eval("$pc")) != int(gdb.parse_and_eval("&zero_stack")):
    gdb.execute("continue")
zero_entry = int(gdb.parse_and_eval("&zero_stack"))
assert int(gdb.parse_and_eval("$pc")) == zero_entry
zero_stack = int(gdb.parse_and_eval("$sp"))
zero_bias = zero_entry - labels["zero_stack"]["entry"]
stop(labels["zero_stack"]["zero_live"] + zero_bias)
typed("zero", 37)
if compiler:
    storage["zero_offset"] = int(gdb.parse_and_eval("&zero")) - zero_stack
else:
    assert gdb.selected_frame().find_sal().symtab.filename.endswith("stack.dbg.c")
assert int(gdb.parse_and_eval("*(int*)" + hex(zero_stack + storage["zero_offset"]))) == 37
stop(labels["zero_stack"]["return"] + zero_bias)
assert int(gdb.parse_and_eval("zero_sink")) == 37
gdb.execute("print/a &zero_sink")
gdb.execute("print &zero_sink")
gdb.execute("continue")
assert int(gdb.parse_and_eval("$_exitcode")) == 0
if compiler:
    assert set(storage) == {"scope_offset", "zero_offset"}
    assert all(-4096 <= offset < 0 for offset in storage.values()), storage
    storage_path.write_text(json.dumps(storage, indent=4) + "\n")
    print("stack-first-use-gdb=compiler PASS")
elif baseline:
    print("stack-first-use-incorrect-location=REPRODUCED")
else:
    print("stack-first-use-gdb=forge PASS")
