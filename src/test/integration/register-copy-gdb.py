"""Compare compiler and Forge locations before and after both register writes."""

import json
import os

import gdb


with open(os.environ["FORGE_COPY_LABELS"], encoding="utf-8") as stream:
    labels = json.load(stream)
mode = os.environ["FORGE_COPY_MODE"]
compiler = mode == "compiler"
target = os.environ["FORGE_COPY_TARGET"]
remote = os.environ.get("FORGE_COPY_REMOTE", "")
functions = ["copy32_keep", "copy32_kill", "copy64_keep", "copy64_kill"]
for name in functions:
    assert int(gdb.parse_and_eval("&" + name)) == labels[name]["entry"]
    gdb.execute("ptype " + name)
    signature = gdb.parse_and_eval(name).type
    assert signature.code == gdb.TYPE_CODE_FUNC
    parameters = signature.fields()
    assert len(parameters) == 1
    for value_type in [signature.target(), parameters[0].type]:
        value_type = value_type.strip_typedefs()
        assert value_type.code == gdb.TYPE_CODE_INT
        assert value_type.sizeof == (8 if "64" in name else 4)
        assert int(gdb.Value(-1).cast(value_type)) == -1, (name, str(value_type))
    gdb.execute("list " + name)
if remote:
    gdb.execute("target remote " + remote)


def stop(address, command="continue"):
    gdb.Breakpoint("*" + hex(address), temporary=True)
    gdb.execute(command)
    assert int(gdb.parse_and_eval("$pc")) == address


def check_value(name, marker, expected, unavailable=False):
    value = gdb.parse_and_eval("value")
    assert value.type.sizeof == (8 if "64" in name else 4)
    if unavailable:
        assert value.is_optimized_out, (name, marker, str(value))
        print(name + ":" + marker + "=unavailable")
    else:
        assert not value.is_optimized_out and int(value) == expected, (name, marker, str(value))
        print(name + ":" + marker + "=" + str(expected))


started = False
for values in [(19, 19), (-19, -19), (-1985229329, -81985529216486895)]:
    for name in functions:
        expected = values[1 if "64" in name else 0]
        width = 64 if "64" in name else 32
        mask = (1 << width) - 1
        record = labels[name]
        # A symbolic instruction breakpoint relocates with a PIE at startup;
        # a numeric link-time address would remain an absolute runtime address.
        gdb.Breakpoint("*" + name, temporary=True)
        gdb.execute("continue" if remote or started else "run")
        started = True
        entry = int(gdb.parse_and_eval("&" + name))
        bias = entry - record["entry"]
        assert int(gdb.parse_and_eval("$pc")) == entry
        check_value(name, "entry", expected)
        if not compiler:
            assert gdb.selected_frame().find_sal().symtab.filename.endswith("copy.dbg.c")
        for marker in ["saved", "write", "after"]:
            stop(record[marker] + bias)
            check_value(name, marker, expected)
            backup = "$rax" if target == "x86_64" else "$x1"
            assert int(gdb.parse_and_eval(backup)) & mask == expected & mask
            if marker == "after":
                incoming = "$rdi" if target == "x86_64" else "$x0"
                assert int(gdb.parse_and_eval(incoming)) & mask != expected & mask
        killed = name.endswith("_kill")
        if killed:
            stop(record["kill"] + bias)
            check_value(name, "kill", expected)
            assert int(gdb.parse_and_eval(name + "_sink")) == expected
            stop(record["unavailable"] + bias)
            assert int(gdb.parse_and_eval(backup)) == 0
            # GCC retains an entry-value recovery expression after destroying
            # its saved copy. Forge has no proven call-site recovery and must
            # instead report an unavailable value at this exact boundary.
            check_value(name, "unavailable", expected, unavailable=not compiler)
        # Break at the return so source next/step cannot silently run out of
        # the function. The compiler and synthetic sources can group differently.
        return_address = record["return"] + bias
        gdb.Breakpoint("*" + hex(return_address), temporary=True)
        for command in ["next", "step"]:
            if int(gdb.parse_and_eval("$pc")) != return_address:
                gdb.execute(command)
        if int(gdb.parse_and_eval("$pc")) != return_address:
            gdb.execute("continue")
        assert int(gdb.parse_and_eval("$pc")) == return_address
        check_value(name, "return", expected, unavailable=killed and not compiler)
        assert int(gdb.parse_and_eval(name + "_sink")) == expected
        gdb.execute("print/a &" + name + "_sink")
        gdb.execute("print &" + name + "_sink")
gdb.execute("continue")
assert int(gdb.parse_and_eval("$_exitcode")) == 0
print("register-copy-gdb=" + mode + " PASS")
