"""Actual Linux AArch64 SVC: compiler value versus honest Forge unavailability."""

import os

import gdb


labels = {}
with open(os.environ["FORGE_OPAQUE_LABELS"], encoding="utf-8") as stream:
    for line in stream:
        name, address = line.split()
        labels[name] = int(address, 0)
mode = os.environ["FORGE_OPAQUE_MODE"]
expectation = os.environ["FORGE_OPAQUE_EXPECTATION"]
assert mode in ("compiler", "forge")
assert expectation in ("fixed", "baseline-reproducer")


def integer(expression):
    return int(gdb.parse_and_eval(expression))


def parameters(stage, post_opaque):
    value = gdb.parse_and_eval("value")
    destination = gdb.parse_and_eval("destination")
    assert value.type.strip_typedefs().code == gdb.TYPE_CODE_INT
    assert value.type.sizeof == 4
    assert destination.type.strip_typedefs().code == gdb.TYPE_CODE_PTR
    assert destination.type.sizeof == 8 and destination.type.target().sizeof == 4
    if mode == "forge" and expectation == "fixed":
        assert value.is_optimized_out and destination.is_optimized_out, (
            stage + ": opaque operation must not retain an unproved register location")
        print(stage + "-parameters=unavailable")
    else:
        assert not value.is_optimized_out and not destination.is_optimized_out
        assert int(destination) == sink
        if mode == "forge" and post_opaque:
            assert int(value) == integer("$w0") and int(value) > 0
            print(stage + "-incorrect-parameter=" + str(int(value)))
        else:
            assert int(value) == -19
            print(stage + "-value=-19")


# Exec has link-time addresses before any full CU is requested. PIE's runtime
# address is checked below after GDB supplies the independently verified bias.
if os.environ["FORGE_OPAQUE_ROLE"] == "exec":
    gdb.execute("print/a " + hex(labels["opaque_sink"]))
symbol = gdb.lookup_global_symbol("opaque_value") or gdb.lookup_static_symbol("opaque_value")
assert symbol is not None and symbol.is_function and symbol.symtab is not None
signature = symbol.type.strip_typedefs()
assert signature.code == gdb.TYPE_CODE_FUNC and signature.target().code == gdb.TYPE_CODE_VOID
assert len(signature.fields()) == 2
assert signature.fields()[0].type.sizeof == 4
assert signature.fields()[1].type.strip_typedefs().code == gdb.TYPE_CODE_PTR
if mode == "forge":
    assert symbol.symtab.filename.endswith("opaque.dbg.c")
gdb.execute("info functions opaque_value")
gdb.execute("ptype opaque_value")
gdb.execute("list opaque_value")

entry = integer("&opaque_value")
bias = entry - labels["opaque_value"]
sink = labels["opaque_sink"] + bias
assert integer("&opaque_sink") == sink and integer("opaque_sink") == -1
gdb.execute("print/a " + hex(sink))
gdb.execute("print &opaque_sink")
for name in ("opaque_value", "opaque_before", "opaque_store", "opaque_return"):
    breakpoint = gdb.Breakpoint("*" + hex(labels[name] + bias))
    assert len(breakpoint.locations) == 1
gdb.execute("continue")
assert integer("$pc") == entry
assert integer("$x0") & 0xffffffff == 0xffffffed and integer("$x1") == sink
parameters("entry", False)
gdb.execute("continue")
assert integer("$pc") == labels["opaque_before"] + bias
parameters("before-svc", False)
# The strong store marker lies beyond the NOP adjacent to SVC. Do not rely on
# QEMU stopping at that adjacent instruction or retry a missed breakpoint.
gdb.execute("continue")
assert integer("$pc") == labels["opaque_store"] + bias
assert integer("$x0") > 0 and integer("$x1") == sink
assert integer("opaque_sink") == -1
parameters("after-svc", True)
if mode == "forge":
    assert gdb.selected_frame().find_sal().symtab.filename.endswith("opaque.dbg.c")
gdb.execute("next")
assert integer("$pc") == labels["opaque_return"] + bias
assert integer("opaque_sink") == -19 and integer("&opaque_sink") == sink
gdb.execute("print/a &opaque_sink")
gdb.execute("print &opaque_sink")
parameters("return", True)
gdb.execute("disable breakpoints")
gdb.execute("step")
gdb.execute("continue")
assert integer("$_exitcode") == 0
if mode == "forge" and expectation == "baseline-reproducer":
    print("baseline-incorrect-register-location=REPRODUCED")
else:
    print("opaque-register-effects-gdb=" + mode + " PASS")
