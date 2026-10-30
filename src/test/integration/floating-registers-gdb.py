"""Check real scalar values and honest omissions at exact instruction addresses."""
import os

import gdb

labels = {}
with open(os.environ["FORGE_FP_LABELS"], encoding="utf-8") as stream:
    for line in stream:
        name, address = line.split()
        labels[name] = int(address, 16)
mode = os.environ["FORGE_FP_MODE"]
compiler = mode.startswith("compiler")
target = os.environ["FORGE_FP_TARGET"]
abi_profile = os.environ.get("FORGE_FP_ABI_PROFILE", "default")
assert abi_profile in ("default", "mips-fp32")
assert abi_profile == "default" or target.startswith("mips")
storage_form = os.environ.get("FORGE_FP_STORAGE_FORM", "register-alias")
assert storage_form in ("register-alias", "explicit-pieces")
assert storage_form == "register-alias" or abi_profile == "mips-fp32"
baseline = os.environ.get("FORGE_FP_BASELINE", "0") == "1"
functions = ["fp_float", "fp_double"]
if "fp_clobbered" in labels:
    functions.append("fp_clobbered")
for name in functions:
    assert int(gdb.parse_and_eval("&" + name)) == labels[name]
    gdb.execute("ptype " + name)
    gdb.execute("list " + name)
    gdb.Breakpoint("*" + name, temporary=True)
remote = os.environ.get("FORGE_FP_REMOTE", "")
if remote:
    gdb.execute("target remote " + remote)
gdb.execute("continue" if remote else "run")


def read_value(name, expected, unavailable=False, compiler_pair=False):
    value = gdb.parse_and_eval(name)
    assert value.type.strip_typedefs().code == gdb.TYPE_CODE_FLT, name + " is not floating point"
    if compiler_pair:
        # The tested QEMU/GDB FPXX pair view returns zero even though the
        # machine stores the correct doubles. This is not a positive location
        # oracle. Preserve the exact observation and independently check the
        # stored globals; Forge's unproven pair must remain unavailable.
        observed = float(value)
        assert observed in (0.0, expected), "unexpected compiler pair observation: " + str(value)
        status = "PASS" if observed == expected else "UNVERIFIED"
        print("compiler-double-location=" + status + " name=" + name +
            " observed=" + str(observed) + " expected=" + str(expected))
    elif unavailable:
        assert value.is_optimized_out, name + " unexpectedly available: " + str(value)
    else:
        assert not value.is_optimized_out, name + " unavailable"
        assert float(value) == expected, name + " wrong value: " + str(value)
        if compiler and abi_profile == "mips-fp32" and name in ("first", "second") and value.type.sizeof == 8:
            print("compiler-fp32-double-location=PASS name=" + name + " value=" + str(expected))
        if not compiler and storage_form == "explicit-pieces" and name in ("first", "second") and value.type.sizeof == 8:
            print("forge-fp32-double-piece=PASS name=" + name + " value=" + str(expected))


for function in functions:
    entry = int(gdb.parse_and_eval("&" + function))
    if int(gdb.parse_and_eval("$pc")) != entry:
        gdb.execute("continue")
    assert int(gdb.parse_and_eval("$pc")) == entry
    assert gdb.selected_frame().name() == function
    if not compiler:
        assert gdb.selected_frame().find_sal().symtab.filename.endswith("floating.dbg.c")
    bias = entry - labels[function]
    omitted = not compiler and (baseline or
        (target.startswith("mips") and function == "fp_double" and abi_profile == "default"))
    compiler_pair = compiler and target.startswith("mips") and function == "fp_double" and abi_profile == "default"
    if compiler and target.startswith("mips") and function == "fp_double":
        gdb.execute("show mipsfpu")
        gdb.execute("info registers f12 f13 f14 f15 sr")
    expected = [("value", 13.75)] if function == "fp_clobbered" else (
        [("first", 19.25), ("second", -7.5)] if function == "fp_float" else
        [("first", 21.5), ("second", -9.25)])
    for name, value in expected:
        assert gdb.parse_and_eval(name).type.sizeof == (8 if function == "fp_double" else 4)
        read_value(name, value, omitted, compiler_pair)
    markers = (["fp_clobber_before", "fp_clobber_write", "fp_clobber_after"]
        if function == "fp_clobbered" else [function + "_before", function + "_after"])
    for marker in markers:
        address = labels[marker] + bias
        if int(gdb.parse_and_eval("$pc")) != address:
            gdb.Breakpoint("*" + hex(address), temporary=True)
            gdb.execute("continue")
        assert int(gdb.parse_and_eval("$pc")) == address
        for name, value in expected:
            if compiler and marker == "fp_clobber_after":
                actual = gdb.parse_and_eval(name)
                assert actual.is_optimized_out or float(actual) == value
            else:
                read_value(name, value, omitted or
                    (not compiler and marker == "fp_clobber_after"), compiler_pair)
        print("floating-register-point=" + function + "/" + marker + " PASS")
    if function == "fp_clobbered":
        read_value("fp_clobber_sink", 13.75)
    else:
        read_value(function + "_first", expected[0][1])
        read_value(function + "_second", expected[1][1])
    if function == "fp_float":
        # The later entry breakpoints also stop stepping if the source maps a
        # small function as one statement. Do not step past the next entry.
        print("FP_RETURN_BEGIN")
        before = int(gdb.parse_and_eval("$pc"))
        gdb.execute("next")
        assert int(gdb.parse_and_eval("$pc")) != before
        if gdb.selected_frame().name() not in functions[1:]:
            before = int(gdb.parse_and_eval("$pc"))
            gdb.execute("step")
            assert int(gdb.parse_and_eval("$pc")) != before
        print("FP_RETURN_END")
gdb.execute("continue")
assert int(gdb.parse_and_eval("$_exitcode")) == 0
print("floating-registers-gdb=" + mode + " PASS")
