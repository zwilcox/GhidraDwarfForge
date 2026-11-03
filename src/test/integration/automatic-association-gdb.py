"""Require actual Forge DWARF from the expected automatically associated file."""
import os

import gdb


def require(condition, message):
    if not condition:
        raise gdb.GdbError(message)


function_name = os.environ.get("FORGE_ASSOCIATION_FUNCTION", "recovered_add")
type_name = os.environ.get("FORGE_ASSOCIATION_TYPE", "fixture_state")
symbol = gdb.lookup_global_symbol(function_name) or gdb.lookup_static_symbol(function_name)
if os.environ["FORGE_ASSOCIATION_MODE"] == "absent":
    require(symbol is None or symbol.symtab is None,
            "GDB accepted full DWARF from an intentionally mismatched sidecar")
    print("automatic-association=absent PASS")
else:
    expected_address = int(os.environ["FORGE_ASSOCIATION_ADDRESS"], 0)
    require(symbol is not None and symbol.is_function and symbol.symtab is not None,
            function_name + " has no full DWARF function symbol")
    require(int(symbol.value().address) == expected_address,
            "associated function address differs from the compiler oracle")
    require(os.path.realpath(symbol.symtab.objfile.filename) ==
            os.path.realpath(os.environ["FORGE_ASSOCIATION_DEBUG_FILE"]),
            "GDB used a different debug artifact")
    require(os.path.realpath(symbol.symtab.fullname()) ==
            os.path.realpath(os.environ["FORGE_ASSOCIATION_SOURCE"]),
            "GDB associated an incorrect source file")
    prototype = gdb.execute("ptype " + function_name, to_string=True)
    require("type = int (int, int)" in prototype, "recovered function prototype is incorrect")
    print(prototype)
    structure = gdb.execute("ptype struct " + type_name, to_string=True)
    if "FORGE_ASSOCIATION_MEMBER" in os.environ:
        require(os.environ["FORGE_ASSOCIATION_MEMBER"] in structure, "curated member was not exported")
    print(structure)
    listing = gdb.execute("list " + function_name, to_string=True)
    require(function_name in listing, "synthetic function source was not listed")
    print(listing)
    breakpoint = gdb.Breakpoint(function_name)
    require(breakpoint.locations and all(location.address is not None
            for location in breakpoint.locations), "named breakpoint did not resolve")
    if os.environ.get("FORGE_ASSOCIATION_RUNTIME") == "1":
        remote = os.environ.get("FORGE_ASSOCIATION_REMOTE")
        if remote:
            gdb.execute("set sysroot " + os.environ["FORGE_ASSOCIATION_SYSROOT"])
            gdb.execute("set auto-solib-add off")
            gdb.execute("target remote " + remote)
            gdb.execute("continue")
        else:
            gdb.execute("run")
        require(gdb.newest_frame().name() == function_name, "automatic breakpoint was not hit")
        require(int(gdb.parse_and_eval("left")) == 19 and
                int(gdb.parse_and_eval("right")) == 23, "recovered argument values are wrong")
        print(gdb.execute("info args", to_string=True))
        breakpoint.delete()
        gdb.execute("continue")
        require(gdb.selected_inferior().pid == 0, "fixture did not exit")
    print("automatic-association=present PASS")
