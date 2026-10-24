"""Require actual Forge DWARF from the expected automatically associated file."""
import os

import gdb


def require(condition, message):
    if not condition:
        raise gdb.GdbError(message)


symbol = gdb.lookup_global_symbol("recovered_add") or gdb.lookup_static_symbol("recovered_add")
if os.environ["FORGE_ASSOCIATION_MODE"] == "absent":
    require(symbol is None or symbol.symtab is None,
            "GDB accepted full DWARF from an intentionally mismatched sidecar")
    print("automatic-association=absent PASS")
else:
    expected_address = int(os.environ["FORGE_ASSOCIATION_ADDRESS"], 0)
    require(symbol is not None and symbol.is_function and symbol.symtab is not None,
            "recovered_add has no full DWARF function symbol")
    require(int(symbol.value().address) == expected_address,
            "associated function address differs from the compiler oracle")
    require(os.path.realpath(symbol.symtab.objfile.filename) ==
            os.path.realpath(os.environ["FORGE_ASSOCIATION_DEBUG_FILE"]),
            "GDB used a different debug artifact")
    require(os.path.realpath(symbol.symtab.fullname()) ==
            os.path.realpath(os.environ["FORGE_ASSOCIATION_SOURCE"]),
            "GDB associated an incorrect source file")
    prototype = gdb.execute("ptype recovered_add", to_string=True)
    require("type = int (int, int)" in prototype, "recovered function prototype is incorrect")
    print(prototype)
    print(gdb.execute("ptype struct fixture_state", to_string=True))
    listing = gdb.execute("list recovered_add", to_string=True)
    require("recovered_add" in listing, "synthetic function source was not listed")
    print(listing)
    breakpoint = gdb.Breakpoint("recovered_add")
    require(breakpoint.locations and all(location.address is not None
            for location in breakpoint.locations), "named breakpoint did not resolve")
    if os.environ.get("FORGE_ASSOCIATION_RUNTIME") == "1":
        gdb.execute("run")
        require(gdb.newest_frame().name() == "recovered_add", "automatic breakpoint was not hit")
        require(int(gdb.parse_and_eval("left")) == 19 and
                int(gdb.parse_and_eval("right")) == 23, "recovered argument values are wrong")
        print(gdb.execute("info args", to_string=True))
        breakpoint.delete()
        gdb.execute("continue")
        require(gdb.selected_inferior().pid == 0, "fixture did not exit")
    print("automatic-association=present PASS")
