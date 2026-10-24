"""GDB oracle: distinguish two function statics and a global of the same name."""
import os

import gdb


expected = [int(value, 0) for value in os.environ["FORGE_SCOPE_ADDRESSES"].split()]
kind = os.environ["FORGE_SCOPE_KIND"]


def value(expression):
    return int(gdb.parse_and_eval(expression))


def require(condition, message):
    if not condition:
        raise gdb.GdbError(message)


require(value("private_count") == 19, "global lookup chose a function's private object")
require(value("first_scope::private_count") == 37, "first private object is wrong")
require(value("second_scope::private_count") == 83, "second private object is wrong")
require(value("scoped_value") == 61, "namespace global lookup regressed")
if kind == "forge":
    require("int" in gdb.execute("ptype declared_external", to_string=True),
            "external-data declaration disappeared")
    gdb.execute("list first_scope")
    gdb.execute("list second_scope")
gdb.execute("ptype first_scope")
gdb.execute("ptype second_scope")
gdb.Breakpoint("first_scope")
gdb.Breakpoint("second_scope")
gdb.execute(os.environ["FORGE_SCOPE_RUN"])
require(gdb.newest_frame().name() == "first_scope", "did not stop in the first owner")
bias = value("&first_scope") - expected[0]
require(value("private_count") == 37, "first owner did not shadow the global")
require(value("&first_scope::private_count") == expected[2] + bias,
        "first static address does not match the compiler oracle")
require(value("&second_scope::private_count") == expected[3] + bias,
        "second static address does not match the compiler oracle")
global_symbol = gdb.lookup_global_symbol("private_count") or gdb.lookup_static_symbol("private_count")
require(global_symbol is not None and int(global_symbol.value().address) == expected[4] + bias,
        "global identity or address was lost")
require(int(global_symbol.value()) == 19, "global value changed")
print("SCOPE_RETURN_BEGIN")
for attempt in range(8):
    if gdb.newest_frame().name() != "first_scope":
        break
    gdb.execute("next")
require(gdb.newest_frame().name() != "first_scope", "next did not leave the first owner")
print("SCOPE_RETURN_END owner=" + str(gdb.newest_frame().name()))
gdb.execute("continue")
require(gdb.newest_frame().name() == "second_scope", "did not stop in the second owner")
require(value("private_count") == 83, "second owner did not shadow the global")
require(value("first_scope::private_count") == 37, "other owner's value became ambiguous")
gdb.execute("continue")
require(gdb.selected_inferior().pid == 0, "fixture did not exit")
print("function-static-scopes-gdb=" + kind + " PASS")
