"""GDB oracle: distinguish two function statics and a global of the same name."""
import os

import gdb


expected = [int(value, 0) for value in os.environ["FORGE_SCOPE_ADDRESSES"].split()]
kind = os.environ["FORGE_SCOPE_KIND"]
qualified_fixture = os.environ.get("FORGE_SCOPE_QUALIFIED", "0") == "1"
qualified_names = qualified_fixture and kind == "forge"
first_name = "analysis_left::nested::curated_same" if qualified_names else "first_scope"
second_name = "analysis_right::nested::curated_same" if qualified_names else "second_scope"
# C11 expression parsing requires quoting the function name, not the complete
# function-and-variable path. No C++ CU language or guessed linkage name is used.
first_expression = "'" + first_name + "'" if qualified_names else first_name
second_expression = "'" + second_name + "'" if qualified_names else second_name


def value(expression):
    return int(gdb.parse_and_eval(expression))


def require(condition, message):
    if not condition:
        raise gdb.GdbError(message)


require(value("private_count") == 19, "global lookup chose a function's private object")
require(value(first_expression + "::private_count") == 37, "first private object is wrong")
require(value(second_expression + "::private_count") == 83, "second private object is wrong")
require(value("scoped_value") == 61, "namespace global lookup regressed")
initial_bias = value("&" + first_expression) - expected[0]
require(value("&" + second_expression) == expected[1] + initial_bias,
        "second initial function address is wrong")
for expression in ("private_count", first_expression + "::private_count",
        second_expression + "::private_count", "scoped_value"):
    # Formatting invokes GDB's address-to-CU lookup, unlike integer-only reads.
    gdb.execute("print/a &" + expression)
    gdb.execute("print &" + expression)
if qualified_fixture:
    require(value("&curated_same") == expected[6] + initial_bias,
            "bare global function identity was lost")
    require("int" in gdb.execute("ptype curated_same", to_string=True),
            "global function prototype was lost")
if kind == "forge":
    require("int" in gdb.execute("ptype declared_external", to_string=True),
            "external-data declaration disappeared")
    for name, expression in ((first_name, first_expression), (second_name, second_expression)):
        symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)
        require(symbol is not None and symbol.is_function and symbol.symtab is not None and
                symbol.symtab.filename.endswith(".dbg.c"), "missing full Forge symbol " + name)
        gdb.execute("list " + expression)
for expression in (first_expression, second_expression):
    require("int" in gdb.execute("ptype " + expression, to_string=True),
            "function prototype lost: " + expression)
for name in (first_name, second_name):
    breakpoint = gdb.Breakpoint(name)
    require(len(breakpoint.locations) == 1, "ambiguous qualified breakpoint " + name)
gdb.execute(os.environ["FORGE_SCOPE_RUN"])
require(gdb.newest_frame().name() == first_name, "did not stop in the first owner")
bias = value("&" + first_expression) - expected[0]
require(value("&" + second_expression) == expected[1] + bias, "second runtime function address is wrong")
if qualified_fixture:
    require(value("&curated_same") == expected[6] + bias, "bare global runtime address is wrong")
require(value("private_count") == 37, "first owner did not shadow the global")
require(value("&" + first_expression + "::private_count") == expected[2] + bias,
        "first static address does not match the compiler oracle")
require(value("&" + second_expression + "::private_count") == expected[3] + bias,
        "second static address does not match the compiler oracle")
global_symbol = gdb.lookup_global_symbol("private_count") or gdb.lookup_static_symbol("private_count")
require(global_symbol is not None and int(global_symbol.value().address) == expected[4] + bias,
        "global identity or address was lost")
require(int(global_symbol.value()) == 19, "global value changed")
gdb.execute("print/a " + hex(int(global_symbol.value().address)))
gdb.execute("print " + first_expression + "::private_count")
print("global-address-formatting=PASS")
print("SCOPE_RETURN_BEGIN")
for attempt in range(8):
    if gdb.newest_frame().name() != first_name:
        break
    gdb.execute("next")
require(gdb.newest_frame().name() != first_name, "next did not leave the first owner")
print("SCOPE_RETURN_END owner=" + str(gdb.newest_frame().name()))
gdb.execute("continue")
require(gdb.newest_frame().name() == second_name, "did not stop in the second owner")
require(value("private_count") == 83, "second owner did not shadow the global")
require(value(first_expression + "::private_count") == 37, "other owner's value became ambiguous")
gdb.execute("continue")
require(gdb.selected_inferior().pid == 0, "fixture did not exit")
require(value("$_exitcode") == 0, "fixture returned an incorrect function/static value")
print("function-static-scopes-gdb=" + kind + " PASS")
