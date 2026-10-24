"""Require full recovered types/source and real execution from each saved-program export."""
import os

import gdb

address = int(os.environ["FORGE_SAVED_ADD"], 0)
symbol = gdb.lookup_global_symbol("saved_program_add") or gdb.lookup_static_symbol("saved_program_add")
assert symbol is not None and symbol.is_function and symbol.symtab is not None, "missing full function DIE"
assert int(symbol.value().address) == address, "wrong function address"
assert symbol.symtab.fullname() == os.environ["FORGE_SAVED_SOURCE"], "wrong synthetic source"
assert "type = int (int, int, int, int)" in gdb.execute("ptype saved_program_add", to_string=True)
structure = gdb.lookup_type("struct saved_identity_type")
assert structure.code == gdb.TYPE_CODE_STRUCT and structure.sizeof == 4, "wrong analyst layout"
assert [(field.name, field.bitpos) for field in structure.fields()] == [("value", 0)], "wrong member offset"
assert structure.fields()[0].type.sizeof == 4, "wrong member type"
assert gdb.lookup_type("struct Elf64_Dyn").sizeof == 16
gdb.execute("ptype struct saved_identity_type")
gdb.execute("ptype struct Elf64_Dyn")
gdb.execute("list saved_program_add")
gdb.Breakpoint("*saved_program_add", temporary=True)
gdb.execute("run")
assert int(gdb.parse_and_eval("$pc")) == address
assert gdb.selected_frame().name() == "saved_program_add"
assert int(gdb.parse_and_eval("left")) == 19
assert int(gdb.parse_and_eval("right")) == 23
assert int(gdb.parse_and_eval("fixture_sink")) == 0
assert int(gdb.parse_and_eval("saved_identity_object.value")) == 7
assert gdb.selected_frame().find_sal().symtab.fullname() == os.environ["FORGE_SAVED_SOURCE"]
before = int(gdb.parse_and_eval("$pc"))
gdb.execute("next")
assert int(gdb.parse_and_eval("$pc")) != before
gdb.execute("step")
gdb.execute("finish")
assert int(gdb.parse_and_eval("fixture_sink")) == 42
gdb.execute("continue")
assert int(gdb.parse_and_eval("$_exitcode")) == 0
print("saved-program-gdb=PASS")
