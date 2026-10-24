"""Require the exact exported source directory from an unrelated working directory."""

import json
import os
from pathlib import Path

import gdb


labels = json.loads(Path(os.environ["FORGE_PATH_LABELS"]).read_text())
source = Path(os.environ["FORGE_PATH_SOURCE"])
assert int(gdb.parse_and_eval("&analyst_add")) == labels["entry"]
assert "int (int, int)" in gdb.execute("ptype analyst_add", to_string=True)
assert source.is_file()
listing = gdb.execute("list analyst_add", to_string=True)
assert "analyst_add" in listing
gdb.Breakpoint("*analyst_add", temporary=True)
gdb.execute("run")
assert int(gdb.parse_and_eval("$pc")) == labels["entry"]
for name, expected in [("left", 19), ("right", 23)]:
    value = gdb.parse_and_eval(name)
    assert value.type.code == gdb.TYPE_CODE_INT and value.type.sizeof == 4
    assert not value.is_optimized_out and int(value) == expected
assert Path(gdb.selected_frame().find_sal().symtab.fullname()) == source
gdb.execute("info source")
gdb.Breakpoint("*" + hex(labels["return"]), temporary=True)
gdb.execute("next")
assert int(gdb.parse_and_eval("$pc")) == labels["return"]
assert int(gdb.parse_and_eval("$eax")) == 42
gdb.execute("step")
assert gdb.selected_frame().name() == "main"
gdb.execute("continue")
assert int(gdb.parse_and_eval("$_exitcode")) == 0
print("path-traversal-gdb=PASS")
