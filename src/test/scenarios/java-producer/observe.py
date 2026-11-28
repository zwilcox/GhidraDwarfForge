"""GDB assertions use the linker map and explicit runtime values of the fixture."""
import json
import os
from pathlib import Path

import gdb

case = os.environ["EVAL_CASE"]
sidecar = Path(os.environ["EVAL_SIDECAR"])
source = Path(str(sidecar) + ".c")
gdb.execute(f'file "{os.environ["EVAL_INPUT"]}"')
gdb.execute(f'symbol-file "{sidecar}"')
start, size, split, first, second = (int(os.environ["EVAL_" + key], 16)
                                     for key in ("START", "SIZE", "SPLIT", "FIRST", "SECOND"))
width = 4 if case == "mips32be" else 8
mask = (1 << (width * 8)) - 1
if case == "mips64high":
    assert start >> 63 == first >> 63 == second >> 63 == 1
assert int(gdb.parse_and_eval("(unsigned long long)&eval_probe")) == start
assert "eval_probe" in gdb.execute("list eval_probe", to_string=True)
body = source.read_text().splitlines()
lines = [next(n for n, text in enumerate(body, 1) if marker in text)
         for marker in ("int eval_probe(void)", "    return ")]
for pc, expected in [(start, lines[0]), (split, lines[1])]:
    line = gdb.find_pc_line(pc)
    assert (line.line, line.symtab.fullname()) == (expected, str(source))
block = gdb.block_for_pc(start)
while block and not block.function:
    block = block.superblock
assert (block.start, block.end) == (start, start + size)
report = {"function": [start, start + size], "lines": lines}
rich = os.environ["EVAL_MODEL"] == "rich"
if rich:
    node = gdb.lookup_type("struct EvalNode")
    next_member, value_member = node.fields()
    assert next_member.type.target() == node and next_member.bitpos == 0
    assert value_member.type.sizeof == 4 and value_member.bitpos == width * 8
    assert node.sizeof == 2 * width
    report["type"] = [str(node), node.sizeof, next_member.name, value_member.name, value_member.bitpos]

socket = os.environ["EVAL_SOCKET"]
if socket:
    gdb.execute("target remote " + socket)
values = []
for address, storage, expected in [(start, first, 19), (split, second, 42)]:
    gdb.Breakpoint("*" + hex(address), temporary=True)
    gdb.execute("run" if address == start and not socket else "continue")
    frame = gdb.selected_frame()
    assert frame.name() == "eval_probe" and (frame.pc() & mask) == address
    if case == "x86_64":
        expected_return = int(os.environ["EVAL_CALLER"], 16)
        assert (frame.older().pc() & mask) == expected_return
        report["caller"] = expected_return
    if rich:
        moving = frame.read_var("moving")
        observed = [int(moving.address) & mask, int(moving["value"]),
                    int(moving["next"]) & mask, int(moving["next"].dereference()["value"])]
        assert observed == [storage, expected, first, 19], observed
        values.append(observed)
if rich:
    report["values"] = values
if case == "mips64high":
    gdb.execute("disconnect")
else:
    gdb.execute("continue")
    assert int(gdb.parse_and_eval("$_exitcode")) == 0
(sidecar.parent / "observations.json").write_text(json.dumps(report, sort_keys=True) + "\n")
print("GDB observations PASS")
