"""Compare encoded CFI to an independent assembler reference at instruction stops."""

import json
import os
from pathlib import Path

import gdb


remote = os.environ.get("FORGE_FRAME_REMOTE", "")
witness = "r12" if os.environ["FORGE_FRAME_TARGET"] == "x86_64" else "x19"
mode = os.environ["FORGE_FRAME_MODE"]
if remote:
    gdb.execute("target remote " + remote)
gdb.Breakpoint("*cf_recurse", temporary=True)
gdb.execute("continue" if remote else "run")
checkpoint_address = int(gdb.parse_and_eval("&cf_checkpoint"))


def frames():
    rows = []
    frame = gdb.newest_frame()
    while frame is not None and len(rows) < 8:
        row = {"name": frame.name(), "pc": int(frame.pc())}
        try:
            row["witness"] = int(frame.read_register(witness))
        except gdb.error:
            row["witness"] = None
        rows.append(row)
        if frame.name() == "_start":
            break
        try:
            frame = frame.older()
        except gdb.error:
            break
    return rows


trace = []
checkpoint = False
for unused in range(128):
    stack = frames()
    trace.append(stack)
    name = stack[0]["name"]
    if name == "cf_checkpoint" and not checkpoint:
        gdb.execute("set debug frame 1")
        gdb.execute("maintenance flush register-cache")
        stack = frames()
        gdb.execute("bt")
        gdb.execute("set debug frame 0")
        complete = ([row["name"] for row in stack] == ["cf_checkpoint"] + ["cf_recurse"] * 4 + ["_start"] and
                    [row["witness"] for row in stack] == [0x5100, 0x5100, 0x5101, 0x5102, 0x5103, 0x6172])
        if mode != "absent":
            assert complete, stack
        checkpoint = True
        gdb.execute("finish")
        assert gdb.newest_frame().name() == "cf_recurse"
    elif name == "_start":
        assert checkpoint
        break
    else:
        if mode != "absent":
            assert name in ("cf_recurse", "cf_checkpoint") and stack[-1]["name"] == "_start", stack
        gdb.execute("stepi")
else:
    raise AssertionError("instruction trace exceeded fixture bounds")
gdb.execute("continue")
assert int(gdb.parse_and_eval("$_exitcode")) == 0
Path(os.environ["FORGE_FRAME_RESULT"]).write_text(json.dumps({
    "trace": trace, "complete": complete, "exitcode": 0, "checkpointAddress": checkpoint_address,
}, indent=4) + "\n")
print("cfi-encoder-gdb=" + mode + " PASS")
