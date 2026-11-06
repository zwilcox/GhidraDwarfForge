"""Independent compiler-CFI oracle; this does not test Forge synthesis yet."""

import json
import os
from pathlib import Path

import gdb


mode = os.environ["FORGE_CFI_MODE"]
register = os.environ["FORGE_CFI_REGISTER"]
remote = os.environ.get("FORGE_CFI_REMOTE", "")
shared = os.environ.get("FORGE_CFI_SHARED", "") == "1"
root_name = "main" if shared else "_start"
expected_names = ["cfi_checkpoint"] + ["cfi_recursive"] * 4 + [
    "cfi_outer", "cfi_main", root_name]
expected_values = [0x5100, 0x5100, 0x5101, 0x5102, 0x5103, 0x6172]


def snapshot():
    result = []
    frame = gdb.newest_frame()
    while frame is not None and len(result) < 12:
        row = {"name": frame.name(), "pc": int(frame.pc())}
        try:
            row["witness"] = int(frame.read_register(register))
        except gdb.error as error:
            row["unavailable"] = str(error)
        result.append(row)
        if frame.name() == root_name:
            break
        try:
            frame = frame.older()
        except gdb.error as error:
            result.append({"stop": str(error)})
            break
    return result


if mode == "disabled":
    gdb.execute("maintenance set dwarf unwinders off")
if remote:
    gdb.execute("target remote " + remote)
if shared:
    gdb.Breakpoint("cfi_ready", temporary=True)
    gdb.execute("continue" if remote else "run")
    bias = int(gdb.parse_and_eval("cfi_module_bias"))
    symbols = os.environ["FORGE_CFI_SYMBOLS"]
    gdb.execute('add-symbol-file "' + symbols + '" -o ' + hex(bias))
gdb.Breakpoint("*cfi_checkpoint", temporary=True)
gdb.execute("continue" if remote or shared else "run")
checkpoint_address = int(gdb.parse_and_eval("&cfi_checkpoint"))
gdb.execute("set debug frame 1")
gdb.execute("maintenance flush register-cache")
frames = snapshot()
gdb.execute("bt")
gdb.execute("set debug frame 0")
complete = ([frame.get("name") for frame in frames] == expected_names and
            [frame.get("witness") for frame in frames[:6]] == expected_values)
if mode == "compiler":
    assert complete, frames

# Probe the recursive leaf's return and its caller's epilogue one instruction
# at a time. The observed trace will be the independent reference for synthesis.
# Negative controls intentionally do not rely on a successful complete bt.
gdb.execute("finish")
assert gdb.newest_frame().name() == "cfi_recursive"
trace = []
if mode == "compiler":
    for unused in range(128):
        row = snapshot()
        trace.append(row)
        if row[0]["name"] == "cfi_outer":
            break
        assert row[0]["name"] == "cfi_recursive", row
        assert row[-1]["name"] == root_name, row
        gdb.execute("stepi")
    else:
        raise AssertionError("recursive returns exceeded instruction budget")
    # Four distinct recursive frames must actually have been returned through.
    assert {sum(f.get("name") == "cfi_recursive" for f in row)
            for row in trace} == {0, 1, 2, 3, 4}, trace
gdb.execute("continue")
assert int(gdb.parse_and_eval("$_exitcode")) == 0
Path(os.environ["FORGE_CFI_RESULT"]).write_text(json.dumps({
    "mode": mode, "complete": complete, "frames": frames,
    "instructionTrace": trace, "exitcode": 0,
    "checkpointAddress": checkpoint_address,
}, indent=4) + "\n")
print("synthetic-cfi-reference-gdb=" + mode + " PASS")
