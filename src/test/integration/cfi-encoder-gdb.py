"""Compare encoded CFI to an independent assembler reference at instruction stops."""

import json
import os
from pathlib import Path

import gdb


remote = os.environ.get("FORGE_FRAME_REMOTE", "")
witness = "r12" if os.environ["FORGE_FRAME_TARGET"] == "x86_64" else "x19"
mode = os.environ["FORGE_FRAME_MODE"]
uses_cfi = mode not in ("absent", "disabled")
profile = os.environ.get("FORGE_FRAME_PROFILE", "encoder")
shared = os.environ.get("FORGE_FRAME_SHARED", "") == "1"
module_bias = 0
assert profile in ("encoder", "shrinkwrap")
if mode == "disabled":
    gdb.execute("maintenance set dwarf unwinders off")
if remote:
    gdb.execute("target remote " + remote)
if shared:
    gdb.Breakpoint("cfi_ready", temporary=True)
    gdb.execute("continue" if remote else "run")
    module_bias = int(gdb.parse_and_eval("cfi_module_bias"))
    gdb.execute('add-symbol-file "' + os.environ["FORGE_FRAME_SYMBOLS"] + '" -o ' + hex(module_bias))
gdb.Breakpoint("*cf_recurse", temporary=True)
gdb.execute("continue" if remote or shared else "run")
checkpoint_address = int(gdb.parse_and_eval("&cf_checkpoint"))
recurse_address = int(gdb.parse_and_eval("&cf_recurse"))


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
    if stack[0]['pc'] in (checkpoint_address, recurse_address):
        stack_pointer = int(gdb.parse_and_eval('$rsp' if witness == 'r12' else '$sp'))
        assert (stack_pointer + (8 if witness == 'r12' else 0)) % 16 == 0, 'fixture call violates ABI stack alignment'
    if name == "cf_checkpoint" and not checkpoint:
        gdb.execute("set debug frame 1")
        gdb.execute("maintenance flush register-cache")
        stack = frames()
        # The fixture oracle ends at its explicitly unsupported _start;
        # never ask GDB to speculate beyond that captured boundary.
        gdb.execute("bt " + str(len(stack)))
        gdb.execute("set debug frame 0")
        depth = 3 if profile == "shrinkwrap" else 4
        expected_witnesses = ([0x5101, 0x5101, 0x5102, 0x5103, 0x6172] if profile == "shrinkwrap" else
            [0x5100, 0x5100, 0x5101, 0x5102, 0x5103, 0x6172])
        complete = ([row["name"] for row in stack] == ["cf_checkpoint"] + ["cf_recurse"] * depth + ["_start"] and
                    [row["witness"] for row in stack] == expected_witnesses)
        if uses_cfi:
            assert complete, stack
        checkpoint = True
        gdb.execute("finish")
        assert gdb.newest_frame().name() == "cf_recurse"
    elif name == "_start":
        assert checkpoint
        break
    else:
        if uses_cfi:
            assert name in ("cf_recurse", "cf_checkpoint") and stack[-1]["name"] == "_start", stack
        gdb.execute("stepi")
else:
    raise AssertionError("instruction trace exceeded fixture bounds")
shape_evidence = {}
if profile == "shrinkwrap":
    labels = ("cf_entry_branch", "cf_saved", "cf_allocated", "cf_restored", "cf_fast_return")
    if os.environ["FORGE_FRAME_TARGET"] == "aarch64":
        labels += ("cf_return_saved",)
    addresses = {name: int(gdb.parse_and_eval("&" + name)) for name in labels}
    pcs = [stack[0]["pc"] for stack in trace]
    visits = {name: pcs.count(address) for name, address in addresses.items()}
    assert visits["cf_entry_branch"] == visits["cf_fast_return"] == 4, visits
    assert all(visits[name] == 3 for name in labels if name not in ("cf_entry_branch", "cf_fast_return", "cf_restored")), visits
    # Restored and fast-return labels intentionally share the common return.
    assert visits["cf_restored"] == 4
    direct = sum(left == addresses["cf_entry_branch"] and right == addresses["cf_fast_return"]
        for left, right in zip(pcs, pcs[1:]))
    assert direct == 1, (visits, direct)
    shape_evidence = {"visits": visits, "directUnsavedReturnEdges": direct}
gdb.execute("continue")
assert int(gdb.parse_and_eval("$_exitcode")) == 0
Path(os.environ["FORGE_FRAME_RESULT"]).write_text(json.dumps({
    "trace": trace, "complete": complete, "exitcode": 0, "checkpointAddress": checkpoint_address,
    "profile": profile, "shapeEvidence": shape_evidence,
    "moduleBias": module_bias,
}, indent=4) + "\n")
print("cfi-encoder-gdb=" + mode + " PASS")
