"""Observe compiler call-site behavior; assertions are in the parent harness."""
import json
import os
from pathlib import Path

import gdb


def value(expression):
    try:
        result = gdb.parse_and_eval(expression)
        if result.is_optimized_out:
            return {"available": False, "text": str(result)}
        return {"available": True, "value": int(result)}
    except gdb.error as error:
        return {"available": False, "text": str(error)}


remote = os.environ.get("FORGE_CALL_SITE_REMOTE")
if remote:
    gdb.execute("set sysroot /usr/aarch64-linux-gnu")
    gdb.execute("target remote " + remote)
gdb.Breakpoint("*cs_checkpoint", temporary=True, internal=True)
gdb.execute("continue" if remote else "run " + os.environ["FORGE_CALL_SITE_SCENARIO"])
assert gdb.newest_frame().name() == "cs_checkpoint"
backtrace = gdb.execute("bt", to_string=True)
frames = []
frame = gdb.newest_frame()
while frame is not None and len(frames) < 32:
    frame.select()
    record = {
        "name": frame.name(), "pc": hex(frame.pc()),
        "tail": frame.type() == gdb.TAILCALL_FRAME,
        "info": gdb.execute("info frame", to_string=True),
    }
    if frame.name() not in ("cs_checkpoint", "cs_driver", "main"):
        record["value"] = value("value")
        record["entryValue"] = value("value@entry")
    if frame.name() in (os.environ.get("FORGE_CALL_SITE_RECURSIVE_NAME", "cs_recursive"), "cs_tail_recursive"):
        record["depth"] = value("depth")
        record["entryDepth"] = value("depth@entry")
    frames.append(record)
    if frame.name() == "main":
        break
    frame = frame.older()
assert frames[-1]["name"] == "main", frames
sink = int(gdb.parse_and_eval("*(int *)&cs_sink"))
driver = int(gdb.parse_and_eval("(void *)&cs_driver"))
gdb.newest_frame().select()
gdb.execute("continue")
exit_code = int(gdb.parse_and_eval("$_exitcode"))
assert exit_code == 0, exit_code
Path(os.environ["FORGE_CALL_SITE_RESULT"]).write_text(json.dumps({
    "status": "OBSERVED", "frames": frames, "backtrace": backtrace,
    "sink": sink, "driverAddress": hex(driver), "exitCode": exit_code,
    "gdbVersion": gdb.VERSION,
}, indent=4) + "\n")
