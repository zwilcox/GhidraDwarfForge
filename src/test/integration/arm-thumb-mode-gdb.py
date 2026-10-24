"""Default-mode static and QEMU behavior oracle for the bounded mixed ET_EXEC."""
import json
import os
from pathlib import Path

import gdb

directory = Path(os.environ["FORGE_THUMB_CASE"])
variant = os.environ["FORGE_THUMB_VARIANT"]
phase = os.environ["FORGE_THUMB_PHASE"]
labels = json.loads((directory / "labels.json").read_text())
compiler = variant == "compiler"
result = {"variant": variant, "phase": phase, "status": "STARTED", "stops": []}


def name(original):
    return original if compiler or original == "main" else "recovered_" + original


def integer(expression):
    return int(gdb.parse_and_eval(expression))


def instructions(original):
    row = labels[original]
    return [{"address": item["addr"], "length": item["length"],
             "mnemonic": item["asm"].split()[0]}
            for item in gdb.selected_inferior().architecture().disassemble(
                row["code"], row["code"] + row["size"] - 1)]


def stop(label):
    frame = gdb.newest_frame()
    sal = frame.find_sal()
    row = {"label": label, "pc": integer("$pc"), "cpsr": integer("$cpsr"),
           "function": frame.name(), "line": sal.line,
           "source": None if sal.symtab is None else sal.symtab.fullname()}
    result["stops"].append(row)
    return row


def thumb_stop(label):
    row = stop(label)
    entry = labels["thumb_add"]["code"]
    assert entry <= row["pc"] < entry + labels["thumb_add"]["size"], row
    assert row["cpsr"] & 32 and row["function"] == name("thumb_add"), row
    expected_source = labels["compilerSource"] if compiler else str(directory / "thumb.dbg.c")
    assert row["source"] == expected_source and row["line"] > 0, row
    return row


def persist():
    (directory / (variant + "-" + phase + ".json")).write_text(json.dumps(result, indent=4) + "\n")


try:
    assert variant in ("compiler", "forge") and phase in ("calls", "from-arm")
    result["forceMode"] = gdb.execute("show arm force-mode", to_string=True)
    result["fallbackMode"] = gdb.execute("show arm fallback-mode", to_string=True)
    assert '"auto"' in result["forceMode"] and '"auto"' in result["fallbackMode"]
    result["static"] = {function: instructions(function)
                        for function in ("arm_call", "main", "thumb_add", "arm_after")}
    result["functionAddress"] = integer("&" + name("thumb_add"))
    result["storedPointer"] = integer("thumb_pointer")
    assert result["storedPointer"] == labels["thumb_add"]["raw"], result
    assert result["storedPointer"] & 1
    result["type"] = gdb.execute("ptype " + name("thumb_add"), to_string=True)
    assert result["type"] == "type = int (int, int)\n", result["type"]
    result["list"] = gdb.execute("list " + name("thumb_add"), to_string=True)
    if not compiler:
        oracle = json.loads((directory / ("compiler-" + phase + ".json")).read_text())
        assert oracle["status"] == "PASS"
        assert result["static"] == oracle["static"], "static ARM/Thumb decoding differs from compiler"
        assert result["functionAddress"] == oracle["functionAddress"], "GDB function address differs"
        assert result["storedPointer"] == oracle["storedPointer"]
    for function, rows in result["static"].items():
        cursor = labels[function]["code"]
        for row in rows:
            assert row["address"] == cursor, rows
            assert row["length"] in ((2, 4) if function == "thumb_add" else (4,)), row
            cursor += row["length"]
        assert cursor == labels[function]["code"] + labels[function]["size"], rows
    assert labels["thumb_add"]["code"] + labels["thumb_add"]["size"] == labels["arm_after"]["code"]
    result["upperBound"] = gdb.execute("x/2i " + hex(labels["arm_after"]["code"]), to_string=True)

    if phase == "calls":
        breakpoint = gdb.Breakpoint(name("thumb_add"))
    else:
        breakpoint = gdb.Breakpoint("*" + hex(labels["arm_call"]["code"]))
    gdb.execute("target remote " + os.environ["FORGE_THUMB_REMOTE"])
    if phase == "calls":
        result["values"] = []
        for call, (left, right, total) in enumerate(((12, 7, 19), (19, 3, 22))):
            gdb.execute("continue")
            thumb_stop("call-" + str(call))
            values = {}
            for parameter, expected in (("left", left), ("right", right)):
                try:
                    actual = integer(parameter)
                except gdb.error as unavailable:
                    assert not compiler, unavailable
                    values[parameter] = {"available": False, "diagnostic": str(unavailable)}
                else:
                    assert actual == expected, (parameter, actual, expected)
                    values[parameter] = {"available": True, "value": actual}
            for step in range(12):
                if integer("thumb_sink") == total:
                    break
                gdb.execute("next")
                thumb_stop("next-" + str(call) + "-" + str(step))
            assert integer("thumb_sink") == total
            values["sink"] = total
            result["values"].append(values)
            gdb.execute("finish")
            row = stop("return-" + str(call))
            assert row["function"] == name("arm_call") and not row["cpsr"] & 32, row
        breakpoint.delete()
    else:
        gdb.execute("continue")
        row = stop("arm-caller")
        assert row["pc"] == labels["arm_call"]["code"] and not row["cpsr"] & 32, row
        breakpoint.delete()
        result["thumbDecodedFromArm"] = instructions("thumb_add")
        assert result["thumbDecodedFromArm"] == result["static"]["thumb_add"]
        breakpoint = gdb.Breakpoint("*" + hex(labels["thumb_add"]["code"]))
        gdb.execute("continue")
        row = thumb_stop("entry-from-arm")
        assert row["pc"] == labels["thumb_add"]["code"], row
        result["entryStop"] = gdb.execute("info program", to_string=True)
        assert "It stopped at breakpoint" in result["entryStop"]
        gdb.execute("stepi")
        row = thumb_stop("first-instruction")
        assert row["pc"] == labels["thumb_add"]["code"] + result["static"]["thumb_add"][0]["length"]
        breakpoint.delete()
    gdb.execute("continue")
    result["exitCode"] = integer("$_exitcode")
    assert result["exitCode"] == 0
    result["status"] = "PASS"
    persist()
    print("arm-thumb-mode-gdb=" + variant + "/" + phase + " PASS")
except BaseException as failure:
    result["status"] = "FAIL"
    result["error"] = repr(failure)
    persist()
    raise
