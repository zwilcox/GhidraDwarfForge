"""Default-mode static and QEMU behavior oracle for mixed ARM/Thumb executables."""
import json
import os
from pathlib import Path
import re

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


def instructions(original, offset=0):
    row = labels[original]
    return [{"address": item["addr"] - offset, "length": item["length"],
             "mnemonic": item["asm"].split()[0]}
            for item in gdb.selected_inferior().architecture().disassemble(
                row["code"] + offset, row["code"] + offset + row["codeSize"] - 1)]


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
    assert entry <= row["pc"] < entry + labels["thumb_add"]["codeSize"], row
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
    sectionless = labels.get("sectionless", False)
    inspection_bias = 0
    if sectionless:
        # No .ARM.attributes survives. This explicit fixture architecture is
        # independent of the exporter and leaves instruction mode on auto.
        gdb.execute("set architecture armv7")
        gdb.execute("target remote " + os.environ["FORGE_THUMB_REMOTE"])
        inspection_bias = integer("&main") - labels["main"]["code"]
    result["instructionSource"] = "remote-before-continue" if sectionless else "file-before-attach"
    result["static"] = {function: instructions(function, inspection_bias)
                        for function in ("arm_call", "main", "thumb_add", "arm_after")}
    # GCC st_size includes literal pools. Compare actual instructions only,
    # bounded independently by compiler $d mapping symbols. Data disassembly
    # is a consumer observation, not evidence of executable instruction mode.
    result["literalPoolDecoding"] = {function: gdb.selected_inferior().architecture().disassemble(
        row["code"] + inspection_bias + row["codeSize"], row["code"] + inspection_bias + row["size"] - 1)
        for function, row in labels.items() if isinstance(row, dict)
        and "codeSize" in row and row["codeSize"] < row["size"]}
    result["functionAddress"] = integer("&" + name("thumb_add")) - inspection_bias
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
    if labels["role"] == "pie-dynamic":
        result["originalLookup"] = {original: integer("&" + original) - inspection_bias
            for original in ("arm_call", "thumb_add", "arm_after", "thumb_sink", "thumb_pointer")}
        if not compiler:
            assert result["originalLookup"] == oracle["originalLookup"], "inherited dynamic lookup changed"
    for function, rows in result["static"].items():
        cursor = labels[function]["code"]
        for row in rows:
            assert row["address"] == cursor, rows
            assert row["length"] in ((2, 4) if function == "thumb_add" else (4,)), row
            cursor += row["length"]
        assert cursor == labels[function]["code"] + labels[function]["codeSize"], rows
    assert labels["thumb_add"]["code"] + labels["thumb_add"]["size"] == labels["arm_after"]["code"]
    result["upperBound"] = gdb.execute("x/2i " + hex(labels["arm_after"]["code"] + inspection_bias), to_string=True)
    thumb = labels["thumb_add"]
    writes = [row for row in gdb.selected_inferior().architecture().disassemble(
        thumb["code"] + inspection_bias, thumb["code"] + inspection_bias + thumb["codeSize"] - 1)
        if re.fullmatch(r"mov\s+r0,\s*r3", row["asm"])]
    assert len(writes) == 1 and writes[0]["length"] == 2, writes
    write_pc = writes[0]["addr"] - inspection_bias

    if not sectionless:
        gdb.execute("target remote " + os.environ["FORGE_THUMB_REMOTE"])
    bias = integer("&main") - labels["main"]["code"]
    assert (bias != 0) == labels["role"].startswith("pie"), bias
    result["loadBias"] = bias
    for function in ("arm_call", "main", "thumb_add", "arm_after"):
        labels[function]["code"] += bias
        labels[function]["raw"] += bias
    write_pc += bias
    if phase == "calls":
        breakpoint = gdb.Breakpoint(name("thumb_add"))
    else:
        breakpoint = gdb.Breakpoint("*" + hex(labels["arm_call"]["code"]))
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
            boundary = gdb.Breakpoint("*" + hex(write_pc))
            for step in range(12):
                if integer("thumb_sink") == total:
                    break
                gdb.execute("next")
                thumb_stop("next-" + str(call) + "-" + str(step))
            assert integer("thumb_sink") == total
            values["sink"] = total
            # The incoming r0 value is valid before the return-value move, then
            # Forge must stop describing it. Compiler DWARF retains a stack copy.
            assert integer("$pc") <= write_pc
            if integer("$pc") != write_pc:
                gdb.execute("continue")
            before = thumb_stop("before-register-write-" + str(call))
            assert before["pc"] == write_pc and integer("left") == left and integer("right") == right
            gdb.execute("stepi")
            after = thumb_stop("after-register-write-" + str(call))
            assert after["pc"] == write_pc + 2 and integer("$r0") == total and integer("right") == right
            value = gdb.parse_and_eval("left")
            assert bool(value.is_optimized_out) == (not compiler)
            if compiler:
                assert int(value) == left
            values["lifetime"] = {"write": write_pc, "end": write_pc + 2,
                                  "afterUnavailable": bool(value.is_optimized_out), "returnRegister": total}
            boundary.delete()
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
        assert result["thumbDecodedFromArm"] == [dict(row, address=row["address"] + bias)
            for row in result["static"]["thumb_add"]]
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
