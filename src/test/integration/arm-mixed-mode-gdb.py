"""Independent assembly-known ARM/Thumb transitions and instruction values."""
import json
import os
from pathlib import Path
import re
import gdb

case = Path(os.environ["FORGE_MIXED_CASE"])
variant = os.environ["FORGE_MIXED_VARIANT"]
phase = os.environ.get("FORGE_MIXED_PHASE", "instructions")
assert phase in ("instructions", "next", "step", "address", "calls")
labels = json.loads((case / "labels.json").read_text())
start = labels["start"]
name = "mixed_body" if variant == "compiler" else "recovered_mixed_body"
result = {"status": "FAILED", "variant": variant, "phase": phase, "observations": []}
try:
    assert str(gdb.parameter("arm force-mode")) == "auto"
    assert str(gdb.parameter("arm fallback-mode")) == "auto"
    assert int(gdb.parse_and_eval("&" + name)) == start
    sectionless = labels.get("sectionless", False)
    inspection_bias = 0
    if sectionless:
        gdb.execute("set architecture armv7")
        gdb.execute("target remote " + os.environ["FORGE_MIXED_REMOTE"])
        inspection_bias = int(gdb.parse_and_eval("&" + name)) - start
    arch = gdb.selected_inferior().architecture()
    result["static"] = arch.disassemble(start + inspection_bias, start + inspection_bias + 43)
    for row in result["static"]:
        row["addr"] -= inspection_bias
    result["instructionSource"] = "remote-before-continue" if sectionless else "file-before-attach"
    expected_offsets = [0, 4, 8, 12, 16, 18, 20, 22, 24, 28, 32, 36, 40]
    expected_lengths = [4, 4, 4, 4, 2, 2, 2, 2, 4, 4, 4, 4, 4]
    result["staticWidthsMatch"] = [(r["addr"] - start, r["length"]) for r in result["static"]] == list(
        zip(expected_offsets, expected_lengths))
    if variant != "compiler":
        reference = json.loads((case / "compiler-gdb.json").read_text())
        def decoded(rows):
            return [(row["addr"], row["length"], re.sub(r"\s*<[^>]*>", "", row["asm"])) for row in rows]
        result["staticMatchesCompiler"] = decoded(result["static"]) == decoded(reference["static"])
    if labels.get("shared", False):
        gdb.execute("file " + str(case / "mixed.driver"))
        gdb.execute("set solib-search-path " + str(case))
        gdb.execute("target remote " + os.environ["FORGE_MIXED_REMOTE"])
        driver_entry = gdb.Breakpoint("*main", internal=True)
        gdb.execute("continue")
        driver_entry.delete()
        libraries = gdb.execute("info sharedlibrary", to_string=True)
        line, = [row for row in libraries.splitlines() if row.split()[-1:] == [str(case / "mixed.stripped")]]
        runtime_text = int(line.split()[0], 16)
        bias = runtime_text - labels["textAddress"]
        assert bias > 0
        artifact = case / ("mixed.reference" if variant == "compiler" else variant + ".dbg")
        gdb.execute("add-symbol-file " + str(artifact) + " -o " + hex(bias))
        assert int(gdb.parse_and_eval("&" + name)) == start + bias
        result["sharedLoading"] = {"bias": bias, "runtimeText": runtime_text,
            "linkText": labels["textAddress"], "autoSolibAdd": False, "libraries": libraries,
            "loadCommand": "add-symbol-file", "retainsDriverEntry": True}
    else:
        if not sectionless:
            gdb.execute("target remote " + os.environ["FORGE_MIXED_REMOTE"])
        bias = int(gdb.parse_and_eval("&" + name)) - start
        assert (bias != 0) == labels.get("role", "exec").startswith("pie"), bias
    result["loadBias"] = bias
    start += bias
    stop = gdb.Breakpoint("*" + hex(start + 16) if phase == "address" else name)
    gdb.execute("continue")
    assert int(gdb.parse_and_eval("$pc")) == start + (16 if phase == "address" else 0)
    stop.delete()
    # Source-known values before each instruction; mappings cannot supply these.
    values = [11, 14, 14, 14, 14, 19, 19, 19, 19, 26, 26, 4686]
    if phase in ("next", "step"):
        result["listing"] = gdb.execute("list " + name, to_string=True)
        assert ("mixed_body:" if variant == "compiler" else "recovered_mixed_body") in result["listing"]
        assert "No such file" not in result["listing"]
        if variant != "compiler":
            result["type"] = gdb.execute("ptype " + name, to_string=True)
            assert "int (int)" in result["type"]
            result["parameter"] = gdb.execute("print value", to_string=True)
            assert "<optimized out>" in result["parameter"]
    if phase == "calls":
        result["pointerCall"] = int(gdb.parse_and_eval("((int (*)(int)) &" + name + ")(11)"))
        assert result["pointerCall"] == 4686
        assert int(gdb.parse_and_eval("$pc")) == start and int(gdb.parse_and_eval("$r0")) == 11
    visited = []
    for _ in range(16):
        pc = int(gdb.parse_and_eval("$pc"))
        if not start <= pc < start + 40:
            break
        offset = pc - start
        assert offset in expected_offsets[:-1]
        position = expected_offsets.index(offset)
        width, value = expected_lengths[position], values[position]
        r0 = int(gdb.parse_and_eval("$r0"))
        thumb = bool(int(gdb.parse_and_eval("$cpsr")) & 32)
        actual_bytes = bytes(gdb.selected_inferior().read_memory(pc, width)).hex()
        assert r0 == value
        assert thumb == (16 <= offset < 24)
        assert actual_bytes == labels["hex"][offset * 2:(offset + width) * 2]
        row = {"pc": pc, "offset": offset, "r0": r0, "thumb": thumb, "bytes": actual_bytes,
            "instruction": arch.disassemble(pc, count=1)}
        if phase in ("next", "step"):
            sal = gdb.selected_frame().find_sal()
            assert sal.symtab is not None and sal.line > 0
            row["source"] = {"path": sal.symtab.fullname(), "line": sal.line}
            if variant != "compiler":
                assert Path(sal.symtab.fullname()).resolve() == (case / "curated.dbg.c").resolve()
                text = Path(sal.symtab.fullname()).read_text().splitlines()[sal.line - 1].strip()
                assert text == "return value + 0x1243;" or (
                    offset == 0 and text == "int recovered_mixed_body(int value)"), text
        result["observations"].append(row)
        visited.append(offset)
        gdb.execute(phase if phase in ("next", "step") else "stepi")
    else:
        raise AssertionError("mixed function failed to make bounded stepping progress")
    if phase not in ("next", "step"):
        expected_visits = expected_offsets[4:-1] if phase == "address" else expected_offsets[:-1]
        assert visited == expected_visits
    result["returnedPc"] = int(gdb.parse_and_eval("$pc"))
    assert int(gdb.parse_and_eval("$r0")) == 4686
    assert bytes(gdb.selected_inferior().read_memory(start + 40, 4)).hex() == "34120000"
    exits = []
    gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
    gdb.execute("continue")
    assert exits == [0], exits
    result["exitCodes"] = exits
    assert result["staticWidthsMatch"], "mixed instruction widths differ before attachment"
    assert result.get("staticMatchesCompiler", True), "mixed static decoding differs from compiler"
    result["status"] = "PASS"
finally:
    (case / (variant + ("" if phase == "instructions" else "-" + phase) + "-gdb.json")).write_text(json.dumps(result, indent=4) + "\n")
