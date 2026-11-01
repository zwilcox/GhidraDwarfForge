"""Independent assembly-known ARM/Thumb transitions and instruction values."""
import json
import os
from pathlib import Path
import re
import gdb

case = Path(os.environ["FORGE_MIXED_CASE"])
variant = os.environ["FORGE_MIXED_VARIANT"]
labels = json.loads((case / "labels.json").read_text())
start = labels["start"]
name = "mixed_body" if variant == "compiler" else "recovered_mixed_body"
result = {"status": "FAILED", "variant": variant, "observations": []}
try:
    assert str(gdb.parameter("arm force-mode")) == "auto"
    assert str(gdb.parameter("arm fallback-mode")) == "auto"
    assert int(gdb.parse_and_eval("&" + name)) == start
    arch = gdb.selected_inferior().architecture()
    result["static"] = arch.disassemble(start, start + 43)
    expected_offsets = [0, 4, 8, 12, 16, 18, 20, 22, 24, 28, 32, 36, 40]
    expected_lengths = [4, 4, 4, 4, 2, 2, 2, 2, 4, 4, 4, 4, 4]
    result["staticWidthsMatch"] = [(r["addr"] - start, r["length"]) for r in result["static"]] == list(
        zip(expected_offsets, expected_lengths))
    if variant != "compiler":
        reference = json.loads((case / "compiler-gdb.json").read_text())
        def decoded(rows):
            return [(row["addr"], row["length"], re.sub(r"\s*<[^>]*>", "", row["asm"])) for row in rows]
        result["staticMatchesCompiler"] = decoded(result["static"]) == decoded(reference["static"])
    gdb.execute("target remote " + os.environ["FORGE_MIXED_REMOTE"])
    stop = gdb.Breakpoint(name)
    gdb.execute("continue")
    assert int(gdb.parse_and_eval("$pc")) == start
    stop.delete()
    # Source-known values before each instruction; mappings cannot supply these.
    values = [11, 14, 14, 14, 14, 19, 19, 19, 19, 26, 26, 4686]
    for offset, width, value in zip(expected_offsets[:-1], expected_lengths[:-1], values):
        pc = int(gdb.parse_and_eval("$pc"))
        r0 = int(gdb.parse_and_eval("$r0"))
        thumb = bool(int(gdb.parse_and_eval("$cpsr")) & 32)
        actual_bytes = bytes(gdb.selected_inferior().read_memory(pc, width)).hex()
        assert pc == start + offset and r0 == value
        assert thumb == (16 <= offset < 24)
        assert actual_bytes == labels["hex"][offset * 2:(offset + width) * 2]
        result["observations"].append({"pc": pc, "offset": offset, "r0": r0,
            "thumb": thumb, "bytes": actual_bytes,
            "instruction": arch.disassemble(pc, count=1)})
        gdb.execute("stepi")
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
    (case / (variant + "-gdb.json")).write_text(json.dumps(result, indent=4) + "\n")
