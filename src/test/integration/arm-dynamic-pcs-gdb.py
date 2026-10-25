"""Compiler-relative dynamic PCS entry values; no injected calls or return ABI inference."""
import gdb
import json
import os
from pathlib import Path
import re
import struct

case = Path(os.environ["FORGE_PCS_CASE"])
variant = os.environ["FORGE_PCS_VARIANT"]
labels = json.loads((case / "labels.json").read_text())
result = {"status": "STARTED", "variant": variant, "functions": []}
functions = ("base_probe", "vfp_probe", "vfp_sum")
arguments = ((1.25, 2.5), (3.25, 4.5), (6.25, 7.5))


def number(expression):
    return int(gdb.parse_and_eval(expression))


def parameter(name):
    value = gdb.parse_and_eval(name)
    available = not value.is_optimized_out
    return {"type": str(value.type), "available": available,
            "value": float(value) if available else None}


try:
    entries = [gdb.Breakpoint("*" + hex(labels[name]["raw"])) for name in functions]
    source_stops = [gdb.Breakpoint(name) for name in functions] if variant == "compiler" else []
    for index, name in enumerate(functions):
        chosen = name if variant == "compiler" else "curated_" + name
        symbol = (gdb.lookup_global_symbol(chosen) if variant == "compiler"
                  else gdb.lookup_static_symbol(chosen))
        assert symbol is not None and symbol.symtab is not None, chosen
        source = Path(symbol.symtab.fullname()).resolve()
        expected_source = Path(labels["compilerSource"]) if variant == "compiler" else case / "pcs.dbg.c"
        assert source == expected_source, (source, expected_source)
        text = gdb.execute("ptype " + chosen, to_string=True)
        assert "float, float" in text, text
        result[chosen + "Type"] = text
        result[chosen + "Source"] = str(source)
        listing = gdb.execute("list " + chosen, to_string=True)
        assert chosen in listing, listing
    gdb.execute("target remote " + os.environ["FORGE_PCS_REMOTE"])
    for index, (name, expected) in enumerate(zip(functions, arguments)):
        gdb.execute("continue")
        assert number("$pc") == labels[name]["raw"] and not number("$cpsr") & 32
        entries[index].delete()
        raw = {"r0": number("$r0"), "r1": number("$r1"),
               "s0": float(gdb.parse_and_eval("$s0")), "s1": float(gdb.parse_and_eval("$s1"))}
        if name == "base_probe":
            assert (raw["r0"], raw["r1"]) == tuple(struct.unpack("<I", struct.pack("<f", x))[0] for x in expected)
        else:
            assert (raw["s0"], raw["s1"]) == expected, raw
        row = {"function": name, "entry": number("$pc"), "raw": raw}
        result["functions"].append(row)
        if variant == "compiler":
            # Compiler DWARF uses stack slots initialized by the prologue, not entry carriers.
            gdb.execute("continue")
            source_stops[index].delete()
            assert gdb.newest_frame().name() == name
        row["parameterPc"] = number("$pc")
        row["parameters"] = {key: parameter(key) for key in ("first", "second")}
        for key, value in zip(("first", "second"), expected):
            observation = row["parameters"][key]
            assert observation["type"] == "float", observation
            assert observation["available"] and observation["value"] == value, observation
        if name == "vfp_sum":
            code = labels[name]
            writes = [item for item in gdb.selected_inferior().architecture().disassemble(
                code["raw"], code["raw"] + code["size"] - 1)
                if re.fullmatch(r"vmov\.f32\s+s0,\s*s15", item["asm"])]
            assert len(writes) == 1 and writes[0]["length"] == 4, writes
            pc = writes[0]["addr"]
            boundary = gdb.Breakpoint("*" + hex(pc))
            assert number("$pc") < pc
            gdb.execute("continue")
            assert number("$pc") == pc
            assert all(parameter(key)["available"] and parameter(key)["value"] == value
                for key, value in zip(("first", "second"), expected))
            gdb.execute("stepi")
            assert number("$pc") == pc + 4 and float(gdb.parse_and_eval("$s0")) == sum(expected)
            tail = {key: parameter(key) for key in ("first", "second")}
            for key, value in zip(("first", "second"), expected):
                assert tail[key]["available"] == (variant == "compiler"), tail
                if variant == "compiler":
                    assert tail[key]["value"] == value
            row["lifetime"] = {"write": pc, "end": pc + 4, "tail": tail}
            boundary.delete()
    gdb.execute("continue")
    result["exitCode"] = number("$_exitcode")
    assert result["exitCode"] == 0
    result["status"] = "PASS"
    print("arm-dynamic-pcs-gdb=" + variant + " PASS")
except BaseException as error:
    result["status"] = "FAIL"
    result["error"] = repr(error)
    raise
finally:
    (case / (variant + ".json")).write_text(json.dumps(result, indent=4) + "\n")
