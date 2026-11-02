"""Actual incoming carriers and typed observed lifetimes, without injected calls."""
import json
import os
from pathlib import Path

import gdb

case = Path(os.environ["FORGE_MIPS_CASE"])
variant = os.environ["FORGE_MIPS_VARIANT"]
compiler = variant == "compiler"
fixture = json.loads((case / "fixture.json").read_text())
labels = json.loads((case / "labels.json").read_text())
prep = json.loads((case / "effective-storage.json").read_text())
report = json.loads((case / "export-report.json").read_text())
wide_prefix = None if fixture["abi"] == "n32" else json.loads((case / "wide-prefix-proof.json").read_text())
n32 = fixture["abi"] == "n32"
functions = ("capture_wide", "capture_args")
parameters = ((('value', 0x1122334455667788, 8),), tuple(zip(
    ("first", "second", "third", "fourth", "fifth", "sixth"), (-19, 7, 11, 13, -37, 41), (4,) * 6)))
result = {"status": "STARTED", "variant": variant, "functions": [], "exitCodes": []}
gdb.events.exited.connect(lambda event: result["exitCodes"].append(getattr(event, "exit_code", None)))


def number(expression):
    return int(gdb.parse_and_eval(expression))


def register(name):
    value = gdb.parse_and_eval("$" + name)
    bits = value.type.sizeof * 8
    return {"name": name, "bits": bits, "value": int(value) & ((1 << bits) - 1)}


def inside(pc, function):
    return any(int(start, 16) <= pc < int(end, 16) for start, end in function["ranges"])


def typed(name, expected, size, function=None):
    value = gdb.selected_frame().read_var(name)
    assert value.type.sizeof == size and value.type.strip_typedefs().code == gdb.TYPE_CODE_INT
    row = {"name": name, "type": str(value.type), "bytes": value.type.sizeof, "available": not value.is_optimized_out}
    omitted = [] if function is None else [o for o in report["omittedLocations"] if
        o["function"] == function["name"] and o["variable"] == name and
        int(o["startAddress"], 16) <= number("$pc") < int(o["endAddress"], 16)]
    assert len(omitted) <= 1
    if omitted:
        assert omitted[0]["kind"] == "PARAMETER" and omitted[0]["reason"] != "UNASSIGNED"
        assert not row["available"], (function["name"], name, hex(number("$pc")), row, omitted)
        row["omission"] = omitted[0]
    else:
        assert row["available"], (name, hex(number("$pc")), row)
        row["value"] = int(value)
        assert row["value"] == expected, (name, hex(number("$pc")), row, expected)
    return row


try:
    assert variant in ("compiler", "forge")
    compiler_facts = None if compiler else json.loads((case / "compiler-gdb.json").read_text())
    if compiler_facts is not None:
        assert compiler_facts["status"] == "PASS"
    for name in functions:
        chosen = name if compiler else "curated_" + name
        symbol = gdb.lookup_global_symbol(chosen) if compiler else gdb.lookup_static_symbol(chosen)
        assert symbol is not None and symbol.type.code == gdb.TYPE_CODE_FUNC and symbol.symtab is not None
        assert Path(symbol.symtab.fullname()).resolve() == (Path(labels["compilerSource"]) if compiler else case / "abi.dbg.c")
        signature = gdb.execute("ptype " + chosen, to_string=True)
        assert "void (" in signature, signature
        assert chosen in gdb.execute("list " + chosen, to_string=True)
    gdb.execute("target remote " + os.environ["FORGE_MIPS_REMOTE"])
    result["architecture"] = gdb.selected_frame().architecture().name()
    for index, (name, wanted) in enumerate(zip(functions, parameters)):
        function = prep["functions"][index]
        entry = labels[name]["address"]
        exact = gdb.Breakpoint("*" + hex(entry))
        named = gdb.Breakpoint(name) if compiler else None
        if compiler:
            locations = list(named.locations)
            assert len(locations) == 1
            later = locations[0].address
            assert entry < later < entry + labels[name]["size"]
        else:
            later = compiler_facts["functions"][index]["postProloguePc"]
        gdb.execute("continue")
        assert number("$pc") == entry == int(function["entry"], 16)
        raw = [register("a" + str(i)) for i in range(4)]
        row = {"name": name, "entryPc": entry, "incoming": raw,
            "registerDump": gdb.execute("info registers", to_string=True)}
        result["functions"].append(row)
        if name == "capture_wide":
            if n32:
                assert raw[0]["bits"] == 64 and raw[0]["value"] == 0x1122334455667788, raw
            else:
                expected = [0x11223344, 0x55667788] if fixture["endian"] == "be" else [0x55667788, 0x11223344]
                assert [r["value"] for r in raw[:2]] == expected, raw
        else:
            assert [r["value"] & 0xffffffff for r in raw] == [v & 0xffffffff for v in (-19, 7, 11, 13)]
            if n32:
                row["extraIncoming"] = [register("a4"), register("a5")]
                assert [r["value"] & 0xffffffff for r in row["extraIncoming"]] == [(-37) & 0xffffffff, 41]
            else:
                sp = number("$sp")
                data = bytes(gdb.selected_inferior().read_memory(sp + 16, 8))
                values = [int.from_bytes(data[i:i + 4], "big" if fixture["endian"] == "be" else "little", signed=True) for i in (0, 4)]
                row["stackIncoming"] = {"sp": sp, "offsets": [16, 20], "bytes": data.hex(), "values": values}
                assert values == [-37, 41]
        exact.delete()
        if compiler:
            gdb.execute("continue")
            assert number("$pc") == later
            row["postProloguePc"] = later
            row["parameters"] = [typed(*item) for item in wanted]
            named.delete()
            gdb.execute("finish")
        else:
            assert raw == compiler_facts["functions"][index]["incoming"]
            row["states"] = []
            for step in range(256):
                pc = number("$pc")
                if not inside(pc, function):
                    break
                state = {"pc": pc, "parameters": [typed(*item, function) for item in wanted]}
                row["states"].append(state)
                if step == 0:
                    assert all(p["available"] for p in state["parameters"]), state
                if not n32 and name == "capture_wide":
                    assert state["parameters"][0]["available"] == (entry <= pc < wide_prefix["end"]), state
                gdb.execute("stepi")
            else:
                raise AssertionError("bounded leaf did not return")
            assert row["states"] and not inside(number("$pc"), function)
            assert any(state["pc"] == later for state in row["states"]), later
        row["returnPc"] = number("$pc")
        globals_expected = {"observed_wide": 0x1122334455667788} if index == 0 else {
            "observed_first": -19, "observed_fifth": -37, "observed_sixth": 41, "observed_sum": 16}
        row["globalsAfterReturn"] = {key: number(key) for key in globals_expected}
        assert row["globalsAfterReturn"] == globals_expected
    gdb.execute("continue")
    assert result["exitCodes"] == [0]
    result["status"] = "PASS"
    print("mips-truncated-space-gdb=" + variant + " PASS")
except BaseException as error:
    result["status"] = "FAIL"
    result["error"] = repr(error)
    raise
finally:
    (case / (variant + "-gdb.json")).write_text(json.dumps(result, indent=4) + "\n")
