"""Actual incoming values and reported register lifetimes, without injected calls."""
import json
import os
from pathlib import Path

import gdb

case = Path(os.environ["FORGE_DYNAMIC_CASE"])
variant = os.environ["FORGE_DYNAMIC_VARIANT"]
compiler = variant == "compiler"
labels = json.loads((case / "labels.json").read_text())
prep = json.loads((case / "effective-storage.json").read_text())
report = json.loads((case / "export-report.json").read_text())
result = {"status": "STARTED", "variant": variant, "functions": []}
functions = ("dynamic_keep", "dynamic_change")
arguments = ((-19, 37), (-11, 5))


def integer(expression):
    return int(gdb.parse_and_eval(expression))


def parameter(name):
    value = gdb.parse_and_eval(name)
    assert str(value.type) == "int", str(value.type)
    if value.is_optimized_out:
        return {"type": "int", "available": False}
    # Missing memory, unsupported expressions and other read errors are failures.
    return {"type": "int", "available": True, "value": int(value)}


def inside(pc, function):
    return any(int(start, 16) <= pc < int(end, 16) for start, end in function["ranges"])


def observe(function, expected):
    pc = integer("$pc")
    row = {"pc": pc, "parameters": {}}
    for name, wanted in zip(("first", "second"), expected):
        value = parameter(name)
        omitted = [entry for entry in report["omittedLocations"] if
                   entry["function"] == function["name"] and entry["variable"] == name and
                   int(entry["startAddress"], 16) <= pc < int(entry["endAddress"], 16)]
        assert len(omitted) <= 1, omitted
        if omitted:
            assert omitted[0]["kind"] == "PARAMETER" and omitted[0]["reason"] != "UNASSIGNED"
            assert not value["available"], (function["name"], pc, name, omitted, value)
            value["omission"] = omitted[0]
        else:
            assert value["available"] and value["value"] == wanted, (function["name"], pc, name, value)
        row["parameters"][name] = value
    return row


try:
    assert variant in ("compiler", "forge")
    entries = [gdb.Breakpoint("*" + hex(labels[name]["address"])) for name in functions]
    source_stops = [gdb.Breakpoint(name) for name in functions] if compiler else []
    if compiler:
        for name, breakpoint in zip(functions, source_stops):
            locations = list(breakpoint.locations)
            assert len(locations) == 1
            address = locations[0].address
            assert labels[name]["address"] < address < labels[name]["address"] + labels[name]["size"], address
    for name in functions:
        chosen = name if compiler else "curated_" + name
        symbol = gdb.lookup_global_symbol(chosen) if compiler else gdb.lookup_static_symbol(chosen)
        assert symbol is not None and symbol.symtab is not None
        source = Path(symbol.symtab.fullname()).resolve()
        assert source == (Path(labels["compilerSource"]) if compiler else case / "dynamic.dbg.c")
        signature = gdb.execute("ptype " + chosen, to_string=True)
        assert signature == ("type = void (int, int)\n" if name == "dynamic_keep" else "type = int (int, int)\n"), signature
        assert chosen in gdb.execute("list " + chosen, to_string=True)
    remote = os.environ.get("FORGE_DYNAMIC_REMOTE", "")
    if remote:
        gdb.execute("target remote " + remote)
    for index, (name, expected) in enumerate(zip(functions, arguments)):
        gdb.execute("continue" if remote or index else "run")
        function = prep["functions"][index]
        assert integer("$pc") == labels[name]["address"] == int(function["entry"], 16)
        entries[index].delete()
        raw = {}
        for item, wanted in zip(function["parameters"], expected):
            register = item["register"].lower()
            value = integer("$" + register) & 0xffffffff
            assert value == wanted & 0xffffffff, (register, value, wanted)
            raw[register] = value
        row = {"name": name, "entryPc": integer("$pc"), "incomingRegisterBits": raw}
        result["functions"].append(row)
        if compiler:
            # The compiler's stack homes are meaningful only after its prologue.
            gdb.execute("continue")
            source_stops[index].delete()
            assert gdb.newest_frame().name() == name
            row["postProloguePc"] = integer("$pc")
            row["parameters"] = {key: parameter(key) for key in ("first", "second")}
            for key, wanted in zip(("first", "second"), expected):
                assert row["parameters"][key] == {"type": "int", "available": True, "value": wanted}
            gdb.execute("finish")
        else:
            row["states"] = []
            for step in range(256):
                if not inside(integer("$pc"), function):
                    break
                state = observe(function, expected)
                row["states"].append(state)
                if step == 0 and name == "dynamic_keep":
                    assert all(item["available"] for item in state["parameters"].values()), state
                gdb.execute("stepi")
            else:
                raise AssertionError("bounded leaf did not return")
            assert row["states"] and not inside(integer("$pc"), function)
        globals_expected = (("dynamic_first", -19), ("dynamic_second", 37)) if index == 0 else (
            ("dynamic_before", -11), ("dynamic_after", -6))
        row["globalsAfterReturn"] = {key: integer(key) for key, _ in globals_expected}
        assert all(row["globalsAfterReturn"][key] == wanted for key, wanted in globals_expected)
    gdb.execute("continue")
    result["exitCode"] = integer("$_exitcode")
    assert result["exitCode"] == 0
    result["status"] = "PASS"
    print("dynamic-parameter-storage-gdb=" + variant + " PASS")
except BaseException as error:
    result["status"] = "FAIL"
    result["error"] = repr(error)
    raise
finally:
    (case / (variant + "-gdb.json")).write_text(json.dumps(result, indent=4) + "\n")
