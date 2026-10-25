"""Real aggregate members and scalar values at actual PCs; no injected calls."""
import json
import os
from pathlib import Path

import gdb

case = Path(os.environ["FORGE_COMPOSITE_CASE"])
target = os.environ["FORGE_COMPOSITE_TARGET"]
variant = os.environ["FORGE_COMPOSITE_VARIANT"]
compiler = variant == "compiler"
prefix = "custom-" if variant == "custom" else ""
labels = json.loads((case / "labels.json").read_text())
prep = json.loads((case / (prefix + "effective-storage.json")).read_text())
report = json.loads((case / (prefix + "export-report.json")).read_text())
functions = ("capture_pair", "capture_scalar")
wide = 0x1122334455667788
result = {"status": "STARTED", "variant": variant, "target": target, "functions": [], "exitCodes": []}
gdb.events.exited.connect(lambda event: result["exitCodes"].append(getattr(event, "exit_code", None)))


def number(expression):
    return int(gdb.parse_and_eval(expression))


def inside(pc, function):
    return any(int(start, 16) <= pc < int(end, 16) for start, end in function["ranges"])


def observe(function, aggregate, omissions):
    pc = number("$pc")
    value = gdb.selected_frame().read_var("value")
    row = {"pc": pc, "type": str(value.type), "bytes": value.type.sizeof, "available": not value.is_optimized_out}
    assert value.type.sizeof == 8, row
    assert value.type.strip_typedefs().code == (gdb.TYPE_CODE_STRUCT if aggregate else gdb.TYPE_CODE_INT), row
    omitted = [item for item in report["omittedLocations"] if omissions and
        item["function"] == function["name"] and item["variable"] == "value" and
        int(item["startAddress"], 16) <= pc < int(item["endAddress"], 16)]
    assert len(omitted) <= 1, omitted
    if omitted:
        assert omitted[0]["kind"] == "PARAMETER" and omitted[0]["reason"] != "UNASSIGNED"
        assert value.is_optimized_out, row
        row["omission"] = omitted[0]
    else:
        assert not value.is_optimized_out, row
        if aggregate:
            row["fields"] = {name: {"type": str(value[name].type), "bytes": value[name].type.sizeof,
                "value": int(value[name])} for name in ("first", "second")}
            assert row["fields"] == {"first": {"type": "int", "bytes": 4, "value": -19},
                "second": {"type": "int", "bytes": 4, "value": 37}}, row
        else:
            row["value"] = int(value)
            assert row["value"] == wide and int(gdb.Value(-1).cast(value.type)) == (1 << 64) - 1, row
    return row


def incoming(aggregate):
    names = {"x86_64": ("rdi",), "aarch64": ("x0",), "arm32": ("r0", "r1"),
        "mips32be": ("a0", "a1"), "mips32le": ("a0", "a1")}[target]
    rows = []
    for name in names:
        value = gdb.parse_and_eval("$" + name)
        bits = value.type.sizeof * 8
        rows.append({"register": name, "bits": bits, "value": int(value) & ((1 << bits) - 1)})
    if len(rows) == 1:
        expected = [((37 << 32) | (-19 & 0xffffffff)) if aggregate else wide]
    elif aggregate:
        expected = [-19 & 0xffffffff, 37]
    elif target == "mips32be":
        expected = [wide >> 32, wide & 0xffffffff]
    else:
        expected = [wide & 0xffffffff, wide >> 32]
    assert [row["value"] for row in rows] == expected, rows
    return rows


try:
    assert variant in ("compiler", "forge", "custom")
    entries = [gdb.Breakpoint("*" + hex(labels[name]["address"])) for name in functions]
    named = [gdb.Breakpoint(name) for name in functions] if compiler else []
    for index, name in enumerate(functions):
        chosen = name if compiler else "curated_" + name
        symbol = gdb.lookup_global_symbol(chosen) if compiler else gdb.lookup_static_symbol(chosen)
        assert symbol is not None and symbol.symtab is not None
        expected_source = Path(labels["compilerSources"][name]) if compiler else case / ("custom.composite.dbg.c" if variant == "custom" else "composite.dbg.c")
        assert Path(symbol.symtab.fullname()).resolve() == expected_source.resolve()
        signature = gdb.execute("ptype " + chosen, to_string=True)
        assert signature.startswith("type = void (") and chosen in gdb.execute("list " + chosen, to_string=True)
        if compiler:
            locations = list(named[index].locations)
            assert len(locations) == 1
            start = labels[name]["address"]
            assert start <= locations[0].address < start + labels[name]["size"]
            if index == 0:
                assert locations[0].address > start  # Aggregate O0 stack home needs its prologue.
    remote = os.environ.get("FORGE_COMPOSITE_REMOTE", "")
    if remote:
        gdb.execute("target remote " + remote)
    for index, name in enumerate(functions):
        gdb.execute("continue" if remote or index else "run")
        function = prep["functions"][index]
        entry = labels[name]["address"]
        assert number("$pc") == entry == int(function["entry"], 16)
        row = {"name": name, "entryPc": entry, "incoming": incoming(index == 0)}
        result["functions"].append(row)
        entries[index].delete()
        if compiler:
            source_pc = list(named[index].locations)[0].address
            if source_pc != entry:
                gdb.execute("continue")
            assert number("$pc") == source_pc
            row["sourceStop"] = observe(function, index == 0, False)
            named[index].delete()
            gdb.execute("finish")
        else:
            row["states"] = []
            for step in range(256):
                if not inside(number("$pc"), function):
                    break
                state = observe(function, index == 0, True)
                row["states"].append(state)
                if step == 0:
                    expected_available = not (index == 1 and target in ("mips32be", "mips32le"))
                    assert state["available"] == expected_available, state
                if index == 1 and target in ("mips32be", "mips32le"):
                    assert not state["available"] and state["omission"]["reason"] == "REGISTER_MODIFIED", state
                    assert [int(state["omission"][key], 16) for key in ("startAddress", "endAddress")] == [
                        int(bound, 16) for bound in function["ranges"][0]], state
                gdb.execute("stepi")
            else:
                raise AssertionError("bounded ordinary leaf did not return")
            assert row["states"]
        row["returnPc"] = number("$pc")
        expected_globals = {"observed_first": -19, "observed_second": 37} if index == 0 else {"observed_scalar": wide}
        row["globalsAfterReturn"] = {key: number(key) for key in expected_globals}
        assert row["globalsAfterReturn"] == expected_globals
    gdb.execute("continue")
    assert result["exitCodes"] == [0], result["exitCodes"]
    result["status"] = "PASS"
    print("dynamic-composite-storage-gdb=" + variant + " PASS")
except BaseException as failure:
    result.update(status="FAIL", error=repr(failure))
    raise
finally:
    (case / (variant + "-gdb.json")).write_text(json.dumps(result, indent=4) + "\n")
