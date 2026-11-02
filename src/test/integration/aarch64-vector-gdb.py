"""Instruction-level lane values, full-width storage, clobber gaps and call rejection."""

import json
import os
from pathlib import Path
import struct
import gdb

case = Path(os.environ["FORGE_AARCH64_VECTOR_CASE"])
mode = os.environ["FORGE_AARCH64_VECTOR_MODE"]
failed = os.environ.get("FORGE_AARCH64_VECTOR_FAILED_FUNCTION")
assert mode in ("compiler", "forge") and (
    failed is None or mode == "forge" and failed == "vector_stack"
)
metadata = json.loads((case / "metadata.json").read_text())
locations = json.loads((case / "vector-locations.json").read_text()) if mode == "forge" else {}
gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set debuginfod enabled off")
gdb.execute("set auto-solib-add off")
gdb.execute("set sysroot /usr/aarch64-linux-gnu")
gdb.execute("file " + str(case / "abi.input"))
gdb.execute("symbol-file " + str(case / ("abi.reference" if mode == "compiler" else "abi.dbg")))
gdb.execute("target remote " + os.environ["FORGE_AARCH64_VECTOR_REMOTE"])
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, "exit_code", None)))
expected = {
    "vector_plain": [11, -22, 33, -44],
    "vector_copy": [101, -202, 303, -404],
    "vector_stack": [501, -602, 703, -804],
    "vector_alias": [1501, -1602, 1703, -1804],
    "vector_float": [1.25, -2.5, 3.75, -4.0],
    "vector_stack_arg": [901, -902, 903, -904],
}
rows = []
returns = {}
blocked_calls = []
entries = {}


def register(number):
    return bytes(gdb.selected_frame().read_register("v" + str(number - 64)).bytes)


def machine():
    return {
        "registers": {
            item.name: str(gdb.selected_frame().read_register(item.name))
            for item in gdb.selected_frame().architecture().registers()
        },
        "stack": bytes(
            gdb.selected_inferior().read_memory(int(gdb.parse_and_eval("$sp")), 256)
        ).hex(),
    }


for name, values in expected.items():
    stop = gdb.Breakpoint("*" + name, internal=True)
    gdb.execute("continue")
    stop.delete()
    entry = int(gdb.parse_and_eval("$pc"))
    entries[name] = entry
    bias = entry - metadata["symbols"][name]
    assert (bias == 0) == (metadata["role"] == "exec")
    entry_stack = int(gdb.parse_and_eval("$sp"))
    if name != failed:
        listing = gdb.execute("list " + name, to_string=True)
        assert name in listing and "No such file" not in listing
        signature = gdb.parse_and_eval(name).type
        dtype = signature.target().strip_typedefs()
        assert dtype.code == gdb.TYPE_CODE_ARRAY and dtype.sizeof == 16 and dtype.range() == (0, 3)
        assert dtype.target().sizeof == 4
        if mode == "forge":
            before = machine()
            try:
                argument = "{" + ",".join(str(value) for value in values) + "}"
                arguments = (
                    ",".join(["{1,2,3,4}"] * 8 + [argument])
                    if name == "vector_stack_arg"
                    else argument
                )
                gdb.parse_and_eval(name + "(" + arguments + ")")
                raise AssertionError("unsupported vector call was executed")
            except gdb.error as error:
                assert "does not follow the target calling convention" in str(error), str(error)
                assert machine() == before
                blocked_calls.append({"name": name, "error": str(error), "unchanged": True})
    available = memory = missing = zero_carriers = 0
    function_rows = []
    alias_retired = False
    for step in range(200):
        # GCC describes the always-inline clobber helper as a virtual frame.
        # Inspect the owning physical function's parameter at the same PC.
        frame = gdb.newest_frame()
        while frame and frame.name() != name and frame.type() == gdb.INLINE_FRAME:
            frame = frame.older()
        assert frame and frame.name() == name, (name, frame.name() if frame else None)
        frame.select()
        pc = int(gdb.parse_and_eval("$pc"))
        offset = pc - entry
        instruction = gdb.selected_frame().architecture().disassemble(pc, count=1)[0]["asm"]
        row = {"name": name, "pc": pc, "offset": offset, "instruction": instruction}
        raw = [
            item
            for item in locations.get(name, {}).get("intervals", [])
            if item["start"] <= offset < item["end"]
        ]
        assert len(raw) <= 1
        if name != failed:
            value = gdb.parse_and_eval("value")
            actual = [
                (
                    None
                    if value[index].is_optimized_out
                    else float(value[index]) if name == "vector_float" else int(value[index])
                )
                for index in range(4)
            ]
            row["lanes"] = actual
            if mode == "forge" and not raw:
                assert actual == [None] * 4, (name, offset, actual)
                missing += 1
                if name == "vector_alias":
                    alias_retired = True
            else:
                assert actual == values, (name, offset, actual)
                available += 1
            if mode == "forge" and alias_retired:
                assert not raw, "unproven spill identity revived after reload"
            if mode == "forge" and raw:
                location = raw[0]
                if location["kind"] == "register":
                    data = register(location["register"])
                else:
                    address = int(gdb.parse_and_eval("$sp")) + location["displacement"]
                    data = bytes(gdb.selected_inferior().read_memory(address, 16))
                    memory += 1
                    row["memoryAddress"] = address
                    if name == "vector_stack_arg":
                        assert address == entry_stack
                decoded = list(struct.unpack("<4f" if name == "vector_float" else "<4i", data))
                assert decoded == values, (name, offset, location, decoded)
                row["rawLocation"] = location
                row["rawLanes"] = decoded
        if name in ("vector_stack", "vector_alias") and all(
            register(number) == bytes(16) for number in range(64, 96)
        ):
            zero_carriers += 1
            if mode == "forge" and name != failed:
                assert (bool(raw) and raw[0]["kind"] == "memory") == (name == "vector_stack")
        function_rows.append(row)
        if instruction == "ret":
            decoded = list(struct.unpack("<4f" if name == "vector_float" else "<4i", register(64)))
            additions = (
                [0.5, 1.25, -0.75, 2.0]
                if name == "vector_float"
                else [9, 11, 13, 15] if name == "vector_stack_arg" else [1, 2, 3, 4]
            )
            assert decoded == [a + b for a, b in zip(values, additions)], (name, decoded)
            typed = None
            if name != failed:
                returned = gdb.Value(register(64), dtype)
                typed = [
                    float(returned[i]) if name == "vector_float" else int(returned[i])
                    for i in range(4)
                ]
                assert typed == decoded
            if mode == "forge" and name == "vector_stack" and name != failed:
                assert raw and raw[0]["kind"] == "register", "location used a released spill slot"
            returns[name] = {
                "rawLanes": decoded,
                "typedLanes": typed,
                "registerBytes": register(64).hex(),
            }
            break
        gdb.execute("stepi")
    else:
        raise AssertionError("no terminal return " + name)
    if name != failed:
        assert available >= 2, (name, available)
        if mode == "forge":
            if name in ("vector_stack", "vector_stack_arg"):
                assert memory >= 2, (name, memory)
            if name in ("vector_plain", "vector_float", "vector_alias"):
                assert missing >= 1, (name, missing)
            if name == "vector_copy":
                assert (
                    len(
                        {
                            item["rawLocation"]["register"]
                            for item in function_rows
                            if "rawLocation" in item
                        }
                    )
                    >= 2
                )
    if name in ("vector_stack", "vector_alias"):
        assert zero_carriers >= 1, (name, zero_carriers)
    rows.extend(function_rows)
gdb.execute("continue")
assert exits == [0], exits
(case / (mode + "-observations.json")).write_text(json.dumps(rows, indent=4) + "\n")
(case / (mode + "-returns.json")).write_text(json.dumps(returns, indent=4) + "\n")
(case / (mode + "-vector-result.json")).write_text(
    json.dumps(
        {
            "status": "PASS",
            "observations": len(rows),
            "blockedCalls": blocked_calls,
            "failedFunction": failed,
            "exitCodes": exits,
        },
        indent=4,
    )
    + "\n"
)
print("AARCH64_VECTOR_" + mode.upper() + "_ORACLE_PASS")
