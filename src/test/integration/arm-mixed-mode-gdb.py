"""Independent assembly-known ARM/Thumb transitions and instruction values."""
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import gdb

case = Path(os.environ["FORGE_MIXED_CASE"])
variant = os.environ["FORGE_MIXED_VARIANT"]
phase = os.environ.get("FORGE_MIXED_PHASE", "instructions")
assert phase in ("instructions", "next", "step", "address", "calls")
labels = json.loads((case / "labels.json").read_text())
spec = importlib.util.spec_from_file_location('mixed_source_reference', Path(__file__).with_name('arm-mixed-mode-reference.py'))
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)
expected = fixture_module.fixture(labels.get('split', False))
assert labels['hex'] == expected['hex']
start = labels["start"]
name = "mixed_body" if variant == "compiler" else "recovered_mixed_body"
result = {"status": "FAILED", "variant": variant, "phase": phase, "observations": []}



def shared_link_map():
    """Read the Linux ARM32 loader rendezvous, independent of exported symbols."""
    driver = fixture_module.inventory.elf(case / 'mixed.driver')
    dynamic = fixture_module.inventory.section(driver, '.dynamic')
    slots = [dynamic['row'][3] + offset + 4 for offset in range(0, len(dynamic['data']), 8)
        if struct.unpack_from('<II', dynamic['data'], offset)[0] == 21]  # DT_DEBUG
    assert len(slots) == 1 and driver['header'][0] == 2  # fixed-address driver
    memory = gdb.selected_inferior()
    def word(at):
        return int.from_bytes(memory.read_memory(at, 4), 'little')
    debug = word(slots[0])
    assert debug and word(debug) == 1  # r_debug.r_version
    node = word(debug + 4)  # r_debug.r_map
    seen, entries = set(), []
    selected = []
    while node:
        assert node not in seen and len(seen) < 64
        seen.add(node)
        bias, path, dynamic_address, following, previous = struct.unpack('<5I', memory.read_memory(node, 20))
        name_bytes = bytearray()
        for offset in range(4096):
            value = bytes(memory.read_memory(path + offset, 1))
            if value == b'\0':
                break
            name_bytes += value
        else:
            raise AssertionError('unterminated link_map name')
        loaded = name_bytes.decode()
        row = {'node': node, 'bias': bias, 'path': loaded, 'dynamic': dynamic_address}
        entries.append(row)
        if loaded == str(case / 'mixed.stripped'):
            selected.append(row)
        node = following
    row, = selected
    original = fixture_module.inventory.elf(case / 'mixed.reference')
    assert row['dynamic'] == row['bias'] + fixture_module.inventory.section(original, '.dynamic')['row'][3]
    assert bytes(memory.read_memory(row['bias'], 16)) == original['data'][:16]
    assert bytes(memory.read_memory(row['bias'] + labels['start'], expected['size'])).hex() == expected['hex']
    return row['bias'], {'debugSlot': slots[0], 'rDebug': debug, 'entries': entries,
        'matchingHeaderAndCodeBytes': True}


def load_shared():
    gdb.execute("file " + str(case / "mixed.driver"))
    gdb.execute("set solib-search-path " + str(case))
    gdb.execute("target remote " + os.environ["FORGE_MIXED_REMOTE"])
    driver_entry = gdb.Breakpoint("*main", internal=True)
    gdb.execute("continue")
    driver_entry.delete()
    libraries = gdb.execute("info sharedlibrary", to_string=True)
    line, = [row for row in libraries.splitlines() if row.split()[-1:] == [str(case / "mixed.stripped")]]
    if labels.get('sectionless', False):
        bias, rendezvous = shared_link_map()
        runtime_text = None  # GDB has no section-derived From address.
    else:
        runtime_text = int(line.split()[0], 16)
        bias = runtime_text - labels["textAddress"]
        rendezvous = None
    assert bias > 0
    artifact = case / ("mixed.reference" if variant == "compiler" else variant + ".dbg")
    gdb.execute("add-symbol-file " + str(artifact) + " -o " + hex(bias))
    assert int(gdb.parse_and_eval("&" + name)) == start + bias
    result["sharedLoading"] = {"bias": bias, "runtimeText": runtime_text,
        "linkText": labels["textAddress"], "autoSolibAdd": False, "libraries": libraries,
        "loadCommand": "add-symbol-file", "retainsDriverEntry": True,
        "loaderRendezvous": rendezvous}
    return bias

try:
    assert str(gdb.parameter("arm force-mode")) == "auto"
    assert str(gdb.parameter("arm fallback-mode")) == "auto"
    assert int(gdb.parse_and_eval("&" + name)) == start
    sectionless = labels.get("sectionless", False)
    inspection_bias = 0
    if sectionless:
        gdb.execute("set architecture armv7")
        if labels.get('shared', False):
            inspection_bias = load_shared()
        else:
            gdb.execute("target remote " + os.environ["FORGE_MIXED_REMOTE"])
            inspection_bias = int(gdb.parse_and_eval("&" + name)) - start
    arch = gdb.selected_inferior().architecture()
    result["static"] = arch.disassemble(start + inspection_bias, start + inspection_bias + expected['size'] - 1)
    for row in result["static"]:
        row["addr"] -= inspection_bias
    result["instructionSource"] = ("remote-before-mixed-call" if labels.get("shared", False) else "remote-before-continue") if sectionless else "file-before-attach"
    expected_offsets = expected['units']
    expected_lengths = expected['lengths']
    result["staticWidthsMatch"] = [(r["addr"] - start, r["length"]) for r in result["static"]] == list(
        zip(expected_offsets, expected_lengths))
    if variant != "compiler":
        reference = json.loads((case / "compiler-gdb.json").read_text())
        def decoded(rows):
            return [(row["addr"], row["length"], re.sub(r"\s*<[^>]*>", "", row["asm"])) for row in rows]
        result["staticMatchesCompiler"] = decoded(result["static"]) == decoded(reference["static"])
    if labels.get("shared", False):
        bias = inspection_bias if sectionless else load_shared()
    else:
        if not sectionless:
            gdb.execute("target remote " + os.environ["FORGE_MIXED_REMOTE"])
        bias = int(gdb.parse_and_eval("&" + name)) - start
        assert (bias != 0) == labels.get("role", "exec").startswith("pie"), bias
    result["loadBias"] = bias
    start += bias
    thumb_offset = expected['thumb'][0]
    stop = gdb.Breakpoint("*" + hex(start + thumb_offset) if phase == "address" else name)
    gdb.execute("continue")
    assert int(gdb.parse_and_eval("$pc")) == start + (thumb_offset if phase == "address" else 0)
    stop.delete()
    # Source-known values before each instruction; mappings cannot supply these.
    values = dict(zip(expected['offsets'], expected['values']))
    if labels.get('split', False) and variant != 'compiler':
        for offset in range(4, 8):
            block = gdb.block_for_pc(start + offset)
            while block is not None:
                assert block.function is None, 'data hole belongs to a function'
                block = block.superblock
            sal = gdb.find_pc_line(start + offset)
            assert sal.line == 0, 'data hole has executable source mapping'
        result['excludedDataHole'] = [start + 4, start + 8]
    if phase in ("next", "step"):
        result["listing"] = gdb.execute("list " + name, to_string=True)
        listing_marker = ("mixed_body:" if labels.get('split', False) else "add r0, r0, #3") if variant == "compiler" else "recovered_mixed_body"
        assert listing_marker in result["listing"]
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
        if not start <= pc < start + expected['codeEnd']:
            break
        offset = pc - start
        assert offset in expected['offsets'], 'execution entered data or unknown bytes'
        position = expected_offsets.index(offset)
        width, value = expected_lengths[position], values[offset]
        r0 = int(gdb.parse_and_eval("$r0"))
        thumb = bool(int(gdb.parse_and_eval("$cpsr")) & 32)
        actual_bytes = bytes(gdb.selected_inferior().read_memory(pc, width)).hex()
        assert r0 == value
        assert thumb == (expected['thumb'][0] <= offset < expected['thumb'][1])
        assert actual_bytes == labels["hex"][offset * 2:(offset + width) * 2]
        row = {"pc": pc, "offset": offset, "r0": r0, "thumb": thumb, "bytes": actual_bytes,
            "instruction": arch.disassemble(pc, count=1)}
        if phase in ("next", "step"):
            sal = gdb.selected_frame().find_sal()
            if variant != 'compiler' and labels.get('split', False) and offset == 8:
                # GDB stops at the second discontiguous range's entry. Ghidra's
                # first expression token is later; never fabricate a line here.
                assert sal.line == 0
                row['source'] = {'line': 0, 'reason': 'unmapped second range entry'}
            else:
                assert sal.symtab is not None and sal.line > 0
                row["source"] = {"path": sal.symtab.fullname(), "line": sal.line}
            if variant != "compiler" and sal.line > 0:
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
        expected_visits = [offset for offset in expected['offsets'] if phase != 'address' or offset >= thumb_offset]
        assert visited == expected_visits
    result["returnedPc"] = int(gdb.parse_and_eval("$pc"))
    assert int(gdb.parse_and_eval("$r0")) == 4686
    assert bytes(gdb.selected_inferior().read_memory(start + expected['codeEnd'], 4)).hex() == "34120000"
    if labels.get('split', False):
        assert bytes(gdb.selected_inferior().read_memory(start + 4, 4)).hex() == 'cefaedfe'
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
