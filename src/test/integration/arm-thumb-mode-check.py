#!/usr/bin/env python3
"""Fixture-specific independent ELF/symbol/report oracle; no target support inference."""
import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import struct
from urllib.parse import unquote, urlsplit


def snapshot(path):
    stat = path.stat()
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": stat.st_size, "mtimeNs": stat.st_mtime_ns}


def elf(path):
    data = path.read_bytes()
    assert data[:7] == b"\x7fELF\x01\x01\x01", path
    header = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    assert header[0] == 2 and header[1] == 40, header
    offset, width, count, names_index = header[5], header[10], header[11], header[12]
    assert width == 40 and 0 < count < 0xff00 and 0 < names_index < count
    sections = [struct.unpack_from("<10I", data, offset + index * width) for index in range(count)]
    names_row = sections[names_index]
    names = data[names_row[4]:names_row[4] + names_row[5]]
    def string(table, at):
        return table[at:table.index(0, at)].decode("ascii")
    result = [{"index": index, "name": string(names, row[0]), "row": row,
               "data": b"" if row[1] == 8 else data[row[4]:row[4] + row[5]]}
              for index, row in enumerate(sections)]
    symbols = []
    for section in result:
        row = section["row"]
        if row[1] != 2:
            continue
        assert row[9] == 16 and row[5] % 16 == 0
        strings = result[row[6]]["data"]
        for at in range(0, row[5], 16):
            name, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", section["data"], at)
            symbols.append({"name": string(strings, name), "raw": value, "size": size,
                            "info": info, "other": other, "section": shndx})
    return {"data": data, "header": header, "sections": result, "symbols": symbols}


def transcript(path, marker):
    lines = [line.split(marker, 1)[1].strip() for line in path.read_text().splitlines() if marker in line]
    assert len(lines) == 1, (path, marker, len(lines))
    value, end = json.JSONDecoder().raw_decode(lines[0])
    assert lines[0][end:].strip() in ("", "(GhidraScript)"), lines[0][end:]
    return value


def section(image, name):
    selected = [row for row in image["sections"] if row["name"] == name]
    assert len(selected) == 1, (name, len(selected))
    return selected[0]


def validate_symbol_inventory(original, output):
    table = section(output, ".symtab")
    dynamic = section(original, ".dynsym")
    original_strings = original["sections"][dynamic["row"][6]]
    mirror_strings = output["sections"][table["row"][6]]
    old_locals, new_locals = dynamic["row"][7], table["row"][7]
    assert table["row"][2:4] == (0, 0)
    assert dynamic["row"][9] == table["row"][9] == 16
    assert 0 < old_locals < new_locals <= len(output["symbols"])
    inserted = output["symbols"][old_locals:new_locals]
    assert inserted and all(row["name"].startswith("__forge_arm_mode_") and
        row["info"] == 2 and row["other"] == 0 for row in inserted)
    assert all(row["info"] >> 4 == 0 for row in output["symbols"][:new_locals])
    assert all(row["info"] >> 4 != 0 for row in output["symbols"][new_locals:])
    # Every original row (including null, local and undefined/nonlocal imports)
    # retains its exact bytes and string offsets around the inserted local block.
    assert table["data"][:old_locals * 16] + table["data"][new_locals * 16:] == dynamic["data"]
    assert mirror_strings["data"].startswith(original_strings["data"])
    for inherited in (dynamic, original_strings):
        retained = section(output, inherited["name"])
        assert retained["data"] == inherited["data"]
        assert retained["row"][1:4] == inherited["row"][1:4]
        assert retained["row"][5:] == inherited["row"][5:]


def inventory_negative_controls(original, output):
    for kind in ("missing-import", "changed-import", "wrong-local-boundary", "changed-dynamic-table", "false-mode-name"):
        altered = deepcopy(output)
        table = section(altered, ".symtab")
        if kind == "missing-import":
            table["data"] = table["data"][:-16]
            altered["symbols"].pop()
        elif kind == "changed-import":
            data = bytearray(table["data"])
            data[-1] ^= 1
            table["data"] = bytes(data)
        elif kind == "wrong-local-boundary":
            row = list(table["row"])
            row[7] = len(altered["symbols"])
            table["row"] = tuple(row)
        elif kind == "changed-dynamic-table":
            dynamic = section(altered, ".dynsym")
            dynamic["data"] = dynamic["data"][:-1] + bytes([dynamic["data"][-1] ^ 1])
        else:
            altered["symbols"][section(original, ".dynsym")["row"][7]]["name"] = "invented"
        try:
            validate_symbol_inventory(original, altered)
        except AssertionError:
            continue
        raise AssertionError("symbol inventory corruption accepted: " + kind)
    print("arm-thumb-symbol-inventory-negative-controls=PASS cases=5")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("labels", "finish"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("repository", type=Path)
    parser.add_argument("module", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    reference = elf(directory / "thumb.reference")
    original = elf(directory / "thumb.stripped")
    if args.stage == "labels":
        labels = {}
        for name in ("thumb_add", "arm_call", "main", "arm_after", "thumb_sink", "thumb_pointer"):
            rows = [row for row in reference["symbols"] if row["name"] == name]
            assert len(rows) == 1, (name, rows)
            row = dict(rows[0])
            function = name in ("thumb_add", "arm_call", "main", "arm_after")
            row["code"] = row["raw"] & ~1 if function else row["raw"]
            assert row["size"] > 0
            if function:
                assert row["info"] & 15 == 2 and row["raw"] & 1 == (name == "thumb_add"), row
            labels[name] = row
        assert labels["thumb_add"]["code"] + labels["thumb_add"]["size"] == labels["arm_after"]["code"]
        assert labels["thumb_add"]["section"] == labels["arm_after"]["section"]
        labels["compilerSource"] = str(args.repository / "src/test/fixtures/arm-thumb-leaf.c")
        assert not original["symbols"]
        assert not any(row["name"].startswith(".debug_") or row["name"] == ".note.gnu.build-id"
                       for row in original["sections"])
        assert section(reference, ".text")["data"] == section(original, ".text")["data"]
        (directory / "labels.json").write_text(json.dumps(labels, indent=4) + "\n")
        (directory / "prepare.txt").write_text("\n".join(hex(labels[name]["code"]) for name in
            ("thumb_add", "arm_call", "main", "thumb_sink", "thumb_pointer", "arm_after")) + "\n")
        paths = [directory / "thumb.reference", directory / "thumb.stripped"]
        paths += sorted(args.module.rglob("*.jar")) + [args.module / "ghidra_scripts/GhidraDwarfForge.java"]
        paths += [args.repository / "src/test/fixtures" / name for name in
                  ("arm-thumb-caller.c", "arm-thumb-leaf.c", "arm-thumb-after.c")]
        paths += [args.repository / "src/test/integration" / name for name in
                  ("arm-thumb-mode-export.sh", "arm-thumb-mode-gdb.py", "arm-thumb-mode-check.py",
                   "ghidra_scripts/PrepareArmThumbMode.java")]
        (directory / "protected-before.json").write_text(json.dumps(
            {str(path): snapshot(path) for path in paths}, indent=4) + "\n")
        return
    labels = json.loads((directory / "labels.json").read_text())
    output = elf(directory / "thumb.dbg")
    assert output["header"][4] == output["header"][9] == 0
    assert output["header"][:4] == original["header"][:4]
    assert output["header"][6] == original["header"][6]
    assert section(output, ".text")["data"] == section(original, ".text")["data"]
    validate_symbol_inventory(original, output)
    inventory_negative_controls(original, output)
    prep = transcript(directory / "export-first.log", "ARM_THUMB_PREP=")
    assert prep["language"] == "ARM:LE:32:v8" and len(prep["functions"]) == 4
    jars = list((args.module / "lib").glob("GhidraDwarfForge.jar"))
    origin = urlsplit(prep["exporterClassOrigin"])
    assert origin.scheme == "file" and not origin.netloc and not origin.query and not origin.fragment
    assert len(jars) == 1 and unquote(origin.path) == str(jars[0].resolve())
    names = {"main": "main", **{name: "recovered_" + name for name in ("thumb_add", "arm_call", "arm_after")}}
    compiler_static = json.loads((directory / "compiler-calls.json").read_text())["static"]
    info = (directory / "forge-info.stdout").read_text()
    for name, recovered in names.items():
        row = labels[name]
        expected = {"name": "__forge_arm_mode_%08x" % row["code"], "raw": row["raw"],
                    "size": row["size"], "info": 2, "other": 0, "section": row["section"]}
        actual = [symbol for symbol in output["symbols"] if symbol["name"] == expected["name"]]
        assert actual == [expected], (name, expected, actual)
        selected = [entry for entry in prep["functions"] if entry["name"] == recovered]
        assert len(selected) == 1
        assert int(selected[0]["entry"], 16) == row["code"]
        assert selected[0]["mode"] == (name == "thumb_add")
        assert [(int(item["address"], 16), item["length"]) for item in selected[0]["instructions"]] == [
            (item["address"], item["length"]) for item in compiler_static[name]]
        # Each selected subprogram has an even true code PC, independently of ELF symbol tags.
        dies = re.split(r"(?=^\s*<\d+><[0-9a-f]+>:)", info, flags=re.M)
        matching = [die for die in dies if "DW_TAG_subprogram" in die and
                    re.search(r"DW_AT_name\s*:.*\b" + re.escape(recovered) + r"\s*$", die, re.M)]
        assert len(matching) == 1, (recovered, matching)
        low = re.search(r"DW_AT_low_pc\s*:\s*(0x[0-9a-f]+)", matching[0])
        assert low and int(low[1], 16) == row["code"], matching[0]
    reports = [transcript(directory / ("export-" + role + ".log"), "GhidraDwarfForge report: ")
               for role in ("first", "repeat")]
    assert reports[0] == reports[1]
    assert reports[0]["status"] == "PARTIAL" and reports[0]["validation"]["status"] == "NOT_RUN"
    assert reports[0]["target"] == {"architecture": "arm", "addressBits": 32, "byteOrder": "LITTLE_ENDIAN"}
    assert reports[0]["native"]["libdwarfVersion"] == "2.3.2" and reports[0]["failure"] is None
    for role, leaf in (("input", "thumb.stripped"), ("output", "thumb.dbg"), ("source", "thumb.dbg.c")):
        path = directory / leaf
        assert reports[0]["artifacts"][role + "Path"] == str(path)
        assert reports[0]["artifacts"][role + "Sha256"] == snapshot(path)["sha256"]
    for path in (directory / "thumb.dbg", directory / "thumb.dbg.c"):
        assert path.read_bytes() == path.with_name("first." + path.name).read_bytes()
    records = []
    vdso = re.compile(r"warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index")
    for phase in ("calls", "from-arm"):
        warnings = []
        for variant in ("compiler", "forge"):
            prefix = directory / (variant + "-" + phase)
            result = json.loads(prefix.with_suffix(".json").read_text())
            assert result["status"] == "PASS" and result["exitCode"] == 0
            lines = prefix.with_suffix(".stderr").read_text().splitlines()
            assert all(vdso.fullmatch(line) for line in lines), lines
            warnings.append(Counter(vdso.sub("<oracle-vdso>", line) for line in lines))
            assert prefix.with_suffix(".qemu.status").read_text() == "exit=0\n"
            assert not prefix.with_suffix(".qemu.stderr").read_bytes()
            if variant == "forge" and phase == "calls":
                function, = [item for item in prep["functions"] if item["name"] == "recovered_thumb_add"]
                write, = [item for item in function["instructions"] if item["text"] == "mov r0,r3"]
                assert write["length"] == 2
                boundary = int(write["address"], 16) + write["length"]
                for values in result["values"]:
                    assert values["right"]["available"] and values["left"]["available"], values
                    assert values["lifetime"] == {"write": boundary - 2, "end": boundary,
                        "afterUnavailable": True, "returnRegister": values["sink"]}
                    for parameter in ("left", "right"):
                        omitted = [item for item in reports[0]["omittedLocations"] if
                                   item["function"] == "recovered_thumb_add" and item["variable"] == parameter]
                        if parameter == "left":
                            assert len(omitted) == 1 and omitted[0]["reason"] == "REGISTER_MODIFIED"
                            assert omitted[0]["kind"] == "PARAMETER"
                            assert int(omitted[0]["startAddress"], 16) == boundary
                            assert int(omitted[0]["endAddress"], 16) == labels["thumb_add"]["code"] + labels["thumb_add"]["size"]
                        else:
                            assert not omitted, omitted
                owner, = [index for index, die in enumerate(dies) if "DW_TAG_subprogram" in die and
                    re.search(r"DW_AT_name\s*:.*\brecovered_thumb_add\s*$", die, re.M)]
                children = []
                for die in dies[owner + 1:]:
                    depth = re.match(r"\s*<(\d+)>", die)
                    if depth and int(depth[1]) <= 1:
                        break
                    children.append(die)
                left, = [die for die in children if "DW_TAG_formal_parameter" in die and
                    re.search(r"DW_AT_name\s*:.*\bleft\s*$", die, re.M)]
                location = re.search(r"DW_AT_location\s*:\s*(0x[0-9a-f]+) \(location list\)", left)
                assert location
                offset = int(location[1], 16)
                expected = b"\x07" + struct.pack("<II", labels["thumb_add"]["code"], boundary) + b"\x02\x90\x00\x00"
                assert section(output, ".debug_loclists")["data"][offset:offset + len(expected)] == expected
            records.append(result)
        assert warnings[0] == warnings[1]
    protected = json.loads((directory / "protected-before.json").read_text())
    after = {path: snapshot(Path(path)) for path in protected}
    assert protected == after
    (directory / "protected-after.json").write_text(json.dumps(after, indent=4) + "\n")
    result = {"status": "PASS", "scope": "mixed ARM/Thumb ELF32 LE ARMv7 hard-float ET_EXEC; no PIE/rebase claim",
              "labels": labels, "prep": prep, "report": reports[0], "gdb": records,
              "output": snapshot(directory / "thumb.dbg"), "source": snapshot(directory / "thumb.dbg.c"),
              "protectedFiles": len(protected), "strict": json.loads((directory / "strict.log.check.json").read_text())}
    (directory / "result.json").write_text(json.dumps(result, indent=4) + "\n")
    print("arm-thumb-mode-export PASS: " + str(directory))


if __name__ == "__main__":
    main()
