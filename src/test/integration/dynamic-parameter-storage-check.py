#!/usr/bin/env python3
"""Independent ordinary-parameter fixture facts and emitted/report/runtime binding."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
from urllib.parse import unquote, urlsplit

FUNCTIONS = ("dynamic_keep", "dynamic_change")
GLOBALS = ("dynamic_first", "dynamic_second", "dynamic_before", "dynamic_after")
PROFILES = {
    "x86_64": (2, 1, 62, "x86:LE:64:default", "x86_64"),
    "aarch64": (2, 1, 183, "AARCH64:LE:64:v8A", "aarch64"),
    "arm32": (1, 1, 40, "ARM:LE:32:v8", "arm"),
    "mips32be": (1, 2, 8, "MIPS:BE:32:default", "mips"),
    "mips32le": (1, 1, 8, "MIPS:LE:32:default", "mipsel"),
}


def snapshot(path):
    stat = path.stat()
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": stat.st_size, "mtimeNs": stat.st_mtime_ns}


def transcript(path, marker):
    lines = [line.split(marker, 1)[1].strip() for line in path.read_text().splitlines() if marker in line]
    assert len(lines) == 1, (path, marker)
    result, end = json.JSONDecoder().raw_decode(lines[0])
    assert lines[0][end:].strip() == "(GhidraScript)", lines[0][end:]
    return result


def elf(path):
    data = path.read_bytes()
    assert data[:4] == b"\x7fELF" and data[4] in (1, 2) and data[5] in (1, 2)
    wide = data[4] == 2
    order = "<" if data[5] == 1 else ">"
    header = struct.unpack_from(order + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"), data, 16)
    assert header[0] == 2 and header[10] == (64 if wide else 40)
    assert 0 < header[11] < 0xff00 and 0 < header[12] < header[11]
    rows = [struct.unpack_from(order + ("IIQQQQIIQQ" if wide else "10I"), data,
            header[5] + index * header[10]) for index in range(header[11])]
    def payload(row):
        if row[1] == 8:
            return b""
        assert row[4] + row[5] <= len(data)
        return data[row[4]:row[4] + row[5]]
    def string(table, offset):
        assert offset < len(table)
        return table[offset:table.index(0, offset)].decode("ascii")
    names = payload(rows[header[12]])
    sections = {string(names, row[0]): (row, payload(row)) for row in rows}
    symbols = []
    for row in rows:
        if row[1] != 2:
            continue
        width = 24 if wide else 16
        assert row[9] == width and row[5] % width == 0
        strings = payload(rows[row[6]])
        for offset in range(0, row[5], width):
            fields = struct.unpack_from(order + ("IBBHQQ" if wide else "IIIBBH"), payload(row), offset)
            name, info, other, index, value, size = fields if wide else (
                fields[0], fields[3], fields[4], fields[5], fields[1], fields[2])
            symbols.append({"name": string(strings, name), "address": value, "size": size,
                            "info": info, "section": index})
    return {"class": data[4], "data": data[5], "header": header, "sections": sections, "symbols": symbols}


def die_records(text):
    result = []
    for line in text.splitlines():
        header = re.match(r"^\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?", line)
        if header:
            result.append({"depth": int(header[1]), "offset": int(header[2], 16), "tag": header[3], "attrs": {}})
        elif result:
            attribute = re.match(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s+:\s*(.*)", line)
            if attribute:
                result[-1]["attrs"][attribute[1]] = attribute[2]
    return result


def die_name(record):
    return record["attrs"].get("DW_AT_name", "").rsplit(": ", 1)[-1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("labels", "observations", "finish"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("repository", type=Path)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=PROFILES)
    args = parser.parse_args()
    case = args.directory.resolve()
    reference, original = (elf(case / name) for name in ("dynamic.reference", "dynamic.stripped"))
    profile = PROFILES[args.target]
    assert (original["class"], original["data"], original["header"][1]) == profile[:3]
    assert original["header"] == reference["header"] or original["header"][:5] == reference["header"][:5]
    assert original["sections"][".text"][1] == reference["sections"][".text"][1]
    if args.stage == "labels":
        labels = {"compilerSource": str(args.repository / "src/test/fixtures/dynamic-parameter-storage.c")}
        for name in (*FUNCTIONS, *GLOBALS):
            selected = [row for row in reference["symbols"] if row["name"] == name]
            assert len(selected) == 1 and selected[0]["size"] > 0, (name, selected)
            labels[name] = selected[0]
            assert selected[0]["info"] & 15 == (2 if name in FUNCTIONS else 1)
        assert not original["symbols"]
        assert not any(name.startswith(".debug_") or name == ".note.gnu.build-id" for name in original["sections"])
        (case / "labels.json").write_text(json.dumps(labels, indent=4) + "\n")
        (case / "labels.txt").write_text("".join(name + " " + hex(labels[name]["address"]) + "\n" for name in (*FUNCTIONS, *GLOBALS)))
        paths = [case / "dynamic.reference", case / "dynamic.stripped",
                 args.repository / "src/test/fixtures/dynamic-parameter-storage.c",
                 args.module / "lib/GhidraDwarfForge.jar", args.module / "ghidra_scripts/GhidraDwarfForge.java"]
        paths += [args.repository / "src/test/integration" / name for name in (
            "dynamic-parameter-storage-export.sh", "dynamic-parameter-storage-check.py",
            "dynamic-parameter-storage-gdb.py", "ghidra_scripts/PrepareDynamicParameterStorage.java",
            "qemu-socket.sh", "check-dwarfdump.py")]
        (case / "protected-before.json").write_text(json.dumps({str(path): snapshot(path) for path in paths}, indent=4) + "\n")
        return
    labels = json.loads((case / "labels.json").read_text())
    observations = [transcript(case / ("export-" + phase + ".log"), "DYNAMIC_PARAMETER_STORAGE=") for phase in ("curate", "inspect")]
    assert [row["phase"] for row in observations] == ["curate", "inspect"]
    assert {key: value for key, value in observations[0].items() if key != "phase"} == {
        key: value for key, value in observations[1].items() if key != "phase"}
    prep = observations[1]
    assert prep["language"] == profile[3] and len(prep["functions"]) == 2
    origin = urlsplit(prep["exporterOrigin"])
    assert origin.scheme == "file" and not origin.netloc and not origin.query and not origin.fragment
    assert unquote(origin.path) == str((args.module / "lib/GhidraDwarfForge.jar").resolve())
    for name, function in zip(FUNCTIONS, prep["functions"]):
        assert function["name"] == "curated_" + name and not function["customStorage"]
        assert function["callingConvention"] == prep["defaultCallingConvention"] and function["signatureSource"] == "USER_DEFINED"
        assert int(function["entry"], 16) == labels[name]["address"]
        assert len(function["ranges"]) == 1 and int(function["ranges"][0][0], 16) == labels[name]["address"]
        assert labels[name]["address"] < int(function["ranges"][0][1], 16) <= labels[name]["address"] + labels[name]["size"]
        assert function["returnType"] == ("void" if name == "dynamic_keep" else "int")
        assert [p["name"] for p in function["parameters"]] == ["first", "second"]
        for parameter in function["parameters"]:
            assert parameter["type"] == "int" and parameter["source"] == "USER_DEFINED"
            assert not parameter["hasAssignedStorage"] and parameter["storageValid"] and parameter["storageRegister"]
            assert not any(parameter[key] for key in ("storageBad", "storageUnassigned", "storageForcedIndirect", "storageStack"))
            assert parameter["byteSize"] == 4 and parameter["register"]
            assert len(parameter["varnodes"]) == 1 and parameter["varnodes"][0]["size"] == 4
    reports = [transcript(case / ("export-" + phase + ".log"), "GhidraDwarfForge report: ") for phase in ("curate", "inspect")]
    assert reports[0] == reports[1]
    report = reports[0]
    assert report["status"] in ("SUCCESS", "PARTIAL") and report["validation"] == {"status": "NOT_RUN"} and report["failure"] is None
    assert report["target"] == {"architecture": profile[4], "addressBits": 64 if profile[0] == 2 else 32,
                                "byteOrder": "LITTLE_ENDIAN" if profile[1] == 1 else "BIG_ENDIAN"}
    for role, leaf in (("input", "dynamic.stripped"), ("output", "dynamic.dbg"), ("source", "dynamic.dbg.c")):
        assert report["artifacts"][role + "Path"] == str(case / leaf)
        assert report["artifacts"][role + "Sha256"] == snapshot(case / leaf)["sha256"]
    if args.stage == "observations":
        (case / "effective-storage.json").write_text(json.dumps(prep, indent=4) + "\n")
        (case / "export-report.json").write_text(json.dumps(report, indent=4) + "\n")
        return
    assert prep == json.loads((case / "effective-storage.json").read_text()) and report == json.loads((case / "export-report.json").read_text())
    output = elf(case / "dynamic.dbg")
    assert output["header"][4] == output["header"][9] == 0
    assert output["header"][:4] == original["header"][:4] and output["header"][6] == original["header"][6]
    assert output["sections"][".text"][1] == original["sections"][".text"][1]
    dies = die_records((case / "forge-info.stdout").read_text())
    by_offset = {row["offset"]: row for row in dies}
    dwarf = []
    for name, function in zip(FUNCTIONS, prep["functions"]):
        matches = [(index, row) for index, row in enumerate(dies) if row["tag"] == "DW_TAG_subprogram" and die_name(row) == function["name"]]
        assert len(matches) == 1
        index, parent = matches[0]
        parameters = []
        for row in dies[index + 1:]:
            if row["depth"] <= parent["depth"]:
                break
            if row["depth"] == parent["depth"] + 1 and row["tag"] == "DW_TAG_formal_parameter":
                parameters.append(row)
        assert [die_name(row) for row in parameters] == ["first", "second"]
        for parameter in parameters:
            attrs = parameter["attrs"]
            type_ref = re.fullmatch(r"<0x([0-9a-f]+)>", attrs["DW_AT_type"])
            assert type_ref
            datatype = by_offset[int(type_ref[1], 16)]
            assert datatype["tag"] == "DW_TAG_base_type" and datatype["attrs"]["DW_AT_byte_size"] == "4"
            assert "signed" in datatype["attrs"]["DW_AT_encoding"] and "unsigned" not in datatype["attrs"]["DW_AT_encoding"]
            assert "DW_AT_const_value" not in attrs
            omitted = [row for row in report["omittedLocations"] if row["function"] == function["name"] and row["variable"] == die_name(parameter)]
            assert all(row["kind"] == "PARAMETER" and row["reason"] != "UNASSIGNED" for row in omitted)
            if name == "dynamic_keep":
                assert "DW_AT_location" in attrs
                assert not any(int(row["startAddress"], 16) <= labels[name]["address"] < int(row["endAddress"], 16) for row in omitted)
            if "DW_AT_location" not in attrs:
                assert len(omitted) == 1 and omitted[0]["reason"] in ("REGISTER_MODIFIED", "UNKNOWN_LIFETIME")
                assert [int(omitted[0][key], 16) for key in ("startAddress", "endAddress")] == [int(value, 16) for value in function["ranges"][0]]
            dwarf.append({"function": function["name"], "parameter": die_name(parameter), "attrs": attrs, "omissions": omitted})
    vdso = re.compile(r"warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index")
    warnings, records = [], []
    for variant in ("compiler", "forge"):
        record = json.loads((case / (variant + "-gdb.json")).read_text())
        assert record["status"] == "PASS" and record["exitCode"] == 0 and len(record["functions"]) == 2
        lines = (case / (variant + "-gdb.stderr")).read_text().splitlines()
        assert all(args.target in ("arm32", "aarch64") and vdso.fullmatch(line) for line in lines), lines
        warnings.append(Counter(vdso.sub("<oracle-vdso>", line) for line in lines))
        if args.target != "x86_64":
            assert (case / (variant + ".qemu.status")).read_text() == "exit=0\n"
            assert not (case / (variant + ".qemu.stderr")).read_bytes()
        records.append(record)
    assert warnings[0] == warnings[1]
    for leaf in ("dynamic.dbg", "dynamic.dbg.c"):
        assert (case / leaf).read_bytes() == (case / ("first." + leaf)).read_bytes()
    before = json.loads((case / "protected-before.json").read_text())
    after = {path: snapshot(Path(path)) for path in before}
    assert before == after
    (case / "protected-after.json").write_text(json.dumps(after, indent=4) + "\n")
    result = {"status": "PASS", "target": args.target, "scope": "Ordinary ET_EXEC integer parameters; dynamic default storage, actual entry values and observed report-bound availability; no debugger call ABI or new profile claim",
              "observations": observations, "report": report, "dwarf": dwarf, "gdb": records,
              "protectedFiles": len(before), "output": snapshot(case / "dynamic.dbg"),
              "source": snapshot(case / "dynamic.dbg.c"), "strict": json.loads((case / "strict.log.check.json").read_text())}
    (case / "result.json").write_text(json.dumps(result, indent=4) + "\n")
    print("dynamic-parameter-storage-export PASS: " + str(case))


if __name__ == "__main__":
    main()
