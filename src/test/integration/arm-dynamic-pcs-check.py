#!/usr/bin/env python3
"""Exact mixed-PCS fixture: computed storage, emitted locations, and honest omissions."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import struct
from urllib.parse import unquote, urlsplit

# Reuse the existing small ELF32 LE fixture reader and strict transcript decoder.
spec = importlib.util.spec_from_file_location("arm_fixture", Path(__file__).with_name("arm-thumb-mode-check.py"))
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)
FUNCTIONS = ("base_probe", "vfp_probe", "vfp_sum")
GLOBALS = ("base_first", "base_second", "vfp_first", "vfp_second", "sum_value")


def records(text):
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


def name(record):
    return record["attrs"].get("DW_AT_name", "").rsplit(": ", 1)[-1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("labels", "finish"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("repository", type=Path)
    parser.add_argument("module", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    reference = model.elf(directory / "pcs.reference")
    original = model.elf(directory / "pcs.stripped")
    assert original["header"][6] == reference["header"][6] == 0x05000400
    assert "Tag_ABI_VFP_args: VFP registers" in (directory / "compiler-attributes.stdout").read_text()
    assert model.section(reference, ".text")["data"] == model.section(original, ".text")["data"]
    if args.stage == "labels":
        labels = {}
        for symbol in (*FUNCTIONS, *GLOBALS, "main"):
            candidates = [row for row in reference["symbols"] if row["name"] == symbol]
            assert len(candidates) == 1 and candidates[0]["size"] > 0, (symbol, candidates)
            labels[symbol] = candidates[0]
            if symbol in (*FUNCTIONS, "main"):
                assert candidates[0]["info"] & 15 == 2 and candidates[0]["raw"] & 1 == 0
        labels["compilerSource"] = str(args.repository / "src/test/fixtures/arm-dynamic-pcs.c")
        assert not original["symbols"] and not any(row["name"].startswith(".debug_") or
            row["name"] == ".note.gnu.build-id" for row in original["sections"])
        (directory / "labels.json").write_text(json.dumps(labels, indent=4) + "\n")
        (directory / "labels.txt").write_text("".join(key + " " + hex(labels[key]["raw"]) + "\n"
            for key in (*FUNCTIONS, *GLOBALS)))
        paths = [directory / "pcs.reference", directory / "pcs.stripped",
                 args.repository / "src/test/fixtures/arm-dynamic-pcs.c",
                 args.module / "lib/GhidraDwarfForge.jar", args.module / "ghidra_scripts/GhidraDwarfForge.java"]
        paths += [args.repository / "src/test/integration" / leaf for leaf in (
            "arm-dynamic-pcs-export.sh", "arm-dynamic-pcs-check.py", "arm-dynamic-pcs-gdb.py",
            "arm-thumb-mode-check.py", "ghidra_scripts/PrepareArmDynamicPcs.java")]
        (directory / "protected-before.json").write_text(json.dumps(
            {str(path): model.snapshot(path) for path in paths}, indent=4) + "\n")
        return
    labels = json.loads((directory / "labels.json").read_text())
    output = model.elf(directory / "pcs.dbg")
    assert output["header"][4] == output["header"][9] == 0
    assert output["header"][:4] == original["header"][:4] and output["header"][6] == original["header"][6]
    assert model.section(output, ".text")["data"] == model.section(original, ".text")["data"]
    observations = [model.transcript(directory / ("export-" + phase + ".log"), "ARM_DYNAMIC_PCS=")
                    for phase in ("curate", "inspect")]
    assert [item["phase"] for item in observations] == ["curate", "inspect"]
    assert {k: v for k, v in observations[0].items() if k != "phase"} == {
        k: v for k, v in observations[1].items() if k != "phase"}
    prep = observations[1]
    assert prep["language"] == "ARM:LE:32:v8" and prep["compiler"] == "default"
    origin = urlsplit(prep["exporterOrigin"])
    assert origin.scheme == "file" and not origin.netloc and not origin.query and not origin.fragment
    assert unquote(origin.path) == str((args.module / "lib/GhidraDwarfForge.jar").resolve())
    assert len(prep["functions"]) == 3
    for index, function in enumerate(prep["functions"]):
        symbol = FUNCTIONS[index]
        assert function["name"] == "curated_" + symbol and not function["customStorage"]
        assert function["signatureSource"] == "USER_DEFINED" and function["bodyRanges"] == 1
        assert function["callingConvention"] == ("__stdcall_softfp" if index == 0 else "__stdcall")
        assert function["returnType"] == ("float" if symbol == "vfp_sum" else "void")
        assert int(function["entry"], 16) == int(function["bodyStart"], 16) == labels[symbol]["raw"]
        assert int(function["bodyEnd"], 16) == labels[symbol]["raw"] + labels[symbol]["size"]
        assert [p["name"] for p in function["parameters"]] == ["first", "second"]
        assert [p["register"] for p in function["parameters"]] == (["r0", "r1"] if index == 0 else ["s0", "s1"])
        for parameter in function["parameters"]:
            assert parameter["type"] == "float" and parameter["source"] == "USER_DEFINED"
            assert not parameter["hasAssignedStorage"] and parameter["storageValid"]
            assert not any(parameter[key] for key in ("storageBad", "storageUnassigned", "storageForcedIndirect", "storageStack"))
            assert parameter["storageRegister"] and parameter["byteSize"] == 4
            assert len(parameter["varnodes"]) == 1 and parameter["varnodes"][0]["size"] == 4
        terminal = function["lastInstruction"]
        assert terminal["terminal"] and not terminal["jump"] and terminal["fallThrough"] is None
        assert terminal["instruction"] == "bx lr", terminal
        assert any(op.get("userop") == "setISAMode" for op in terminal["operations"]), terminal
        assert "return" in terminal["operations"][-1]["pcode"].lower(), terminal
    reports = [model.transcript(directory / ("export-" + phase + ".log"), "GhidraDwarfForge report: ")
               for phase in ("curate", "inspect")]
    assert reports[0] == reports[1]
    report = reports[0]
    assert report["status"] == "PARTIAL" and report["validation"] == {"status": "NOT_RUN"}
    assert report["target"] == {"architecture": "arm", "addressBits": 32, "byteOrder": "LITTLE_ENDIAN"}
    assert report["native"]["libdwarfVersion"] == "2.3.2" and report["failure"] is None
    for role, leaf in (("input", "pcs.stripped"), ("output", "pcs.dbg"), ("source", "pcs.dbg.c")):
        path = directory / leaf
        assert report["artifacts"][role + "Path"] == str(path)
        assert report["artifacts"][role + "Sha256"] == model.snapshot(path)["sha256"]
    dies = records((directory / "forge-info.stdout").read_text())
    by_offset = {row["offset"]: row for row in dies}
    forge_gdb = json.loads((directory / "forge.json").read_text())
    sum_result, = [row for row in forge_gdb["functions"] if row["function"] == "vfp_sum"]
    lifetime = sum_result["lifetime"]
    assert lifetime["end"] == lifetime["write"] + 4
    text_section = model.section(original, ".text")
    write_offset = lifetime["write"] - text_section["row"][3]
    assert text_section["data"][write_offset:write_offset + 4] == bytes.fromhex("67 0a b0 ee")
    checked = []
    for symbol in FUNCTIONS:
        full_name = "curated_" + symbol
        selected = [(index, row) for index, row in enumerate(dies) if row["tag"] == "DW_TAG_subprogram" and name(row) == full_name]
        assert len(selected) == 1, (full_name, selected)
        index, function = selected[0]
        parameters = []
        for row in dies[index + 1:]:
            if row["depth"] <= function["depth"]:
                break
            if row["tag"] == "DW_TAG_formal_parameter" and row["depth"] == function["depth"] + 1:
                parameters.append(row)
        assert [name(row) for row in parameters] == ["first", "second"]
        for ordinal, parameter in enumerate(parameters):
            attrs = parameter["attrs"]
            type_ref = re.fullmatch(r"<0x([0-9a-f]+)>", attrs["DW_AT_type"])
            actual_type = by_offset[int(type_ref[1], 16)]
            assert actual_type["tag"] == "DW_TAG_base_type" and name(actual_type) == "float"
            assert actual_type["attrs"]["DW_AT_byte_size"] == "4" and "float" in actual_type["attrs"]["DW_AT_encoding"]
            assert "DW_AT_const_value" not in attrs
            omitted = [row for row in report["omittedLocations"] if row["function"] == full_name and row["variable"] == name(parameter)]
            if symbol == "vfp_sum":
                assert "DW_AT_location" in attrs and len(omitted) == 1, (attrs, omitted)
                omission = omitted[0]
                assert omission["reason"] == "REGISTER_MODIFIED" and omission["kind"] == "PARAMETER"
                assert int(omission["startAddress"], 16) == lifetime["end"]
                assert int(omission["endAddress"], 16) == labels[symbol]["raw"] + labels[symbol]["size"]
                location = re.fullmatch(r"(0x[0-9a-f]+) \(location list\)", attrs["DW_AT_location"])
                assert location
                offset = int(location[1], 16)
                expression = bytes.fromhex("90 80 02" + (" 9d 20 20" if ordinal else ""))
                expected = b"\x07" + struct.pack("<II", labels[symbol]["raw"], lifetime["end"]) + bytes([len(expression)]) + expression + b"\x00"
                assert model.section(output, ".debug_loclists")["data"][offset:offset + len(expected)] == expected
            else:
                assert not omitted, omitted
                block = re.match(r"(\d+) byte block: ((?:[0-9a-f]{1,2}\s+)+)\(",
                                 attrs.get("DW_AT_location", ""))
                assert block, attrs
                expression = bytes(int(token, 16) for token in block[2].split())
                assert len(expression) == int(block[1]), attrs
                expected = (bytes((0x90, ordinal)) if symbol == "base_probe" else
                    bytes.fromhex("90 80 02" + (" 9d 20 20" if ordinal else "")))
                assert expression == expected, (full_name, ordinal, expression.hex(), expected.hex())
            checked.append({"function": full_name, "parameter": name(parameter), "attrs": attrs})
    warnings = []
    gdb_results = []
    vdso = re.compile(r"warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index")
    for variant in ("compiler", "forge"):
        result = json.loads((directory / (variant + ".json")).read_text())
        assert result["status"] == "PASS" and result["exitCode"] == 0 and len(result["functions"]) == 3
        lines = (directory / (variant + ".stderr")).read_text().splitlines()
        assert all(vdso.fullmatch(line) for line in lines), lines
        warnings.append(Counter(vdso.sub("<oracle-vdso>", line) for line in lines))
        assert (directory / (variant + ".qemu.status")).read_text() == "exit=0\n"
        assert not (directory / (variant + ".qemu.stderr")).read_bytes()
        gdb_results.append(result)
    assert warnings[0] == warnings[1]
    before = json.loads((directory / "protected-before.json").read_text())
    after = {path: model.snapshot(Path(path)) for path in before}
    assert before == after
    (directory / "protected-after.json").write_text(json.dumps(after, indent=4) + "\n")
    assert (directory / "pcs.dbg").read_bytes() == (directory / "first.dbg").read_bytes()
    assert (directory / "pcs.dbg.c").read_bytes() == (directory / "first.dbg.c").read_bytes()
    result = {"status": "PASS", "scope": "ARM-state mixed per-function base/VFP PCS in hard-float ET_EXEC; dynamic storage only; no debugger call/return ABI claim",
              "labels": labels, "observations": observations, "report": report, "dwarf": checked,
              "gdb": gdb_results, "protectedFiles": len(before),
              "strict": json.loads((directory / "strict.log.check.json").read_text()),
              "output": model.snapshot(directory / "pcs.dbg"), "source": model.snapshot(directory / "pcs.dbg.c")}
    (directory / "result.json").write_text(json.dumps(result, indent=4) + "\n")
    print("arm-dynamic-pcs-export PASS: " + str(directory))


if __name__ == "__main__":
    main()
