#!/usr/bin/env python3
"""Compiler ELF, computed storage, emitted types/pieces and actual GDB values."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

SUPPORT = Path(__file__).with_name("dynamic-parameter-storage-check.py")
spec = importlib.util.spec_from_file_location("dynamic_fixture_facts", SUPPORT)
facts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(facts)
FUNCTIONS = ("capture_pair", "capture_scalar")
GLOBALS = ("observed_first", "observed_second", "observed_scalar")


def die_records(text):
    # GNU aligns short attributes, but long names can directly precede the colon.
    # Adapt that formatting only; preserve the inherited parser and raw evidence.
    aligned = re.sub(r"(^\s*<[0-9a-f]+>\s+DW_AT_\w+):", r"\1 :", text, flags=re.MULTILINE)
    return facts.die_records(aligned)


def children(dies, index):
    parent = dies[index]
    result = []
    for row in dies[index + 1:]:
        if row["depth"] <= parent["depth"]:
            break
        if row["depth"] == parent["depth"] + 1:
            result.append(row)
    return result


def assert_member_use(text):
    # O0 Ghidra can retain an adjacent temporary copy of the stack-home field.
    # Require one field read and one corresponding global assignment, either
    # direct or through exactly one local assignment immediately before it.
    for field in ("first", "second"):
        global_name = "observed_" + field
        member = r"value\." + field
        assert len(re.findall(r"\b" + member + r"\b", text)) == 1
        assert len(re.findall(r"\b" + global_name + r"\s*=(?!=)", text)) == 1
        direct = re.search(r"(?m)^\s*" + global_name + r"\s*=\s*" + member + r"\s*;\s*$", text)
        if direct:
            continue
        temporary = re.search(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*" + member +
            r"\s*;[ \t]*\n[ \t]*" + global_name + r"\s*=\s*\1\s*;[ \t]*$", text)
        assert temporary, (field, text)
        name = temporary[1]
        assert name not in ("observed_first", "observed_second", "value")
        assert len(re.findall(r"\b" + re.escape(name) + r"\s*(?:=(?!=)|[+*/%&|^-]=|\+\+|--)", text)) == 1


def artifact_dwarf(case, original, prep, report, target, prefix):
    output = facts.elf(case / ("custom.composite.dbg" if prefix else "composite.dbg"))
    assert output["header"][:4] == original["header"][:4] and output["header"][6] == original["header"][6]
    assert output["header"][4] == output["header"][9] == 0
    assert output["sections"][".text"][1] == original["sections"][".text"][1]
    dies = die_records((case / (prefix + "forge-info.stdout")).read_text())
    by_offset = {row["offset"]: row for row in dies}
    dwarf = []
    for index, function in enumerate(prep["functions"]):
        selected = [i for i, row in enumerate(dies) if row["tag"] == "DW_TAG_subprogram" and facts.die_name(row) == function["name"]]
        parent_index, = selected
        parameter, = [row for row in children(dies, parent_index) if row["tag"] == "DW_TAG_formal_parameter"]
        attrs = parameter["attrs"]
        assert facts.die_name(parameter) == "value" and "DW_AT_const_value" not in attrs
        dtype = by_offset[int(re.fullmatch(r"<0x([0-9a-f]+)>", attrs["DW_AT_type"])[1], 16)]
        assert dtype["attrs"]["DW_AT_byte_size"] == "8"
        if index == 0:
            assert dtype["tag"] == "DW_TAG_structure_type"
            members = [row for row in children(dies, dies.index(dtype)) if row["tag"] == "DW_TAG_member"]
            assert [facts.die_name(row) for row in members] == ["first", "second"]
            for member, offset in zip(members, (0, 4)):
                assert member["attrs"]["DW_AT_data_member_location"] == str(offset)
        else:
            assert dtype["tag"] == "DW_TAG_base_type" and "unsigned" in dtype["attrs"]["DW_AT_encoding"]
        omitted = [item for item in report["omittedLocations"] if item["function"] == function["name"] and item["variable"] == "value"]
        assert all(item["kind"] == "PARAMETER" and item["reason"] != "UNASSIGNED" for item in omitted)
        scalar_clobber = index == 1 and target in ("mips32be", "mips32le")
        if scalar_clobber:
            omission, = omitted
            assert omission["reason"] == "REGISTER_MODIFIED" and "DW_AT_location" not in attrs
            assert [int(omission[key], 16) for key in ("startAddress", "endAddress")] == [
                int(bound, 16) for bound in function["ranges"][0]]
            write = re.fullmatch(r"function writes parameter piece register a0 at ([0-9a-f]+)", omission["diagnostic"])
            assert write, omission
            address = int(write[1], 16)
            instruction, = [item for item in function["instructions"] if int(item["address"], 16) == address]
            assert instruction["text"].startswith("lui a0,"), instruction
            header, payload = original["sections"][".text"]
            offset = address - header[3]
            assert 0 <= offset <= len(payload) - 4
            word = int.from_bytes(payload[offset:offset + 4], "big" if target == "mips32be" else "little")
            assert word >> 26 == 0x0f and (word >> 16) & 31 == 4  # Actual LUI writes a0.
        else:
            assert not any(int(item["startAddress"], 16) <= int(function["entry"], 16) < int(item["endAddress"], 16) for item in omitted)
            assert "DW_AT_location" in attrs
        if target in ("arm32", "mips32be", "mips32le") and not scalar_clobber:
            first = 0 if target == "arm32" else 4
            match = re.fullmatch(r"(\d+) byte block: (.*?)\s*\(DW_OP_regx:.*", attrs["DW_AT_location"])
            assert match, attrs
            raw = bytes(int(value, 16) for value in match[2].split())
            assert len(raw) == int(match[1]) and raw == bytes((0x90, first, 0x9d, 32, 0, 0x90, first + 1, 0x9d, 32, 0)), raw.hex()
        dwarf.append({"function": function["name"], "parameter": attrs, "omissions": omitted})
    return dwarf


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("labels", "observations", "finish"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("repository", type=Path)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=tuple(facts.PROFILES))
    args = parser.parse_args()
    case = args.directory.resolve()
    profile = facts.PROFILES[args.target]
    reference, original = (facts.elf(case / name) for name in ("composite.reference", "composite.stripped"))
    assert (original["class"], original["data"], original["header"][1]) == profile[:3]
    assert original["header"][:5] == reference["header"][:5] and original["header"][6] == reference["header"][6]
    assert original["sections"][".text"][1] == reference["sections"][".text"][1]
    if args.stage == "labels":
        labels = {"compilerSources": {name: str(args.repository / "src/test/fixtures" /
            ("dynamic-composite-aggregate.c" if name == "capture_pair" else "dynamic-composite-scalar.c")) for name in FUNCTIONS}}
        for name in (*FUNCTIONS, *GLOBALS):
            selected = [row for row in reference["symbols"] if row["name"] == name]
            assert len(selected) == 1 and selected[0]["size"] > 0
            assert selected[0]["info"] & 15 == (2 if name in FUNCTIONS else 1)
            labels[name] = selected[0]
        assert not original["symbols"]
        assert not any(name.startswith(".debug_") or name == ".note.gnu.build-id" for name in original["sections"])
        (case / "labels.json").write_text(json.dumps(labels, indent=4) + "\n")
        (case / "labels.txt").write_text("".join(name + " " + hex(labels[name]["address"]) + "\n" for name in (*FUNCTIONS, *GLOBALS)))
        paths = [case / name for name in ("composite.reference", "composite.stripped", "aggregate.o", "scalar.o", "caller.o")]
        paths += [args.repository / "src/test/fixtures" / ("dynamic-composite-" + name + ".c") for name in ("aggregate", "scalar", "caller")]
        paths += [args.module / "lib/GhidraDwarfForge.jar", args.module / "ghidra_scripts/GhidraDwarfForge.java", SUPPORT]
        paths += [args.repository / "src/test/integration" / name for name in (
            "dynamic-composite-storage-export.sh", "dynamic-composite-storage-check.py", "dynamic-composite-storage-gdb.py",
            "ghidra_scripts/PrepareDynamicCompositeStorage.java", "qemu-socket.sh", "check-dwarfdump.py")]
        assert len(paths) == 17
        (case / "protected-before.json").write_text(json.dumps({str(path): facts.snapshot(path) for path in paths}, indent=4) + "\n")
        return
    labels = json.loads((case / "labels.json").read_text())
    observations = [json.loads((case / (phase + ".json")).read_text()) for phase in ("natural", "curate", "inspect", "custom", "reopen-custom")]
    assert [row["phase"] for row in observations] == ["natural", "curate", "inspect", "custom", "reopen-custom"]
    assert {key: value for key, value in observations[1].items() if key != "phase"} == {
        key: value for key, value in observations[2].items() if key != "phase"}
    assert {key: value for key, value in observations[3].items() if key != "phase"} == {
        key: value for key, value in observations[4].items() if key != "phase"}
    prep, custom_prep = observations[2], observations[4]
    # Conversion changes the storage persistence/class, not its semantic pieces.
    def semantic_observation(observation):
        result = json.loads(json.dumps(observation))
        result.pop("phase")
        for function in result["functions"]:
            function.pop("customStorage")
            for parameter in function["parameters"]:
                parameter.pop("hasAssignedStorage")
                parameter.pop("storageClass")
        return result
    assert semantic_observation(prep) == semantic_observation(custom_prep)
    for observation in observations:
        assert observation["language"] == profile[3] and observation["pointerBytes"] == (8 if profile[0] == 2 else 4)
        assert observation["executablePath"] == str(case / "composite.stripped")
        origin = urlsplit(observation["exporterOrigin"])
        assert origin.scheme == "file" and not origin.netloc and not origin.query and not origin.fragment
        assert unquote(origin.path) == str((args.module / "lib/GhidraDwarfForge.jar").resolve())
    assert prep["aggregateBytes"] == 8 and len(prep["functions"]) == 2
    for index, (name, function) in enumerate(zip(FUNCTIONS, prep["functions"])):
        assert function["name"] == "curated_" + name and function["present"] and not function["customStorage"]
        assert function["callingConvention"] == prep["defaultCallingConvention"] and function["signatureSource"] == "USER_DEFINED"
        assert function["returnType"] == "void" and int(function["entry"], 16) == labels[name]["address"]
        assert len(function["ranges"]) == 1
        start, end = (int(value, 16) for value in function["ranges"][0])
        assert start == labels[name]["address"] < end <= start + labels[name]["size"]
        parameter, = function["parameters"]
        assert parameter["name"] == "value" and parameter["source"] == "USER_DEFINED" and not parameter["hasAssignedStorage"]
        assert parameter["storageValid"] and not any(parameter[key] for key in ("storageBad", "storageUnassigned", "storageForcedIndirect", "storageStack"))
        assert parameter["byteSize"] == 8 and sum(node["size"] for node in parameter["varnodes"]) == 8
        assert all(node["space"] == "register" for node in parameter["varnodes"])
        assert parameter["storageClass"] == "ghidra.program.model.lang.DynamicVariableStorage"
        assert function["functionClass"] == "ghidra.program.database.function.FunctionDB"
        assert parameter["parameterClass"] == "ghidra.program.database.function.ParameterDB"
        assert parameter["ordinal"] == 0 and parameter["ownerIsFunction"] and parameter["isAttachedParameter"]
        if index == 0:
            assert parameter["fields"] == [{"name": "first", "type": "int", "bytes": 4, "offset": 0},
                {"name": "second", "type": "int", "bytes": 4, "offset": 4}]
    for function in custom_prep["functions"]:
        assert function["customStorage"]
        parameter, = function["parameters"]
        assert parameter["hasAssignedStorage"] and parameter["storageClass"] == "ghidra.program.model.listing.VariableStorage"
    for observation in observations[1:]:
        aggregate = observation["functions"][0]
        assert aggregate["highParameterType"] == "/Analyst/RecoveredPair"
        assert aggregate["highParameterStorage"] == aggregate["parameters"][0]["storage"]
        assert aggregate["highParameterStorageSerialization"] == aggregate["parameters"][0]["storageSerialization"]
        assert_member_use(aggregate["decompiledC"])
    for phase in ("curate", "inspect", "custom", "reopen-custom"):
        log = (case / ("export-" + phase + ".log")).read_text()
        scripts = re.findall(r"^INFO\s+SCRIPT: (.+) \(HeadlessAnalyzer\)\s*$", log, re.MULTILINE)
        assert scripts == [str(args.repository / "src/test/integration/ghidra_scripts/PrepareDynamicCompositeStorage.java"),
            str(args.module / "ghidra_scripts/GhidraDwarfForge.java")], scripts
        versions = re.findall(r'^(?:openjdk|java) version "([0-9]+)[^"]*"[^\n]*$', log, re.MULTILINE)
        assert versions == [prep["javaVersion"].split(".", 1)[0]], versions
    reports = [facts.transcript(case / ("export-" + phase + ".log"), "GhidraDwarfForge report: ")
        for phase in ("curate", "inspect", "custom", "reopen-custom")]
    assert reports[0] == reports[1] and reports[2] == reports[3]
    report, custom_report = reports[0], reports[2]
    for current, prefix in ((report, ""), (custom_report, "custom.")):
        assert current["status"] in ("SUCCESS", "PARTIAL") and current["validation"] == {"status": "NOT_RUN"} and current["failure"] is None
        assert current["target"] == {"architecture": profile[4], "addressBits": 64 if profile[0] == 2 else 32,
            "byteOrder": "LITTLE_ENDIAN" if profile[1] == 1 else "BIG_ENDIAN"}
        for role, name in (("input", "composite.stripped"), ("output", prefix + "composite.dbg"), ("source", prefix + "composite.dbg.c")):
            assert current["artifacts"][role + "Path"] == str(case / name)
            assert current["artifacts"][role + "Sha256"] == facts.snapshot(case / name)["sha256"]
    # Output path/embedded source paths are deliberately different. The tested
    # location observations must retain the same meaning and omission inventory.
    assert report["omittedLocations"] == custom_report["omittedLocations"]
    if args.stage == "observations":
        (case / "effective-storage.json").write_text(json.dumps(prep, indent=4) + "\n")
        (case / "export-report.json").write_text(json.dumps(report, indent=4) + "\n")
        (case / "custom-effective-storage.json").write_text(json.dumps(custom_prep, indent=4) + "\n")
        (case / "custom-export-report.json").write_text(json.dumps(custom_report, indent=4) + "\n")
        return
    assert prep == json.loads((case / "effective-storage.json").read_text())
    assert report == json.loads((case / "export-report.json").read_text())
    assert custom_prep == json.loads((case / "custom-effective-storage.json").read_text())
    assert custom_report == json.loads((case / "custom-export-report.json").read_text())
    for name in ("composite.dbg", "composite.dbg.c", "custom.composite.dbg", "custom.composite.dbg.c"):
        assert (case / name).read_bytes() == (case / ("first." + name)).read_bytes()
    dwarf = artifact_dwarf(case, original, prep, report, args.target, "")
    custom_dwarf = artifact_dwarf(case, original, custom_prep, custom_report, args.target, "custom-")
    assert [(row["function"], row["parameter"].get("DW_AT_location"), row["omissions"]) for row in custom_dwarf] == [
        (row["function"], row["parameter"].get("DW_AT_location"), row["omissions"]) for row in dwarf]
    records, warnings = [], []
    vdso = re.compile(r"warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index")
    for variant in ("compiler", "forge", "custom"):
        record = json.loads((case / (variant + "-gdb.json")).read_text())
        assert record["status"] == "PASS" and record["exitCodes"] == [0] and record["target"] == args.target
        assert [row["name"] for row in record["functions"]] == list(FUNCTIONS)
        lines = (case / (variant + "-gdb.stderr")).read_text().splitlines()
        assert all(args.target in ("aarch64", "arm32") and vdso.fullmatch(line) for line in lines), lines
        warnings.append(Counter(vdso.sub("<oracle-vdso>", line) for line in lines))
        if args.target != "x86_64":
            assert (case / (variant + ".qemu.status")).read_text() == "exit=0\n"
            assert not (case / (variant + ".qemu.stderr")).read_bytes()
        records.append(record)
    assert warnings[0] == warnings[1] == warnings[2]
    for index, function in enumerate(prep["functions"]):
        compiler, forge, custom = (record["functions"][index] for record in records)
        assert forge == custom
        assert compiler["incoming"] == forge["incoming"]
        states = forge["states"]
        assert 0 < len(states) <= 256 and states[0]["pc"] == int(function["entry"], 16)
        expected_available = not (index == 1 and args.target in ("mips32be", "mips32le"))
        assert states[0]["available"] == expected_available
        if not expected_available:
            assert all(not state["available"] and state["omission"]["reason"] == "REGISTER_MODIFIED" for state in states)
        addresses = {int(item["address"], 16) for item in function["instructions"]}
        assert all(state["pc"] in addresses for state in states) and len({state["pc"] for state in states}) == len(states)
        assert compiler["sourceStop"]["pc"] in {state["pc"] for state in states}
    strict = json.loads((case / "strict.log.check.json").read_text())
    assert strict["status"] == "PASS" and strict["uncorroborated_errors"] == 0
    custom_strict = json.loads((case / "custom-strict.log.check.json").read_text())
    assert custom_strict["status"] == "PASS" and custom_strict["uncorroborated_errors"] == 0
    assert custom_strict["reported_errors"] == strict["reported_errors"]
    before = json.loads((case / "protected-before.json").read_text())
    after = {path: facts.snapshot(Path(path)) for path in before}
    (case / "protected-after.json").write_text(json.dumps(after, indent=4) + "\n")
    assert before == after
    result = {"status": "PASS", "target": args.target, "observations": observations, "report": report,
        "dwarf": dwarf, "customReport": custom_report, "customDwarf": custom_dwarf,
        "gdb": records, "strict": strict, "customStrict": custom_strict, "protectedFiles": len(before),
        "profile": {"aggregateOptimization": "O0", "scalarOptimization": "O1", "callerOptimization": "O0",
            "scope": "ordinary eight-byte struct and unsigned64 arguments; computed and converted-custom joins; no aggregate ABI generalization"}}
    (case / "result.json").write_text(json.dumps(result, indent=4) + "\n")
    print("dynamic-composite-storage-export PASS: " + str(case))


if __name__ == "__main__":
    main()
