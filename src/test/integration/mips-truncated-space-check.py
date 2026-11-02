#!/usr/bin/env python3
"""Bounded fixture assertions, independent compiler ELF and emitted/runtime facts."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
from urllib.parse import unquote, urlsplit

FUNCTIONS = ("capture_wide", "capture_args")
GLOBALS = ("observed_wide", "observed_first", "observed_fifth", "observed_sixth", "observed_sum")
PARAMETERS = (("value",), ("first", "second", "third", "fourth", "fifth", "sixth"))
SUPPORT = Path(__file__).with_name("dynamic-parameter-storage-check.py")
spec = importlib.util.spec_from_file_location("dynamic_fixture_facts", SUPPORT)
facts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(facts)
snapshot, elf, transcript = facts.snapshot, facts.elf, facts.transcript


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("labels", "observations", "finish"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("repository", type=Path)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=("mips32be", "mips32le"))
    parser.add_argument("abi", choices=("o32", "n32"))
    args = parser.parse_args()
    case = args.directory.resolve()
    endian = "be" if args.target == "mips32be" else "le"
    prefix = "mips-linux-gnu" if endian == "be" else "mipsel-linux-gnu"
    n32 = args.abi == "n32"
    expected_language = "MIPS:" + endian.upper() + (":64:64-32addr" if n32 else ":32:default")
    original, reference = (elf(case / leaf) for leaf in ("abi.stripped", "abi.reference"))
    assert (original["class"], original["data"], original["header"][1]) == (1, 2 if endian == "be" else 1, 8)
    assert original["header"][:5] == reference["header"][:5]
    flags = original["header"][6]
    assert flags == reference["header"][6] == (0x80000021 if n32 else 0x70001001)
    assert original["sections"][".text"][1] == reference["sections"][".text"][1]
    if args.stage == "labels":
        macros = dict(re.findall(r"^#define (\S+) (.+)$", (case / "macros.stdout").read_text(), re.M))
        assert macros["__SIZEOF_POINTER__"] == "4" and macros["__SIZEOF_LONG_LONG__"] == "8"
        assert macros["__NR_Linux"] == ("6000" if n32 else "4000")
        assert macros["__NR_exit"] == ("(__NR_Linux + 58)" if n32 else "(__NR_Linux + 1)")
        labels = {"compilerSource": str(args.repository / "src/test/fixtures/mips-truncated-space.c")}
        for name in (*FUNCTIONS, "fixture_main", *GLOBALS):
            rows = [row for row in reference["symbols"] if row["name"] == name]
            assert len(rows) == 1 and rows[0]["size"] > 0, (name, rows)
            assert rows[0]["info"] & 15 == (1 if name in GLOBALS else 2)
            labels[name] = rows[0]
        assert not original["symbols"]
        assert not any(name.startswith(".debug_") or name == ".note.gnu.build-id" for name in original["sections"])
        (case / "labels.json").write_text(json.dumps(labels, indent=4) + "\n")
        (case / "labels.txt").write_text("".join(name + " " + hex(labels[name]["address"]) + "\n"
            for name in (*FUNCTIONS, "fixture_main", *GLOBALS)))
        paths = [case / "abi.reference", case / "abi.stripped", SUPPORT,
            args.repository / "src/test/fixtures/mips-truncated-space.c",
            args.repository / "src/test/fixtures/mips-truncated-space-start.S",
            args.module / "lib/GhidraDwarfForge.jar", args.module / "ghidra_scripts/GhidraDwarfForge.java"]
        paths += [args.repository / "src/test/integration" / name for name in (
            "mips-truncated-space-export.sh", "mips-truncated-space-check.py", "mips-truncated-space-gdb.py",
            "ghidra_scripts/PrepareMipsTruncatedSpace.java", "qemu-socket.sh", "check-dwarfdump.py")]
        emulator = "qemu-mips" + ("n32" if n32 else "") + ("el" if endian == "le" else "") + "-static"
        paths += [Path(shutil.which(tool)).resolve() for tool in (
            prefix + "-gcc", prefix + "-objcopy", prefix + "-objdump", "readelf", "llvm-dwarfdump", "gdb-multiarch", emulator)]
        paths += [Path("/usr") / prefix / "include/asm" / name for name in (
            "unistd.h", "unistd_o32.h", "unistd_n32.h", "sgidefs.h")]
        (case / "protected-before.json").write_text(json.dumps({str(p): snapshot(p) for p in paths}, indent=4) + "\n")
        (case / "fixture.json").write_text(json.dumps({"target": args.target, "abi": args.abi, "endian": endian,
            "flags": flags, "isa": "mips64r2" if n32 else "mips32r2",
            "cpu": "MIPS64R2-generic" if n32 else "24Kf", "macros": macros}, indent=4) + "\n")
        return
    labels = json.loads((case / "labels.json").read_text())
    observations = [json.loads((case / (phase + ".json")).read_text()) for phase in ("natural", "curate", "inspect")]
    assert [row["phase"] for row in observations] == ["natural", "curate", "inspect"]
    assert {k: v for k, v in observations[1].items() if k != "phase"} == {
        k: v for k, v in observations[2].items() if k != "phase"}
    prep = observations[2]
    for observation in observations:
        assert observation["language"] == expected_language and observation["compiler"] == ("n32" if n32 else "default")
        assert observation["pointerBytes"] == 4 and int(observation["elfFlags"], 16) == flags
        assert observation["executablePath"] == str(case / "abi.stripped")
        origin = urlsplit(observation["exporterOrigin"])
        assert origin.scheme == "file" and not origin.netloc and not origin.query and not origin.fragment
        assert unquote(origin.path) == str((args.module / "lib/GhidraDwarfForge.jar").resolve())
    assert len(prep["functions"]) == 2
    stores = []
    wide_prefix = None
    if not n32:
        entry = labels["capture_wide"]["address"]
        text, payload = original["sections"][".text"]
        at = entry - text[3]
        words = struct.unpack_from((">" if endian == "be" else "<") + "6I", payload, at)
        # Source-built O0 prologue: adjust frame, save/set frame register, home
        # both incoming words; only the following LUI overwrites a carrier.
        assert words[:3] == (0x27bdfff8, 0xafbe0004, 0x03a0f025), words
        assert set(words[3:5]) == {0xafc5000c, 0xafc40008}, words
        assert words[5] >> 16 == 0x3c04, words
        wide_prefix = {"entry": entry, "write": entry + 20, "end": entry + 24,
            "machineWords": [hex(word) for word in words]}
        (case / "wide-prefix-proof.json").write_text(json.dumps(wide_prefix, indent=4) + "\n")
    for name, parameters, function in zip(FUNCTIONS, PARAMETERS, prep["functions"]):
        assert function["present"] and function["name"] == "curated_" + name
        assert function["signatureSource"] == "USER_DEFINED" and function["returnType"] == "void"
        assert not function["customStorage"] and function["callingConvention"] == prep["defaultCallingConvention"]
        assert int(function["entry"], 16) == labels[name]["address"]
        assert len(function["ranges"]) == 1
        start, end = [int(x, 16) for x in function["ranges"][0]]
        assert start == labels[name]["address"] < end <= start + labels[name]["size"]
        assert [p["name"] for p in function["parameters"]] == list(parameters)
        for parameter in function["parameters"]:
            assert not parameter["hasAssignedStorage"] and parameter["storageValid"]
            assert parameter["source"] == "USER_DEFINED"
            assert not any(parameter[k] for k in ("storageBad", "storageUnassigned", "storageForcedIndirect"))
            assert parameter["byteSize"] == (8 if name == "capture_wide" else 4)
        if name == "capture_args":
            assert [p["storage"] for p in function["parameters"]] == (
                ["a0_lo:4", "a1_lo:4", "a2_lo:4", "a3_lo:4", "t0_lo:4", "t1_lo:4"] if n32 else
                ["a0:4", "a1:4", "a2:4", "a3:4", "Stack[0x10]:4", "Stack[0x14]:4"])
        else:
            assert [v["size"] for v in function["parameters"][0]["varnodes"]] == ([8] if n32 else [4, 4])
        for instruction in function["instructions"]:
            for store in instruction["stores"]:
                assert store == {"inputCount": 3, "hasOutput": False, "constantSelector": True,
                    "space": "ram", "memorySpace": True, "pointerBytes": 4,
                    "addressBytes": 8 if n32 else 4, "valueBytes": store["valueBytes"]}
                assert store["valueBytes"] > 0
                stores.append({"instruction": instruction["address"], **store})
    assert stores
    reports = [transcript(case / ("export-" + phase + ".log"), "GhidraDwarfForge report: ") for phase in ("curate", "inspect")]
    assert reports[0] == reports[1]
    report = reports[0]
    assert report["status"] in ("SUCCESS", "PARTIAL") and report["validation"] == {"status": "NOT_RUN"} and report["failure"] is None
    assert report["target"] == {"architecture": "mips" if endian == "be" else "mipsel", "addressBits": 32,
        "byteOrder": "BIG_ENDIAN" if endian == "be" else "LITTLE_ENDIAN"}
    for role, leaf in (("input", "abi.stripped"), ("output", "abi.dbg"), ("source", "abi.dbg.c")):
        assert report["artifacts"][role + "Path"] == str(case / leaf)
        assert report["artifacts"][role + "Sha256"] == snapshot(case / leaf)["sha256"]
    for phase in ("curate", "inspect"):
        log = (case / ("export-" + phase + ".log")).read_text()
        assert "SCRIPT: " + str(args.module / "ghidra_scripts/GhidraDwarfForge.java") in log
        assert "SCRIPT: " + str(args.repository / "src/test/integration/ghidra_scripts/PrepareMipsTruncatedSpace.java") in log
    if args.stage == "observations":
        (case / "effective-storage.json").write_text(json.dumps(prep, indent=4) + "\n")
        (case / "export-report.json").write_text(json.dumps(report, indent=4) + "\n")
        return
    assert prep == json.loads((case / "effective-storage.json").read_text())
    assert report == json.loads((case / "export-report.json").read_text())
    output = elf(case / "abi.dbg")
    assert output["header"][4] == output["header"][9] == 0
    assert output["header"][:4] == original["header"][:4] and output["header"][6] == flags
    assert output["sections"][".text"][1] == original["sections"][".text"][1]
    dies = facts.die_records((case / "forge-info.stdout").read_text())
    by_offset = {d["offset"]: d for d in dies}
    dwarf = []
    for function, parameters in zip(prep["functions"], PARAMETERS):
        matches = [(i, d) for i, d in enumerate(dies) if d["tag"] == "DW_TAG_subprogram" and facts.die_name(d) == function["name"]]
        assert len(matches) == 1
        index, parent = matches[0]
        children = []
        for d in dies[index + 1:]:
            if d["depth"] <= parent["depth"]:
                break
            if d["depth"] == parent["depth"] + 1 and d["tag"] == "DW_TAG_formal_parameter":
                children.append(d)
        assert [facts.die_name(d) for d in children] == list(parameters)
        for d in children:
            name = facts.die_name(d)
            unsigned = name == "value"
            datatype = by_offset[int(re.fullmatch(r"<0x([0-9a-f]+)>", d["attrs"]["DW_AT_type"])[1], 16)]
            assert datatype["tag"] == "DW_TAG_base_type"
            assert datatype["attrs"]["DW_AT_byte_size"] == ("8" if unsigned else "4")
            assert ("unsigned" in datatype["attrs"]["DW_AT_encoding"]) == unsigned
            assert "signed" in datatype["attrs"]["DW_AT_encoding"]
            assert "DW_AT_const_value" not in d["attrs"]
            omitted = [o for o in report["omittedLocations"] if o["function"] == function["name"] and o["variable"] == name]
            assert all(o["kind"] == "PARAMETER" and o["reason"] != "UNASSIGNED" for o in omitted)
            if not n32 and unsigned:
                assert len(omitted) == 1 and omitted[0]["reason"] == "REGISTER_MODIFIED"
                end = int(function["ranges"][0][1], 16)
                assert [int(omitted[0][key], 16) for key in ("startAddress", "endAddress")] == [wide_prefix["end"], end]
                location = re.fullmatch(r"(0x[0-9a-f]+) \(location list\)", d["attrs"]["DW_AT_location"])
                assert location, d
                offset = int(location[1], 16)
                expression = bytes.fromhex("90 04 9d 20 00 90 05 9d 20 00")
                encoded = b"\x07" + struct.pack((">" if endian == "be" else "<") + "II",
                    wide_prefix["entry"], wide_prefix["end"]) + bytes([len(expression)]) + expression + b"\0"
                assert output["sections"][".debug_loclists"][1][offset:offset + len(encoded)] == encoded
            else:
                assert "DW_AT_location" in d["attrs"]
                assert not any(int(o["startAddress"], 16) <= int(function["entry"], 16) < int(o["endAddress"], 16) for o in omitted)
            dwarf.append({"function": function["name"], "parameter": name, "attributes": d["attrs"], "omissions": omitted})
    records = [json.loads((case / (v + "-gdb.json")).read_text()) for v in ("compiler", "forge")]
    for variant, record in zip(("compiler", "forge"), records):
        assert record["status"] == "PASS" and record["exitCodes"] == [0] and len(record["functions"]) == 2
        assert not (case / (variant + "-gdb.stderr")).read_bytes()
        assert (case / (variant + ".qemu.status")).read_text() == "exit=0\n"
        assert not (case / (variant + ".qemu.stderr")).read_bytes()
    strict = json.loads((case / "strict.log.check.json").read_text())
    assert strict["status"] == "PASS" and strict["exit_status"] == 0
    assert strict["reported_errors"] == strict["uncorroborated_errors"] == 0
    for leaf in ("abi.dbg", "abi.dbg.c"):
        assert (case / leaf).read_bytes() == (case / ("first." + leaf)).read_bytes()
    before = json.loads((case / "protected-before.json").read_text())
    after = {p: snapshot(Path(p)) for p in before}
    assert before == after
    (case / "protected-after.json").write_text(json.dumps(after, indent=4) + "\n")
    result = {"status": "PASS", "target": args.target, "abi": args.abi,
        "scope": "Freestanding ET_EXEC O32/N32 integer STORE contrast; no libc, FP, PIE/shared, debugger-call ABI or broad profile claim",
        "observations": observations, "stores": stores, "report": report, "dwarf": dwarf, "gdb": records,
        "strict": strict, "protectedFiles": len(before), "output": snapshot(case / "abi.dbg"), "source": snapshot(case / "abi.dbg.c")}
    (case / "result.json").write_text(json.dumps(result, indent=4) + "\n")
    print("mips-truncated-space-export PASS: " + str(case))


if __name__ == "__main__":
    main()
