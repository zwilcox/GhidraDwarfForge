#!/usr/bin/env python3
"""Exercise the production serializer with compiler-derived controls, not Ghidra extraction."""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "src/test/integration"
reference = runpy.run_path(str(SCRIPTS / "call-site-reference.py"))
run, digest, debugger = (reference[name] for name in ("run", "digest", "debugger"))


def model(binary, compiler, target, work):
    prefix = "" if target == "x86_64" else "aarch64-linux-gnu-"
    symbols = run([prefix + "nm", "-S", "--defined-only", binary], work / "symbols")
    functions = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[2] in ("T", "t") and (fields[3].startswith("cs_") or fields[3] == "main"):
            functions.append({"name": fields[3], "address": int(fields[0], 16), "size": int(fields[1], 16)})
    instructions = run([prefix + "objdump", "-dw", compiler], work / "instructions")
    info = run(["readelf", "--debug-dump=info", compiler], work / "compiler-info")
    calls = reference["dwarf_inventory"](info, instructions)
    inventory = {}
    increments = {"cs_normal": 1, "cs_tail_first": 1, "cs_tail_middle": 2}
    for call in calls:
        if call["caller"] not in (*increments, "cs_leaf"):
            continue
        site = {**call, "pc": int(call["pc"], 16), "returnPc": int(call["returnPc"], 16)}
        if call["caller"] in increments:
            site["value"] = increments[call["caller"]]
        inventory.setdefault(call["caller"], []).append(site)
    # Explicitly partial driver inventory: only the two selected ordinary calls.
    # Their constants are source/disassembly controls, not recovered flow claims.
    owner = None
    for line in instructions.splitlines():
        match = re.fullmatch(r"[0-9a-f]+ <([^>]+)>:", line)
        if match:
            owner = match[1]
        fields = line.split("\t")
        if owner != "cs_driver" or len(fields) < 3:
            continue
        assembly = " ".join(fields[2:]).strip()
        for callee, value in (("cs_normal", 10), ("cs_tail_first", 20)):
            if re.match(r"(?:callq?|bl)\s", assembly) and "<" + callee + ">" in assembly:
                pc = int(fields[0].strip()[:-1], 16)
                size = sum(len(part) // 2 for part in fields[1].split())
                inventory.setdefault(owner, []).append({"pc": pc, "returnPc": pc + size,
                    "callee": callee, "tail": False, "value": value})
    assert len(inventory["cs_driver"]) == 2
    return {"functions": functions, "inventories": [
        {"caller": caller, "sites": sites} for caller, sites in inventory.items()]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=("x86_64", "aarch64"))
    parser.add_argument("reference", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--consumer", type=Path, required=True)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--dwarfdump", type=Path, required=True)
    args = parser.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    binary, compiler = (args.reference.resolve() / name for name in ("input", "reference"))
    preserved = {str(path): digest(path) for path in (binary, compiler)}
    data = model(binary, compiler, args.target, work)
    model_path = work / "model.json"
    model_path.write_text(json.dumps(data, indent=4) + "\n")
    classpath = (ROOT / "build/call-site-serialization-classpath.txt").read_text().strip()
    java = ["java", "--enable-native-access=ALL-UNNAMED",
            "-Djava.io.tmpdir=" + tempfile.gettempdir(), "-Djna.tmpdir=" + tempfile.gettempdir(),
            "-cp", classpath, "ghidradwarfforge.nativeapi.CallSiteSerializationProbe",
            args.consumer.resolve(), args.producer.resolve(), binary]
    rows = []
    for variant in ("complete", "partial", "tails", "failed", "empty", "no-values", "cancel"):
        directory = work / variant
        directory.mkdir()
        sidecar = directory / "input.dbg"
        command = [*java, sidecar, model_path, args.target, variant]
        run(command, directory / "producer")
        source = Path(str(sidecar) + ".c")
        assert source.stat().st_mtime_ns <= sidecar.stat().st_mtime_ns, "source newer than debug objfile"
        first = digest(sidecar)
        first_source = digest(source)
        run(command, directory / "repeat")
        assert source.stat().st_mtime_ns <= sidecar.stat().st_mtime_ns, "repeated source newer than debug objfile"
        assert first == digest(sidecar), "nondeterministic sidecar"
        assert first_source == digest(source), "nondeterministic source"
        text = run(["readelf", "--debug-dump=info", sidecar], directory / "info")
        run(["readelf", "-h", "-S", "-n", "--debug-dump=abbrev,aranges,decodedline", sidecar], directory / "gnu")
        run(["llvm-dwarfdump", "--verify", sidecar], directory / "llvm")
        run([sys.executable, SCRIPTS / "check-dwarfdump.py", sidecar, directory / "strict.log",
             "--tool", args.dwarfdump.resolve(), "--original", binary], directory / "strict")
        if variant == "partial":
            flags = re.findall(r"DW_AT_call_all_calls\s*:\s*(\d+)", text)
            assert len(flags) == 5 and set(flags) == {"0"}, flags
        if variant == "empty":
            assert "DW_TAG_call_site" not in text
        else:
            assert "DW_AT_call_parameter" not in text, "GDB rejects simultaneous parameter location/reference"
        if variant == "cancel":
            assert "PASS_CANCEL_POLLS" in (directory / "producer.stdout").read_text()
        for scenario in (0, 1):
            observed = debugger(args.target, binary, scenario, directory / f"gdb-{scenario}", sidecar)
            frames = observed["frames"]
            tails = [f["name"] for f in frames if f["tail"]]
            expect_tail = scenario == 1 and variant in ("complete", "tails", "no-values", "cancel")
            assert tails == (["cs_tail_middle", "cs_tail_first"] if expect_tail else []), (variant, scenario, frames)
            expected = ["cs_checkpoint", "cs_leaf"] + (["cs_normal"] if scenario == 0 else tails) + ["cs_driver", "main"]
            assert [f["name"] for f in frames] == expected, (variant, scenario, frames)
            assert all(("tail call frame" in f["info"]) == f["tail"] for f in frames)
            assert all(not f["value"]["available"] for f in frames[1:-2]), "unknown body values must remain unavailable"
            link_driver = next(f["address"] for f in data["functions"] if f["name"] == "cs_driver")
            bias = int(observed["driverAddress"], 16) - link_driver
            pie = int.from_bytes(binary.read_bytes()[16:18], "little") == 3
            assert (bias != 0) == pie, (pie, bias)
            assert observed["sink"] == (11 if scenario == 0 else 23)
            known_values = variant not in ("empty", "no-values") and (scenario == 0 or expect_tail)
            values = [f["entryValue"] for f in frames[1:-2]]
            if known_values:
                assert [v.get("value") for v in values] == ([11, 10] if scenario == 0 else [23, 21, 20]), (variant, scenario, values)
            else:
                assert not any(v["available"] for v in values), (variant, scenario, values)
            rows.append({"variant": variant, "scenario": scenario, "tails": tails, "entryValues": values,
                         "warnings": observed["warnings"]})
    assert all(digest(Path(path)) == value for path, value in preserved.items())
    (work / "result.json").write_text(json.dumps({"status": "PASS_SERIALIZATION_CONTROLS",
        "scope": "Production serializer with compiler-derived model; no Ghidra extraction claim",
        "target": args.target, "runtime": rows, "preservedSha256": preserved}, indent=4) + "\n")
    print("PASS_SERIALIZATION_CONTROLS", args.target, "sessions=" + str(len(rows)))


if __name__ == "__main__":
    main()
