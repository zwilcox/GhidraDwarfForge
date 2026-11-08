#!/usr/bin/env python3
"""Validate compiler call-site references before comparing production exports."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "src/test/integration"
SOURCE = ROOT / "src/test/fixtures/call-site-reference.c"
image = runpy.run_path(str(SCRIPTS / "synthetic-cfi-reference.py"))["image"]
EXPECTED_SINK = (11, 23, 34, 36, 43, 53, 60, 70)
EXPECTED_FRAMES = (
    ("cs_normal",), ("cs_tail_middle", "cs_tail_first"), (), (),
    ("cs_recursive",) * 4, ("cs_tail_recursive",), (), ("cs_forward",),
)
EXPECTED_ENTRY = (
    (11, 10), (23, 21, 20), (None,), (None,),
    (None, 43, 42, 41, 40), (53, 50), (None,), (70, 70),
)
EXPECTED_CALLS = {
    "cs_leaf": [("cs_checkpoint", False)],
    "cs_normal": [("cs_leaf", False)],
    "cs_tail_first": [("cs_tail_middle", True)],
    "cs_tail_middle": [("cs_leaf", True)],
    "cs_left": [("cs_leaf", True)],
    "cs_right": [("cs_leaf", True)],
    "cs_diamond": [("cs_left", True), ("cs_right", True)],
    "cs_recursive": [("cs_recursive", False), ("cs_leaf", True)],
    "cs_tail_recursive": [("cs_leaf", True)],
    "cs_indirect": [(None, True)],
    "cs_forward": [("cs_leaf", True)],
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, output, env=None, *, debugger_stderr=False):
    command = list(map(str, command))
    output.with_suffix(".command.json").write_text(json.dumps(command) + "\n")
    with output.with_suffix(".stdout").open("wb") as out, \
            output.with_suffix(".stderr").open("wb") as err:
        result = subprocess.run(command, stdout=out, stderr=err, cwd=ROOT,
                                env={**os.environ, "LC_ALL": "C", **(env or {})}, timeout=90)
    assert result.returncode == 0, (command, result.returncode, output)
    if not debugger_stderr:
        assert not output.with_suffix(".stderr").stat().st_size, output
    return output.with_suffix(".stdout").read_text()


def dwarf_inventory(text, disassembly):
    """Cross-check DWARF calls against independent machine-instruction boundaries."""
    nodes, stack = {}, []
    current = None
    for line in text.splitlines():
        match = re.match(r"\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?", line)
        if match:
            depth, offset, tag = match.groups()
            depth = int(depth)
            stack = stack[:depth]
            current = None
            if tag:
                current = {"tag": tag, "attrs": {}, "parent": stack[-1] if stack else None}
                nodes[int(offset, 16)] = current
                stack.append(current)
        else:
            match = re.match(r"\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)", line)
            if current is not None and match:
                current["attrs"][match[1]] = match[2]

    def name(node):
        return node["attrs"].get("DW_AT_name", "").split(": ")[-1]

    boundaries = {}
    owner = None
    for line in disassembly.splitlines():
        match = re.match(r"[0-9a-f]+ <([^>]+)>:", line)
        if match:
            owner = match[1]
        fields = line.split("\t")
        if len(fields) >= 3 and re.fullmatch(r"\s*[0-9a-f]+:", fields[0]):
            address = int(fields[0].strip()[:-1], 16)
            raw = fields[1].strip().split()
            assert all(re.fullmatch(r"[0-9a-f]+", part) and len(part) % 2 == 0 for part in raw)
            length = sum(len(part) // 2 for part in raw)
            assert length > 0
            boundaries[(owner, address + length)] = (address, " ".join(fields[2:]).strip())

    records = []
    for node in nodes.values():
        if node["tag"] != "DW_TAG_call_site":
            continue
        parent = node["parent"]
        while parent and parent["tag"] != "DW_TAG_subprogram":
            parent = parent["parent"]
        caller = name(parent) if parent else ""
        if caller not in EXPECTED_CALLS:
            continue
        attrs = node["attrs"]
        assert parent["attrs"]["DW_AT_call_all_calls"] == "1", caller
        tail = attrs.get("DW_AT_call_tail_call") == "1"
        return_pc = int(attrs["DW_AT_call_return_pc"], 16)
        address, instruction = boundaries[(caller, return_pc)]
        mnemonic = instruction.split()[0]
        assert mnemonic in (("jmp", "jmpq", "b", "br") if tail else ("call", "callq", "bl")), instruction
        origin = attrs.get("DW_AT_call_origin")
        if origin:
            callee = name(nodes[int(re.fullmatch(r"<0x([0-9a-f]+)>", origin)[1], 16)])
            assert "<" + callee + ">" in instruction, (caller, instruction, callee)
        else:
            callee = None
            assert mnemonic == "br" or re.match(r"jmpq?\s+\*", instruction), instruction
        records.append({"caller": caller, "callee": callee, "tail": tail,
                        "pc": hex(address), "returnPc": hex(return_pc), "instruction": instruction,
                        "targetExpression": attrs.get("DW_AT_call_target")})
    for caller, expected in EXPECTED_CALLS.items():
        actual = [(record["callee"], record["tail"]) for record in records if record["caller"] == caller]
        assert sorted(actual, key=str) == sorted(expected, key=str), (caller, actual, expected)
    assert "DW_OP_entry_value" in text and "DW_AT_call_value" in text
    return records


def check_runtime(data, scenario, mode, role, link_driver):
    assert data["status"] == "OBSERVED" and data["exitCode"] == 0
    frames = data["frames"]
    intermediate = EXPECTED_FRAMES[scenario] if mode == "compiler" else (
        ("cs_normal",) if scenario == 0 else ("cs_recursive",) * 3 if scenario == 4 else ())
    expected = ("cs_checkpoint", "cs_leaf", *intermediate, "cs_driver", "main")
    assert tuple(frame["name"] for frame in frames) == expected, (scenario, mode, frames)
    assert data["sink"] == EXPECTED_SINK[scenario], data
    for index, frame in enumerate(frames):
        tail = mode == "compiler" and 2 <= index < len(frames) - 2 and (
            scenario in (1, 5, 7) or scenario == 4 and index == 2)
        assert frame["tail"] == tail, (scenario, frame)
        assert ("tail call frame" in frame["info"]) == tail, frame
    if mode == "compiler":
        for frame, entry in zip(frames[1:-2], EXPECTED_ENTRY[scenario], strict=True):
            value = frame["entryValue"]
            assert value["available"] == (entry is not None), (scenario, frame)
            if entry is not None:
                assert value["value"] == entry, (scenario, frame)
        leaf_value = frames[1]["value"]
        if leaf_value["available"]:
            assert leaf_value["value"] == EXPECTED_SINK[scenario], frames[1]
        if scenario in (4, 5):
            depths = [frame["entryDepth"] for frame in frames if "entryDepth" in frame]
            expected_depths = (0, 1, 2, 3) if scenario == 4 else (3,)
            assert all(item["available"] for item in depths), depths
            assert tuple(item["value"] for item in depths) == expected_depths, depths
    bias = int(data["driverAddress"], 16) - link_driver
    assert (bias != 0) == (role == "pie"), (role, bias)
    return {"scenario": scenario, "mode": mode, "frames": list(expected),
            "tailFrames": [f["name"] for f in frames if f["tail"]],
            "entryValues": [f.get("entryValue") for f in frames[1:-2]],
            "runtimeBias": hex(bias), "sink": data["sink"], "exitCode": data["exitCode"],
            "warnings": data["warnings"]}


def debugger(target, binary, scenario, output, sidecar=None):
    env = {"FORGE_CALL_SITE_RESULT": str(output.with_suffix(".json")),
           "FORGE_CALL_SITE_SCENARIO": str(scenario), "FORGE_CALL_SITE_REMOTE": ""}
    command = ["gdb" if target == "x86_64" else "gdb-multiarch", "-q", "-nx", "-batch",
               "-ex", "set pagination off", "-ex", "set confirm off",
               "-ex", "set debuginfod enabled off", "-ex", "set auto-solib-add off",
               "-ex", "set disable-randomization off", "-ex", "set print entry-values both"]
    if sidecar is not None:
        command += ["-ex", 'file "' + str(binary) + '"',
                    "-ex", 'symbol-file "' + str(sidecar) + '"']
    command += ["-x", SCRIPTS / "call-site-reference-gdb.py", binary]
    if target == "x86_64":
        run(command, output, env)
    else:
        # Use the guard-supplied temporary parent; never use /dev/shm or detach.
        with tempfile.TemporaryDirectory(prefix="cs-", dir=os.environ.get("TMPDIR")) as temporary:
            socket = Path(temporary) / "gdb"
            assert len(os.fsencode(socket)) < 108, socket
            with output.with_suffix(".qemu.stdout").open("wb") as out, \
                    output.with_suffix(".qemu.stderr").open("wb") as err:
                qemu_command = ["qemu-aarch64-static", "-L", "/usr/aarch64-linux-gnu",
                                "-g", str(socket), str(binary), str(scenario)]
                output.with_suffix(".qemu.command.json").write_text(json.dumps(qemu_command) + "\n")
                child = subprocess.Popen(qemu_command, stdout=out, stderr=err)
                try:
                    for _ in range(100):
                        assert child.poll() is None, "QEMU exited before debugger startup"
                        listeners = [line.split() for line in Path("/proc/net/unix").read_bytes().splitlines()[1:]]
                        if any(len(row) == 8 and row[3] == b"00010000" and row[7] == os.fsencode(socket) for row in listeners):
                            break
                        time.sleep(0.05)
                    else:
                        raise AssertionError("QEMU socket startup timed out")
                    run(command, output, {**env, "FORGE_CALL_SITE_REMOTE": str(socket)}, debugger_stderr=True)
                    assert child.wait(timeout=5) == 0
                finally:
                    if child.poll() is None:
                        child.terminate()
                        try:
                            child.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
            assert not output.with_suffix(".qemu.stderr").stat().st_size
    # A Python exception may not make GDB fail; require this newly written result.
    data = json.loads(output.with_suffix(".json").read_text())
    warnings = output.with_suffix(".stderr").read_text().splitlines()
    vdso = r"warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index"
    assert all(target == "aarch64" and re.fullmatch(vdso, line) for line in warnings), warnings
    data["warnings"] = [re.sub(r"0x[0-9a-f]+", "<vdso-address>", line) for line in warnings]
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=("x86_64", "aarch64"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--role", choices=("exec", "pie"), default="exec")
    parser.add_argument("--dwarfdump", required=True, type=Path)
    args = parser.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    prefix = "" if args.target == "x86_64" else "aarch64-linux-gnu-"
    versions = {}
    for tool in (prefix + "gcc", prefix + "objdump", "readelf", "llvm-dwarfdump",
                 "gdb" if args.target == "x86_64" else "gdb-multiarch", *(
                     ["qemu-aarch64-static"] if args.target == "aarch64" else [])):
        versions[tool] = run([tool, "--version"], work / ("version-" + tool)).splitlines()[0]
    reference, original = work / "reference", work / "input"
    protected = {str(path): digest(path) for path in (SOURCE, Path(__file__), SCRIPTS / "call-site-reference-gdb.py")}
    flags = ["-O2", "-g", "-gdwarf-5", "-fno-ipa-icf", "-Wall", "-Wextra", "-Werror",
             *(["-fPIE", "-pie"] if args.role == "pie" else ["-fno-pie", "-no-pie"])]
    for name in ("reference", "repeat"):
        run([prefix + "gcc", *flags, SOURCE, "-o", work / name], work / ("build-" + name))
    assert reference.read_bytes() == (work / "repeat").read_bytes()
    (work / "repeat").unlink()
    run([prefix + "objcopy", "--strip-debug", reference, original], work / "strip")
    ref_info, ref_allocated, ref_headers = image(reference)
    input_info, input_allocated, input_headers = image(original)
    assert ref_info["profile"] == input_info["profile"] == [2, 1, 62 if args.target == "x86_64" else 183]
    assert int.from_bytes(original.read_bytes()[16:18], "little") == (3 if args.role == "pie" else 2)
    assert ref_allocated == input_allocated and ref_headers == input_headers
    assert not any(section["name"].startswith(".debug_") for section in input_info["sections"])
    protected.update({str(path): digest(path) for path in (reference, original)})
    raw = run(["readelf", "--debug-dump=info", reference], work / "info")
    run(["readelf", "-h", "-S", "-n", "-l", "--debug-dump=abbrev,aranges,decodedline,frames", reference], work / "gnu")
    run(["readelf", "-h", "-S", "-n", "-l", original], work / "input-gnu")
    disassembly = run([prefix + "objdump", "-d", "-w", reference], work / "instructions")
    calls = dwarf_inventory(raw, disassembly)
    run(["llvm-dwarfdump", "--verify", reference], work / "llvm")
    run([sys.executable, SCRIPTS / "check-dwarfdump.py", reference, work / "strict.log",
         "--tool", args.dwarfdump.resolve(), "--original", original], work / "strict")
    link_driver = int(re.search(r"(?m)^([0-9a-f]+) <cs_driver>:", disassembly)[1], 16)
    rows = []
    for scenario in range(8):
        for mode, binary in (("compiler", reference), ("absent", original)):
            result = debugger(args.target, binary, scenario, work / f"gdb-{scenario}-{mode}")
            rows.append(check_runtime(result, scenario, mode, args.role, link_driver))
        # The known QEMU vDSO warning must reproduce on both unchanged controls.
        assert rows[-1]["warnings"] == rows[-2]["warnings"]
    assert all(digest(Path(path)) == expected for path, expected in protected.items())
    report = {"status": "PASS_COMPILER_REFERENCE", "target": args.target, "role": args.role,
              "scope": "Compiler DWARF and absent-debug controls; no Forge call-site export claim",
              "versions": versions, "calls": calls, "runtime": rows, "preservedSha256": protected}
    (work / "result.json").write_text(json.dumps(report, indent=4) + "\n")
    print(f"call-site-reference=PASS target={args.target} role={args.role} sessions={len(rows)}")


if __name__ == "__main__":
    main()
