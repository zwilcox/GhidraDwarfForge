#!/usr/bin/env python3
"""Check an installed owned writer separately from the retained GNU reference."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
from urllib.parse import unquote, urlparse


REPOSITORY = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("content_test", Path(__file__).with_name("debuglink-candidate-content.py"))
content = importlib.util.module_from_spec(spec)
spec.loader.exec_module(content)
program = content.program
require, snapshot, run = program.require, program.snapshot, program.run


def record(path, value):
    path.write_text(json.dumps(value, indent=4) + "\n", encoding="utf-8")


def execute(command, prefix, environment=None, timeout=60):
    """Retain exact subprocess outcomes, including failures, without broad environment dumps."""
    command = list(map(str, command))
    explicit = {"LC_ALL": "C", **({"LD_LIBRARY_PATH": os.environ["LD_LIBRARY_PATH"]}
                if "LD_LIBRARY_PATH" in os.environ else {}), **(environment or {})}
    record(Path(str(prefix) + ".command.json"), command)
    try:
        result = subprocess.run(command, env={**os.environ, **explicit}, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as failure:
        Path(str(prefix) + ".stdout").write_bytes(failure.stdout or b"")
        Path(str(prefix) + ".stderr").write_bytes(failure.stderr or b"")
        record(Path(str(prefix) + ".status.json"), {"environment": explicit, "timeout_seconds": timeout})
        raise
    Path(str(prefix) + ".stdout").write_bytes(result.stdout)
    Path(str(prefix) + ".stderr").write_bytes(result.stderr)
    record(Path(str(prefix) + ".status.json"), {"environment": explicit, "returncode": result.returncode})
    require(result.returncode == 0, f"subprocess failed: {prefix}")
    return result.stdout, result.stderr


def create(name, original, sidecar, parent, jar, classes, prefix, rejected=None):
    before = set(parent.iterdir()) if parent.is_dir() else None
    flag = (["--expect-argument-rejection"] if rejected == "java.lang.IllegalArgumentException"
            else ["--expect-rejection"] if rejected else [])
    output = run([os.environ.get("JAVA", "java"), "-Xmx64m", "-cp", os.pathsep.join(map(str, (jar, classes))),
                  "ghidradwarfforge.elf.OwnedDebuglinkCandidateProbe", *flag,
                  base64.b64encode(name).decode("ascii"), original, sidecar, parent], prefix)
    lines = output.splitlines()
    require(len(lines) == (8 if rejected else 13), "unexpected owned writer adapter output")
    for index, label in enumerate(("owned-candidate", "candidate-content", "program-bytes", "elf", "digests")):
        require(lines[index].startswith(label + "-class-source="), "missing installed writer origin")
        uri = urlparse(lines[index].split("=", 1)[1])
        require(uri.scheme == "file" and Path(unquote(uri.path)).resolve() == jar,
                "writer/helper did not load from selected installed JAR")
    require(re.fullmatch(r"java-version=21(?:[.+-].*)?", lines[5]), "actual Java21 required")
    require(lines[6].startswith("max-heap=") and 0 < int(lines[6].split("=")[1]) <= 64 * 1024 * 1024,
            "bounded writer heap required")
    if rejected:
        match = re.fullmatch(r"rejected=(\S+) diagnostic=(\S+)", lines[7])
        require(match and match[1] == rejected, "incorrect typed writer rejection")
        require((set(parent.iterdir()) == before) if before is not None else not parent.exists(),
                "rejected creation left an owned directory/candidate")
        return {"exception": match[1], "diagnostic": program.decoded(match[2]), "parent_unchanged": True}
    paths = []
    for label, line in zip(("directory", "candidate"), lines[7:9]):
        require(line.startswith(label + "-base64="), "missing returned owned path")
        value = Path(program.decoded(line.split("=", 1)[1]))
        require(value.is_absolute() and not value.is_symlink() and value.resolve(strict=True) == value,
                "returned path is not an absolute real owned path")
        paths.append(value)
    directory, candidate = paths
    require(directory.parent == parent.resolve(strict=True) and directory.name.startswith("forge-debuglink-") and
            candidate == directory / "candidate.elf" and candidate.is_file() and
            set(parent.iterdir()) == before | {directory} and set(directory.iterdir()) == {candidate},
            "writer did not return exactly one fresh owned candidate")
    rows = [line.split("\t") for line in lines[9:]]
    for row, label, status in zip(rows[:3], ("program-bytes", "allocated-sections", "new-debuglink"),
                                  ("MATCHING_PROGRAM_BYTES", "MATCHING", "MATCHING")):
        require(len(row) == 5 and row[:3] == [label, "0", status] and row[4] == "NONE",
                "writer returned nonmatching construction postconditions")
        program.decoded(row[3])
    require(len(rows[3]) == 5 and rows[3][:2] == ["sidecar-digest", "0"] and
            re.fullmatch(r"[0-9a-f]{64}", rows[3][2]), "invalid writer sidecar digest")
    observed = {"sha256": rows[3][2], "gnuDebuglinkCrc32": int(rows[3][3]), "byteCount": int(rows[3][4])}
    wanted = content.expected((name, original, candidate, sidecar))
    require(wanted == {"program_bytes": {"status": "MATCHING_PROGRAM_BYTES"},
                       "allocated_sections": {"status": "MATCHING"}, "new_debuglink": {"status": "MATCHING"},
                       "sidecar_digest": observed}, "independent predicates disagree with writer")
    return {"directory": str(directory), "candidate": str(candidate), "content": wanted,
            "snapshot": snapshot(candidate), "exclusive_owned_result": True}


def layout(original, candidate, sidecar, name):
    """Reconstruct the complete ordinary-fixture result independently from raw ELF records."""
    require(original.stat().st_size <= 64 * 1024 * 1024, "full layout oracle is bounded to small fixtures")
    raw = original.read_bytes()
    require(raw[:4] == b"\x7fELF" and raw[4] in (1, 2) and raw[5] in (1, 2), "invalid original ELF")
    wide, order = raw[4] == 2, "<" if raw[5] == 1 else ">"
    shoff = struct.unpack_from(order + ("Q" if wide else "I"), raw, 40 if wide else 32)[0]
    size, count, names = struct.unpack_from(order + "HHH", raw, 58 if wide else 46)
    fmt = order + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
    require(size == struct.calcsize(fmt) and shoff != 0, "canonical named section table required")
    zero = struct.unpack_from(fmt, raw, shoff)
    count = count or zero[5]
    names = zero[6] if names == 0xffff else names
    require(0 < count <= 4096 and 0 < names < count and shoff + size * count <= len(raw),
            "ordinary layout section bounds exceeded")
    records = [raw[shoff + i * size:shoff + (i + 1) * size] for i in range(count)]
    old_names = struct.unpack(fmt, records[names])
    raw_names = raw[old_names[4]:old_names[4] + old_names[5]]
    require(len(raw_names) == old_names[5] and raw_names[:1] == b"\0" and raw_names[-1:] == b"\0",
            "invalid original raw name table")
    link_payload = content.payload(name, content.digest(sidecar)["gnuDebuglinkCrc32"], order)
    link_offset = (len(raw) + 3) & ~3
    names_offset = link_offset + len(link_payload)
    appended_names = raw_names + b".gnu_debuglink\0.shstrtab\0"
    alignment = 8 if wide else 4
    table_offset = (names_offset + len(appended_names) + alignment - 1) & -alignment
    new_count, new_names = count + 2, count + 1
    expected = bytearray(raw)
    expected.extend(bytes(link_offset - len(expected)))
    expected.extend(link_payload)
    expected.extend(appended_names)
    expected.extend(bytes(table_offset - len(expected)))
    null = list(zero)
    null[5] = new_count if new_count >= 0xff00 else 0
    null[6] = new_names if new_names >= 0xff00 else 0
    expected.extend(struct.pack(fmt, *null))
    expected.extend(b"".join(records[1:]))
    expected.extend(struct.pack(fmt, len(raw_names), 1, 0, 0, link_offset, len(link_payload), 0, 0, 4, 0))
    expected.extend(struct.pack(fmt, len(raw_names) + len(b".gnu_debuglink\0"), 3, 0, 0,
                                names_offset, len(appended_names), 0, 0, 1, 0))
    struct.pack_into(order + ("Q" if wide else "I"), expected, 40 if wide else 32, table_offset)
    struct.pack_into(order + "HH", expected, 60 if wide else 48,
                     0 if new_count >= 0xff00 else new_count, 0xffff if new_names >= 0xff00 else new_names)
    require(candidate.stat().st_size == len(expected), "candidate length differs from independent append layout")
    actual = candidate.read_bytes()
    require(actual == expected, "owned candidate differs from independent complete append layout")
    return {"complete_candidate_sha256": hashlib.sha256(expected).hexdigest(), "byte_count": len(expected),
            "original_prefix_length": len(raw), "original_section_count": count,
            "new_section_count": new_count, "new_name_index": new_names, "raw_old_records_retained": count - 1,
            "section_zero_info_preserved": null[7] == zero[7], "raw_names_sha256": hashlib.sha256(raw_names).hexdigest(),
            "link_offset": link_offset, "name_table_offset": names_offset, "section_table_offset": table_offset,
            "scope": "Complete ordinary fixture bytes; extended-count boundary coverage belongs to focused tests."}


def parent_evidence(args, module, jar, script, original, candidate, sidecar, work):
    program_parent = content.parent_binding(args, module, jar, script, original, candidate, sidecar, work)
    folder = original.parent / "candidate-content"
    receipt = json.loads((folder / "result.json").read_text(encoding="utf-8"))
    require(receipt["status"] == "PASS" and receipt["target"] == args.target and receipt["module"] == str(module) and
            [receipt[key] for key in ("original", "candidate", "debug_file")] == list(map(str, (original, candidate, sidecar))) and
            receipt["jar"]["sha256"] == snapshot(jar)["sha256"] and
            receipt["script"]["sha256"] == snapshot(script)["sha256"], "GNU content receipt binding failed")
    before = json.loads((folder / "protected-before.json").read_text())
    require(before == json.loads((folder / "protected-after.json").read_text()) == receipt["protected_before_after"],
            "GNU content protection receipts differ")
    for path in (original, candidate, sidecar):
        require(snapshot(path) == before[str(path)], "GNU reference changed before writer invocation")
    wanted = content.expected((os.fsencode(sidecar.name), original, candidate, sidecar))
    require(receipt["observations"] == [wanted, wanted], "GNU independent content observations differ")
    retained = work / "parent-content"
    retained.mkdir()
    records = []
    for name in ("result.json", "protected-before.json", "protected-after.json", "DebuglinkCandidateContentProbe.java",
                 "installed.command.json", "installed.stdout", "installed.stderr"):
        source, output = folder / name, retained / name
        shutil.copyfile(source, output)
        records.append({"source": str(source), "retained": str(output), "sha256": snapshot(source)["sha256"]})
        require(snapshot(output)["sha256"] == records[-1]["sha256"], "GNU content evidence copy changed")
    require(not (retained / "installed.stderr").read_bytes(), "GNU content adapter emitted diagnostics")
    require(snapshot(retained / "DebuglinkCandidateContentProbe.java")["sha256"] == receipt["adapter"]["sha256"],
            "GNU content adapter source differs")
    command = json.loads((retained / "installed.command.json").read_text())
    group = [base64.b64encode(os.fsencode(sidecar.name)).decode("ascii"), *map(str, (original, candidate, sidecar))]
    require(command[1:5] == ["-Xmx64m", "-cp", str(jar) + os.pathsep + str(folder / "classes"),
                            "ghidradwarfforge.elf.DebuglinkCandidateContentProbe"] and command[5:] == group * 2,
            "GNU content installed invocation differs")
    lines = (retained / "installed.stdout").read_text(encoding="utf-8").splitlines()
    require(len(lines) == 14, "GNU content output is incomplete")
    for index, label in enumerate(("candidate-content", "program-bytes", "elf", "digests")):
        require(lines[index].startswith(label + "-class-source="), "GNU content origin missing")
        uri = urlparse(lines[index].split("=", 1)[1])
        require(uri.scheme == "file" and Path(unquote(uri.path)).resolve() == jar, "GNU content origin differs")
    require(re.fullmatch(r"java-version=21(?:[.+-].*)?", lines[4]) and lines[5].startswith("max-heap=") and
            0 < int(lines[5].split("=")[1]) <= 64 * 1024 * 1024, "GNU content runtime differs")
    for index in range(2):
        rows = [line.split("\t") for line in lines[6 + index * 4:10 + index * 4]]
        for row, label, status in zip(rows[:3], ("program-bytes", "allocated-sections", "new-debuglink"),
                                     ("MATCHING_PROGRAM_BYTES", "MATCHING", "MATCHING")):
            require(len(row) == 5 and row[:3] == [label, str(index), status] and row[4] == "NONE",
                    "GNU content raw observation differs")
            program.decoded(row[3])
        observed = wanted["sidecar_digest"]
        require(rows[3] == ["sidecar-digest", str(index), observed["sha256"],
                            str(observed["gnuDebuglinkCrc32"]), str(observed["byteCount"])],
                "GNU content raw selected digest differs")
    return {"program_reference": program_parent, "content_records": records,
            "gnu_candidate": str(candidate), "gnu_candidate_snapshot": snapshot(candidate),
            "writer_provenance": "Installed OwnedDebuglinkCandidate, not the separately retained GNU command.",
            "export_installation_identity_claimed": False}


def diagnostics(stdout, stderr, expected=None):
    lines = (stdout + b"\n" + stderr).decode("utf-8", errors="strict").splitlines()
    matches = 0
    for line in lines:
        if expected is not None and line == expected:
            matches += 1
        elif re.search(r"warning:|error:|malformed|corrupt|could not find", line, re.I):
            raise AssertionError("unexpected debugger diagnostic: " + line)
    require(expected is None or matches > 0, "expected CRC rejection diagnostic missing")


def runtime_prefix(target):
    emulators = {"aarch64": ("/usr/bin/qemu-aarch64-static", "/usr/aarch64-linux-gnu"),
                 "arm32": ("/usr/bin/qemu-arm-static", os.environ.get("FORGE_ARM32_SYSROOT", "/usr/arm-linux-gnueabihf")),
                 "mips32be": ("/usr/bin/qemu-mips-static", "/usr/mips-linux-gnu"),
                 "mips32le": ("/usr/bin/qemu-mipsel-static", "/usr/mipsel-linux-gnu")}
    return [] if target == "x86_64" else [emulators[target][0], "-L", emulators[target][1]]


def tool_identity(label, spelling, work):
    selected = shutil.which(spelling)
    require(selected is not None, "required test tool is unavailable: " + spelling)
    resolved = Path(selected).resolve(strict=True)
    before = snapshot(resolved)
    prefix = work / ("tool-" + label)
    stdout, stderr = execute([spelling, "--version"], prefix)
    require(stdout.strip() and not stderr and snapshot(resolved) == before, "tool version/identity check failed")
    return {"argv_spelling": spelling, "resolved": str(resolved), "snapshot": before,
            "version": stdout.decode("utf-8", errors="strict"), "prefix": str(prefix)}


def lookup(candidate, debug_file, source, address, empty_root, prefix, runtime=False, absent=False):
    environment = {"FORGE_ASSOCIATION_MODE": "absent" if absent else "present",
                   "FORGE_ASSOCIATION_ADDRESS": address, "FORGE_ASSOCIATION_DEBUG_FILE": str(debug_file),
                   "FORGE_ASSOCIATION_SOURCE": str(source), "FORGE_ASSOCIATION_RUNTIME": "1" if runtime else "0"}
    command = ["gdb-multiarch", "-q", "-nx", "-batch", "-ex", "set pagination off", "-ex", "set confirm off",
               "-ex", "set debuginfod enabled off", "-ex", "set auto-solib-add off",
               "-ex", "set disable-randomization off", "-ex", f"set debug-file-directory {empty_root}",
               "-ex", f'file "{candidate}"', "-x", REPOSITORY / "src/test/integration/automatic-association-gdb.py"]
    stdout, stderr = execute(command, prefix, environment, timeout=45)
    expected = (f'warning: the debug information found in "{debug_file}" does not match "{candidate}" (CRC mismatch).'
                if absent else None)
    diagnostics(stdout, stderr, expected)
    marker = "automatic-association=" + environment["FORGE_ASSOCIATION_MODE"] + " PASS"
    require(marker in stdout.decode("utf-8"), "actual automatic GDB association oracle did not finish")
    require(not runtime or b"exited normally" in stdout, "native GDB did not observe a normal exit")
    return {"mode": environment["FORGE_ASSOCIATION_MODE"], "runtime": runtime, "prefix": str(prefix), "marker": marker}


def execution(target, original, candidate, work):
    baseline = work / "runtime-original.elf"
    shutil.copyfile(original, baseline)
    require(snapshot(baseline)["sha256"] == snapshot(original)["sha256"], "runtime baseline copy differs")
    for path in (baseline, candidate):
        path.chmod(path.stat().st_mode | stat.S_IRUSR | stat.S_IXUSR)
    command = runtime_prefix(target)
    outputs = [execute([*command, path], work / ("runtime-" + label), timeout=30)
               for label, path in (("original", baseline), ("candidate", candidate))]
    require(outputs[0] == outputs[1] and not outputs[0][1], "original/candidate runtime outputs differ or diagnose")
    return {"transport": "native" if not command else "QEMU user", "command_prefix": command,
            "baseline_copy": str(baseline), "baseline_sha256": snapshot(baseline)["sha256"],
            "exit_status": 0, "stdout_sha256": hashlib.sha256(outputs[0][0]).hexdigest(), "stderr_empty": True,
            "permission_setup": "Owner read/execute added only to owned runtime copies, not a writer metadata promise."}


def controls(name, original, candidate, sidecar, parent, work, jar, classes):
    folder = work / "controls"
    folder.mkdir()
    groups, mutations = [], []
    image = program.image(candidate)
    text = next(entry for entry in image["sections"] if entry["name"] == ".text" and entry["size"])
    for label in ("program-code", "allocated-address", "link-crc"):
        path = folder / label
        shutil.copyfile(candidate, path)
        if label == "program-code":
            program.flip(path, text["offset"])
        elif label == "allocated-address":
            content.set_field(path, text["index"], "address", text["address"] + 1)
        else:
            link = content.link_section(path)
            program.flip(path, link["offset"] + link["size"] - 1)
        groups.append((name, original, path, sidecar))
        mutations.append({"label": label, "candidate": str(path), "snapshot": snapshot(path)})
    observations = content.probe(groups, jar, classes, folder / "mutated-content")
    for index, key in enumerate(("program_bytes", "allocated_sections", "new_debuglink")):
        require(observations[index][key]["status"] in ("DIFFERENT", "DIFFERENT_PROGRAM_BYTES"),
                "mutation was not independently detected")
    rejected = []
    for label, before in (("existing-association", candidate), ("malformed", folder / "malformed.elf")):
        if label == "malformed":
            before.write_bytes(b"not an ELF\n")
        rejected.append({"label": label, **create(name, before, sidecar, parent, jar, classes, folder / label,
                                                 "java.io.IOException")})
    for index, bad_name in enumerate((b"", b".", b"..", b"a/b", b"a\0b")):
        rejected.append({"label": f"invalid-basename-{index}", **create(bad_name, folder / "missing-original",
                         folder / "missing-sidecar", parent, jar, classes, folder / f"bad-name-{index}",
                         "java.lang.IllegalArgumentException")})
    rejected.append({"label": "missing-parent", **create(name, original, sidecar, folder / "missing-parent", jar,
                     classes, folder / "missing-parent", "java.nio.file.NoSuchFileException")})
    plain = folder / "plain.sidecar"
    plain.write_bytes(b"Independent non-DWARF bytes: matching CRC is not a debug-information verdict.\n")
    plain_before = snapshot(plain)
    plain_result = create(name, original, plain, parent, jar, classes, folder / "plain-selected")
    plain_layout = layout(original, Path(plain_result["candidate"]), plain, name)
    require(snapshot(plain) == plain_before, "plaintext selected input changed")
    return {"mutations": mutations, "observations": observations, "rejections": rejected,
            "plaintext": {"path": str(plain), "snapshot": plain_before, "created": plain_result, "layout": plain_layout},
            "scope": "Plaintext success proves the writer does not establish DWARF validity; focused Java tests own cancellation/I/O seams."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=program.common.PROFILES)
    for name in ("original", "gnu_candidate", "debug_file", "source", "reference", "result_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--controls", action="store_true")
    parser.add_argument("--shared", action="store_true")
    args = parser.parse_args()
    module, original, gnu_candidate, sidecar, source, reference = (value.resolve(strict=True) for value in
        (args.module, args.original, args.gnu_candidate, args.debug_file, args.source, args.reference))
    jar = (module / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    script = (module / "ghidra_scripts/GhidraDwarfForge.java").resolve(strict=True)
    adapter = REPOSITORY / "src/test/java/ghidradwarfforge/elf/OwnedDebuglinkCandidateProbe.java"
    content_adapter = adapter.with_name("DebuglinkCandidateContentProbe.java")
    gdb_script = REPOSITORY / "src/test/integration/automatic-association-gdb.py"
    work = args.result_dir.absolute()
    work.mkdir(parents=True, exist_ok=False)
    work = work.resolve(strict=True)
    print(f"owned-debuglink-candidate-results={work}", flush=True)
    parent = parent_evidence(args, module, jar, script, original, gnu_candidate, sidecar, work)
    classes, workspace, empty_root = (work / name for name in ("classes", "workspace", "empty-debug-root"))
    for directory in (classes, workspace, empty_root):
        directory.mkdir()
    sentinel = workspace / "caller-owned-sentinel"
    sentinel.write_bytes(b"The writer does not own its parent or this preexisting entry.\n")
    records = parent["program_reference"]["records"] + parent["content_records"]
    protected = (original, gnu_candidate, sidecar, source, reference, jar, script, adapter, content_adapter, gdb_script,
                 sentinel, *(Path(item["source"]) for item in records))
    with program.preserve(protected, work) as before:
        copies = []
        for label, path in (("original", original), ("gnu-candidate", gnu_candidate), ("sidecar", sidecar),
                            ("synthetic-source", source), ("compiler-reference", reference)):
            output = work / ("input." + label)
            shutil.copyfile(path, output)
            require(snapshot(output)["sha256"] == before[str(path)]["sha256"], "writer evidence copy differs")
            copies.append({"role": label, "source": str(path), "retained": str(output), "snapshot": snapshot(output)})
        for path in (adapter, content_adapter, gdb_script):
            shutil.copyfile(path, work / path.name)
        require(program.image(original)["profile"] == list(program.common.PROFILES[args.target]), "wrong target fixture")
        tools = {label: tool_identity(label, spelling, work) for label, spelling in
                 (("readelf", "readelf"), ("llvm", "llvm-dwarfdump"), ("gdb", "gdb-multiarch"))}
        if not args.shared and args.target != "x86_64":
            tools["qemu"] = tool_identity("qemu", runtime_prefix(args.target)[0], work)
        run([os.environ.get("JAVAC", "javac"), "--release", "21", "-cp", jar, "-d", classes,
             adapter, content_adapter], work / "compile")
        basename = os.fsencode(sidecar.name)
        require(basename != b"candidate.elf", "test sidecar basename collides with fixed candidate leaf")
        created = [create(basename, original, sidecar, workspace, jar, classes, work / f"create-{index}")
                   for index in range(2)]
        candidate, repeat = (Path(item["candidate"]) for item in created)
        require(candidate != repeat and created[0]["content"] == created[1]["content"] and
                snapshot(candidate)["sha256"] == snapshot(repeat)["sha256"], "fresh writer outputs are not deterministic")
        layouts = [layout(original, path, sidecar, basename) for path in (candidate, repeat)]
        require(layouts[0] == layouts[1], "independent repeat layouts differ")
        candidate_before = snapshot(candidate)
        validators = []
        for label, command in (("header", ["readelf", "-h", candidate]),
                               ("programs", ["readelf", "-lW", candidate]),
                               ("sections", ["readelf", "-SW", candidate]),
                               ("notes", ["readelf", "-n", candidate]),
                               ("llvm", ["llvm-dwarfdump", "--verify", candidate])):
            prefix = work / ("candidate-" + label)
            stdout, stderr = execute(command, prefix)
            require(not stderr, "candidate structural tool emitted diagnostics")
            diagnostics(stdout, stderr)
            require(label != "llvm" or b"No errors." in stdout, "LLVM verifier completion marker missing")
            validators.append({"label": label, "prefix": str(prefix)})
        adjacent = candidate.parent / sidecar.name
        with adjacent.open("xb") as output, sidecar.open("rb") as selected:
            shutil.copyfileobj(selected, output, length=1024 * 1024)
        require(content.digest(adjacent) == content.digest(sidecar), "caller-colocated debug file differs")
        symbol_output, symbol_errors = execute(["readelf", "-Ws", reference], work / "reference-symbols")
        require(not symbol_errors, "reference symbol reader diagnosed input")
        addresses = {"0x" + line.split()[1] for line in symbol_output.decode("utf-8").splitlines()
                     if line.split() and line.split()[-1] == "recovered_add"}
        require(len(addresses) == 1, "compiler reference does not identify exactly one recovered_add address")
        address = addresses.pop()
        runtime = None if args.shared else execution(args.target, original, candidate, work)
        debugger = [lookup(candidate, adjacent, source, address, empty_root, work / "writer-gdb",
                           runtime=not args.shared and args.target == "x86_64")]
        note_output, note_errors = execute(["readelf", "-n", original], work / "original-notes")
        require(not note_errors, "original note reader diagnosed input")
        if b"Build ID:" not in note_output:
            try:
                with adjacent.open("ab") as stream:
                    stream.write(b"\0")
                debugger.append(lookup(candidate, adjacent, source, address, empty_root,
                                       work / "writer-crc-rejected", absent=True))
            finally:
                shutil.copyfile(sidecar, adjacent)
            debugger.append(lookup(candidate, adjacent, source, address, empty_root, work / "writer-crc-restored"))
        require(content.digest(adjacent) == content.digest(sidecar) and snapshot(candidate) == candidate_before,
                "writer candidate or colocated bytes changed during runtime/debugger tests")
        result = {"target": args.target, "module": str(module), "jar": before[str(jar)], "script": before[str(script)],
                  "adapter": before[str(adapter)], "parent_gnu_reference": parent, "input_copies": copies,
                  "original": str(original), "gnu_candidate": str(gnu_candidate), "debug_file": str(sidecar),
                  "source": str(source), "reference": str(reference), "literal_basename_hex": basename.hex(),
                  "created": created, "layouts": layouts, "colocated_debug_file": str(adjacent),
                  "colocated_digest": content.digest(adjacent), "compiler_address": address, "debugger": debugger,
                  "candidate_validators": validators, "tools": tools,
                  "runtime": runtime, "shared_static_lookup_only": args.shared,
                  "scope": "Owned candidate preparation, candidate GNU/LLVM structure, and explicit caller runtime setup on known ASCII fixture paths with explicit basename bytes. No generic argv encoding claim. Sidecar strict validation is earlier evidence, not repeated here. No original replacement, attachment approval or host-metadata promise."}
        if args.controls:
            result["controls"] = controls(basename, original, candidate, sidecar, workspace, work, jar, classes)
        require(snapshot(candidate) == candidate_before, "controls changed the successful writer candidate")
        result["protected_before_after"] = before
    result["status"] = "PASS"
    record(work / "result.json", result)
    print("owned-debuglink-candidate=PASS")


if __name__ == "__main__":
    main()
