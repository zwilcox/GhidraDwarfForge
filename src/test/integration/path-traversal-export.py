#!/usr/bin/env python3
"""Exercise real saved-program exports through POSIX directory traversal."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("ghidra", type=Path)
parser.add_argument("--expectation", choices=("fixed", "baseline-reproducer"), default="fixed")
args = parser.parse_args()
repository = Path(__file__).resolve().parents[3]
ghidra = args.ghidra.resolve(strict=True)
root = repository / "build/test-results/path-traversal"
root.mkdir(parents=True, exist_ok=True)
results = Path(tempfile.mkdtemp(prefix="run.", dir=root))
print("path-traversal-results=" + str(results), flush=True)
module = ghidra / "Ghidra/Extensions/GhidraDwarfForge"
wrapper = module / "support/ghidra-dwarf-forge-headless"
scripts = repository / "src/test/integration/ghidra_scripts"
commands = []


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, log, expected=0, cwd=None, environment=None):
    command = [str(value) for value in command]
    commands.append({"command": command, "cwd": str(cwd or repository), "expected": expected})
    (results / "commands.json").write_text(json.dumps(commands, indent=4) + "\n")
    with log.open("w") as output, Path(str(log) + ".stderr").open("w") as errors:
        process = subprocess.run(command, cwd=cwd or repository, env=environment,
            stdout=output, stderr=errors, timeout=300)
    assert process.returncode == expected, (command, process.returncode, str(log))
    return log.read_text()


def unchanged(files):
    for path, checksum in files.items():
        assert digest(path) == checksum, ("protected file changed", str(path))


def project_hashes():
    return {str(path.relative_to(project)): digest(path)
        for path in sorted(project.rglob("*")) if path.is_file()}


def check_project(directory, label):
    observed = project_hashes()
    changed = sorted(key for key in set(observed) | set(saved_project)
        if observed.get(key) != saved_project.get(key))
    # Pinned Ghidra rotates these filesystem index backups even when the
    # Program is opened read-only. Every database, live index and property
    # remains part of the strict byte-preservation assertion.
    housekeeping = {"PathTraversal.rep/idata/~index.bak", "PathTraversal.rep/idata/~journal.bak"}
    (directory / (label + "-project.json")).write_text(json.dumps({
        "hashes": observed, "changed_housekeeping": changed}, indent=4) + "\n")
    assert set(changed) <= housekeeping, ("saved program/project changed", changed)


def report(log):
    assert log.read_text().count("SCRIPT: " + str(module / "ghidra_scripts/GhidraDwarfForge.java")) == 1
    marker = "GhidraDwarfForge report: "
    found = [json.JSONDecoder().raw_decode(line.split(marker, 1)[1])[0]
        for line in log.read_text().splitlines() if marker in line]
    assert len(found) == 1, str(log)
    return found[0]


def validate(artifact, directory):
    run(["readelf", "-hSWn", artifact], directory / "elf.txt")
    for kind in ["info", "abbrev", "aranges", "decodedline", "Ranges", "loc"]:
        run(["readelf", "--debug-dump=" + kind, artifact], directory / (kind + ".txt"))
    run(["llvm-dwarfdump", "--verify", artifact], directory / "llvm.txt")
    run(["python3", repository / "src/test/integration/check-code-address-index.py",
        artifact, "--negative-controls"], directory / "address-index.json")
    run(["python3", repository / "src/test/integration/check-dwarfdump.py", artifact,
        directory / "dwarfdump.txt", "--original", original], directory / "strict-check.txt")
    for log in directory.glob("*.txt.stderr"):
        assert not log.read_bytes(), (str(log), log.read_text())
    assert "No errors." in (directory / "llvm.txt").read_text()
    environment = os.environ.copy()
    environment.update(FORGE_PATH_LABELS=str(results / "labels.json"),
        FORGE_PATH_SOURCE=str(artifact) + ".c")
    run(["gdb-multiarch", "-q", "-nx", "-batch", "-ex", "set pagination off",
        "-ex", "set confirm off", "-ex", "set debuginfod enabled off",
        "-ex", "set auto-solib-add off", "-ex", "set disable-randomization off",
        "-ex", "file " + json.dumps(str(original)),
        "-ex", "symbol-file " + json.dumps(str(artifact)),
        "-x", repository / "src/test/integration/path-traversal-gdb.py"],
        directory / "gdb.txt", cwd=unrelated, environment=environment)
    assert "path-traversal-gdb=PASS" in (directory / "gdb.txt").read_text()
    assert not (directory / "gdb.txt.stderr").read_bytes()


actual = results / "actual files"
logical = results / "lexical lookalikes"
leaf = results / "chosen leaf"
unrelated = results / "unrelated working directory"
project = results / "project"
for directory in [actual, logical, leaf, unrelated, project, actual / "child"]:
    directory.mkdir()
(logical / "link").symlink_to(actual / "child", target_is_directory=True)
reference = actual / "program.reference"
original = actual / "program.elf"
lookalike = logical / original.name
lookalike.write_bytes(b"different input sentinel\n")
run(["gcc", "-Og", "-g", "-gdwarf-5", "-fno-stack-protector", "-fcf-protection=none",
    "-fno-pie", "-no-pie", "-Wl,--build-id=sha1", repository / "src/test/fixtures/minimal.c",
    "-o", reference], results / "compile.txt")
run(["objcopy", "--strip-all", reference, original], results / "strip.txt")
symbols = run(["readelf", "-Ws", reference], results / "symbols.txt")
found = {}
for line in symbols.splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in ("recovered_add", "main"):
        assert fields[7] not in found
        found[fields[7]] = (int(fields[1], 16), int(fields[2]))
assert set(found) == {"recovered_add", "main"}
entry, size = found["recovered_add"]
(results / "labels.json").write_text(json.dumps({"entry": entry, "return": entry + size - 1}, indent=4) + "\n")
run(["objdump", "-d", reference], results / "compiler-disassembly.txt")
run(["llvm-dwarfdump", "--verify", reference], results / "compiler-llvm.txt")
input_metadata = run(["readelf", "-hSWn", original], results / "input-elf.txt")
assert ".debug_" not in input_metadata and ".symtab" not in input_metadata
protected = {path: digest(path) for path in [original, reference, lookalike,
    repository / "src/test/fixtures/minimal.c", module / "lib/GhidraDwarfForge.jar",
    module / "ghidra_scripts/GhidraDwarfForge.java"]}
(results / "protected.json").write_text(json.dumps({str(path): value for path, value in protected.items()}, indent=4) + "\n")
run([ghidra / "support/analyzeHeadless", project, "PathTraversal", "-import", original,
    "-loader", "ElfLoader", "-analysisTimeoutPerFile", "120", "-scriptPath", scripts,
    "-postScript", "PreparePathTraversal.java", hex(entry), hex(found["main"][0])], results / "import.log")
assert "path-traversal-preparation=PASS" in (results / "import.log").read_text()
saved_project = project_hashes()
(results / "project-before.json").write_text(json.dumps(saved_project, indent=4) + "\n")
assert saved_project and any(name.endswith(".gbf") for name in saved_project)
base = [wrapper, "--ghidra-dir=" + str(ghidra), "--project-dir=" + str(project),
    "--project-name=PathTraversal", "--program=" + original.name]
traversed_input = logical / "link/../program.elf"
assert traversed_input.resolve(strict=True) == original
friendly = leaf / "friendly name.elf"
friendly.symlink_to(original)
baseline = args.expectation == "baseline-reproducer"
cases = [("input-traversal", traversed_input, actual / "input-check.dbg", actual / "input-check.dbg"),
    ("output-traversal", original, logical / "link/../chosen [debug].dbg", actual / "chosen [debug].dbg")]
if not baseline:
    cases += [("input-leaf-default", friendly, None, leaf / "friendly name.elf.dbg"),
        ("output-leaf-replacement", original, actual / "linked.dbg", actual / "linked.dbg")]
accepted = []
for name, selected_input, requested_output, intended in cases:
    directory = results / name
    directory.mkdir()
    own_protected = {}
    if name == "output-traversal":
        for path in [intended, Path(str(intended) + ".c"), logical / intended.name,
                logical / (intended.name + ".c")]:
            path.write_bytes(("sentinel " + str(path) + "\n").encode())
        protected_pair = [intended, Path(str(intended) + ".c")] if baseline else [
            logical / intended.name, logical / (intended.name + ".c")]
        own_protected.update({path: digest(path) for path in protected_pair})
    if name == "output-leaf-replacement":
        for path in [intended, Path(str(intended) + ".c")]:
            referent = leaf / (path.name + ".referent")
            referent.write_bytes(b"unrelated symlink referent\n")
            own_protected[referent] = digest(referent)
            path.symlink_to(referent)
    actual_output = logical / intended.name if baseline and name == "output-traversal" else intended
    for iteration in ["first", "repeat"]:
        log = directory / (iteration + ".log")
        command = base + ["--input=" + str(selected_input), "--log=" + str(directory / (iteration + ".headless.log"))]
        if requested_output is not None:
            command += ["--output=" + str(requested_output)]
        expected_failure = baseline and name == "input-traversal"
        run(command, log, expected=10 if expected_failure else 0)
        current = report(log)
        if expected_failure:
            assert current["status"] == "FATAL"
            assert "selected original ELF does not match Ghidra" in log.read_text()
            assert not intended.exists() and not Path(str(intended) + ".c").exists()
        else:
            assert current["status"] in ("SUCCESS", "PARTIAL") and current["failure"] is None
            assert current["counts"]["functionsFailed"] == 0
            artifacts = current["artifacts"]
            assert artifacts["inputPath"] == str(selected_input if name == "input-leaf-default" else original)
            assert artifacts["outputPath"] == str(actual_output)
            assert artifacts["sourcePath"] == str(actual_output) + ".c"
            assert artifacts["inputSha256"] == protected[original]
            assert artifacts["outputSha256"] == digest(actual_output)
            assert artifacts["sourceSha256"] == digest(Path(str(actual_output) + ".c"))
            assert not actual_output.is_symlink() and not Path(str(actual_output) + ".c").is_symlink()
            if iteration == "first":
                shutil.copyfile(actual_output, directory / "first.dbg")
                shutil.copyfile(Path(str(actual_output) + ".c"), directory / "first.dbg.c")
            else:
                assert digest(actual_output) == digest(directory / "first.dbg")
                assert digest(Path(str(actual_output) + ".c")) == digest(directory / "first.dbg.c")
        unchanged(protected)
        unchanged(own_protected)
        check_project(directory, iteration)
        assert friendly.is_symlink() and friendly.resolve(strict=True) == original
        assert not list(actual.glob(".*.staged")) and not list(logical.glob(".*.staged"))
    if not expected_failure:
        validate(actual_output, directory)
    accepted.append({"case": name, "status": "BASELINE-REPRODUCED" if baseline else "PASS",
        "requested_input": str(selected_input), "requested_output": None if requested_output is None else str(requested_output),
        "selected_output": str(actual_output), "protected": {str(path): value for path, value in own_protected.items()}})
    print("path-traversal-case=" + name + " " + accepted[-1]["status"], flush=True)

rejected = []
if not baseline:
    negatives = [("input-alias", original, traversed_input),
        ("source-alias", original, actual / "source-collision.dbg"),
        ("missing-input-parent", results / "absent inputs/program.elf", None)]
    for name, selected_input, destination in negatives:
        if name == "source-alias":
            os.link(original, Path(str(destination) + ".c"))
        before = {path: digest(path) for tree in [actual, logical, leaf]
            for path in tree.rglob("*") if path.is_file()}
        directory = results / name
        directory.mkdir()
        log = directory / "rejection.log"
        command = base + ["--input=" + str(selected_input)]
        if destination is not None:
            command += ["--output=" + str(destination)]
        run(command, log, expected=10)
        failure = report(log)
        assert failure["status"] == "FATAL"
        if name == "missing-input-parent":
            message = failure["failure"]["message"]
            assert "--input=<path>" in message and "--output" not in message, message
            assert not selected_input.parent.exists()
        else:
            assert "aliases the original ELF" in log.read_text()
        unchanged(before)
        unchanged(protected)
        check_project(directory, "rejection")
        assert friendly.is_symlink() and friendly.resolve(strict=True) == original
        rejected.append(name)
        print("path-traversal-rejection=" + name + " PASS", flush=True)

(results / "result.json").write_text(json.dumps({"status": "BASELINE-REPRODUCED" if baseline else "PASS",
    "expectation": args.expectation, "cases": accepted, "rejections": rejected, "original_sha256": protected[original],
    "jar_sha256": protected[module / "lib/GhidraDwarfForge.jar"], "program_database_unchanged": True}, indent=4) + "\n")
print("path-traversal-export=" + ("BASELINE-REPRODUCED" if baseline else "PASS"), flush=True)
