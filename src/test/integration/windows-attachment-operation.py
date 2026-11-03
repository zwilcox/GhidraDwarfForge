#!/usr/bin/env python3
"""Exercise production Windows attachment on the actual Windows Ghidra export."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import zlib


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ghidra", "original", "reference", "sidecar", "report-log", "helper", "readelf", "llvm", "checker-bundle", "results"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    require(os.name == "nt", "requires native Windows")
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location("elf_fixture", Path(__file__).with_name("attachment-elf-controller.py"))
    elf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(elf)
    module = args.ghidra.resolve() / "Ghidra/Extensions/GhidraDwarfForge"
    originals = {"original": args.original.resolve(strict=True), "sidecar": args.sidecar.resolve(strict=True),
        "source": Path(str(args.sidecar) + ".c").resolve(strict=True)}
    protected = {str(path): digest(path) for path in [*originals.values(), args.reference.resolve(strict=True)]}
    reports = []
    for line in args.report_log.read_text(encoding="utf-8-sig").splitlines():
        marker = "GhidraDwarfForge report: "
        if marker in line:
            value, end = json.JSONDecoder().raw_decode(line.split(marker, 1)[1])
            reports.append(value)
    require(len(reports) == 1, "expected one actual exporter report")
    report = reports[0]
    for role, path in originals.items():
        key = {"original": "inputSha256", "sidecar": "outputSha256", "source": "sourceSha256"}[role]
        require(report["artifacts"][key].lower() == digest(path), "export report differs from selected " + role)
    report_file = root / "export-report.json"
    report_file.write_text(json.dumps(report) + "\n", encoding="utf-8")
    provenance = root / "provenance"
    provenance.mkdir()
    dependencies = [module / "lib/GhidraDwarfForge.jar",
        args.ghidra / "Ghidra/Framework/Pty/lib/jna-5.14.0.jar",
        args.ghidra / "Ghidra/Framework/Generic/lib/gson-2.9.0.jar"]
    sources = [repo / "src/test/java/ghidradwarfforge/output" / name for name in
        ("WindowsFileSecurityProbe.java", "WindowsAttachmentOperationProbe.java", "WindowsAttachmentRefreshProbe.java")]
    scripts = repo / "src/test/integration/ghidra_scripts"
    retained = [*dependencies, *sources, Path(__file__), args.report_log, module / "lib/GhidraDwarfForge-src.zip",
        Path(__file__).with_name("windows-attachment-headless.ps1"), scripts / "CurateAttachmentRefresh.java",
        scripts / "RenameFixtureFunction.java", Path(__file__).with_name("check-dwarfdump.py")]
    origin = {}
    for path in retained:
        path = path.resolve(strict=True)
        copied = provenance / path.name
        shutil.copyfile(path, copied)
        require(digest(path) == digest(copied), "retained source/dependency mismatch")
        origin[str(path)] = digest(path)
    (provenance / "origin.json").write_text(json.dumps(origin, indent=4) + "\n", encoding="utf-8")
    commands = []

    def run(label, command):
        command = [str(value) for value in command]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              creationflags=subprocess.CREATE_NEW_PROCESS_GROUP) as child:
            timed_out = False
            try:
                stdout, stderr = child.communicate(timeout=600)
            except subprocess.TimeoutExpired:
                timed_out = True
                # Reap the owned headless wrapper's JVM as well as its shell.
                cleanup = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"),
                    "/PID", str(child.pid), "/T", "/F"], capture_output=True, timeout=30)
                (root / (label + ".cleanup.stdout")).write_bytes(cleanup.stdout)
                (root / (label + ".cleanup.stderr")).write_bytes(cleanup.stderr)
                stdout, stderr = child.communicate(timeout=30)
            result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
        (root / (label + ".stdout")).write_bytes(result.stdout)
        (root / (label + ".stderr")).write_bytes(result.stderr)
        commands.append({"label": label, "command": command, "exit": result.returncode, "timedOut": timed_out})
        (root / "commands.json").write_text(json.dumps(commands, indent=4) + "\n", encoding="utf-8")
        require(not timed_out and result.returncode == 0, label + " failed; inspect retained logs")
        return result

    java_bin = Path(os.environ["JAVA_HOME"]) / "bin"
    version = run("java-version", [java_bin / "java.exe", "-version"])
    require(b'version "21.' in version.stderr, "requires Java 21")
    classes = root / "classes"
    classes.mkdir()
    classpath = os.pathsep.join(str(provenance / path.name) for path in dependencies)
    compiled = run("compile", [java_bin / "javac.exe", "--release", "21", "-cp", classpath, "-d", classes,
        *(provenance / path.name for path in sources)])
    require(not compiled.stderr, "unexpected compiler diagnostics")
    checker = args.checker_bundle.resolve(strict=True)
    result = run("operation", [java_bin / "java.exe", "--enable-native-access=ALL-UNNAMED", "-cp",
        str(classes) + os.pathsep + classpath, "ghidradwarfforge.output.WindowsAttachmentOperationProbe",
        report_file, originals["original"], originals["sidecar"], originals["source"], args.helper.resolve(strict=True),
        args.readelf.resolve(strict=True), args.llvm.resolve(strict=True), checker / "libexec/dwarfdump.exe",
        checker / "share/dwarfdump/dwarfdump.conf", root / "owned"])
    require(not result.stderr, "unexpected native operation diagnostics")
    results = json.loads((root / "owned/result.json").read_text(encoding="utf-8"))
    require(len(results["outcomes"]) == 2, "missing operation outcome")

    def verify_live_evidence(path):
        evidence = json.loads(path.read_text(encoding="utf-8"))
        require(evidence["status"] == "PASS" and evidence["policy"] == "gnu-llvm-libdwarf-2.3.2-v1",
            "production validator evidence missing")
        for label in ("gnuReadelf", "llvmDwarfdump", "strictSidecar"):
            require(label in evidence["checks"], "missing live validator " + label)
        for checked in evidence["checks"].values():
            require(checked["exitCode"] == 0 and checked["cleanupComplete"], "validator did not complete cleanly")
            for log in checked["logs"].values():
                path = Path(log["path"])
                require(digest(path) == log["sha256"] and path.stat().st_size == int(log["bytes"]),
                    "validator log no longer matches evidence")
        return evidence

    for case in results["outcomes"]:
        require(Path(case["operation"]["selected"]["source"]) == originals["source"],
            "operation relocated the source path recorded by the exporter")
        target = Path(case["after"]["path"])
        backup = Path(case["backup"]["path"])
        require(digest(backup) == protected[str(originals["original"])], "backup changed original bytes")
        require((backup.stat().st_dev, backup.stat().st_ino) !=
            (target.stat().st_dev, target.stat().st_ino), "backup aliases target")
        directory = target.parent
        verify_live_evidence(directory / "validation.json")
        if case["case"] == "commit":
            payload, order = elf.debuglink_payload(target)
            name = originals["sidecar"].name.encode("ascii") + b"\0"
            name += b"\0" * (-len(name) % 4)
            selected_sidecar = directory / originals["sidecar"].name
            require(payload == name + struct.pack(order + "I", zlib.crc32(selected_sidecar.read_bytes())),
                "installed debuglink name/CRC differs")
            require(digest(target) != digest(backup), "attachment did not change the owned target")
        else:
            require(digest(target) == digest(backup), "rollback did not restore the target")

    # Reopen real saved analyst changes and export against the retained original
    # backup. The attached image must continue failing the import-hash contract.
    committed = next(case for case in results["outcomes"] if case["case"] == "commit")
    target = Path(committed["after"]["path"])
    directory = target.parent
    backup = Path(committed["backup"]["path"])
    previous_sidecar = directory / originals["sidecar"].name
    previous_receipt = directory / "transaction.json"
    preserved_generation = {str(path): digest(path) for path in
        [backup, previous_sidecar, originals["source"], previous_receipt, directory / "validation.json"]}
    attached_hash = digest(target)
    attached_programs = run("attached-programs", [args.readelf, "-lW", target]).stdout
    project = root / "project"
    project.mkdir()
    symbol_text = run("reference-symbols", [args.readelf, "-Ws", args.reference]).stdout.decode("utf-8")

    def address(name):
        values = {int(fields[1], 16) for line in symbol_text.splitlines()
            if len(fields := line.split()) >= 8 and fields[0].rstrip(":").isdigit() and fields[7] == name}
        require(len(values) == 1, "missing or ambiguous compiler reference: " + name)
        return hex(values.pop())

    base = [str(project), "AttachmentRefresh", "-scriptPath", str(scripts)]
    anchor_args = [address("recovered_add"), str(originals["original"]), digest(originals["original"])]

    def headless(label, arguments):
        selected = root / (label + ".arguments.json")
        selected.write_text(json.dumps([str(value) for value in [*base, *arguments]]) + "\n", encoding="utf-8")
        return run(label, ["pwsh", "-NoProfile", "-File", provenance / "windows-attachment-headless.ps1",
            "-GhidraDirectory", args.ghidra, "-ArgumentsFile", selected])

    edited = headless("curate-save", ["-import", originals["original"], "-analysisTimeoutPerFile", "120",
        "-postScript", "RenameFixtureFunction.java", address("recovered_add"), address("recovered_variadic"),
        address("recovered_spin"), "recovered_add", address("fixture_sink"), address("recovered_composite"),
        address("scoped_counter"), "-postScript", "CurateAttachmentRefresh.java", "anchor", *anchor_args,
        "-postScript", "CurateAttachmentRefresh.java", "edit", *anchor_args])
    require(b"curated-refresh-program=PASS mode=edit" in edited.stdout, "analyst changes did not save")
    process = ["-process", originals["original"].name, "-noanalysis", "-readOnly"]
    verify = ["-postScript", "CurateAttachmentRefresh.java", "verify", *anchor_args]
    rejected = directory / "must-not-exist.dbg"
    refused = headless("attached-input-rejection", [*process, *verify, "-postScript", "GhidraDwarfForge.java",
        "--packaged-natives", "--input=" + str(target), "--output=" + str(rejected)])
    require(b"imported executable SHA-256" in refused.stdout and not rejected.exists() and
        not Path(str(rejected) + ".c").exists(), "modified target bypassed the saved import hash")
    fresh = directory / "refreshed.dbg"
    exported = headless("refresh-export", [*process, *verify, "-postScript", "GhidraDwarfForge.java",
        "--packaged-natives", "--input=" + str(backup), "--output=" + str(fresh), *verify])
    require(exported.stdout.count(b"curated-refresh-program=PASS mode=verify") == 2 and
        b"GhidraDwarfForge symbol export PASS" in exported.stdout, "saved backup-based export failed")
    require(digest(target) == attached_hash, "re-export changed the attached target")
    fresh_reports = []
    for line in exported.stdout.decode("utf-8").splitlines():
        if "GhidraDwarfForge report: " in line:
            fresh_reports.append(json.JSONDecoder().raw_decode(line.split("GhidraDwarfForge report: ", 1)[1])[0])
    require(len(fresh_reports) == 1, "missing unique refresh report")
    fresh_report = directory / "refresh-report.json"
    fresh_report.write_text(json.dumps(fresh_reports[0]) + "\n", encoding="utf-8")
    fresh_source = Path(str(fresh) + ".c")
    for key, path in (("inputSha256", backup), ("outputSha256", fresh), ("sourceSha256", fresh_source)):
        require(fresh_reports[0]["artifacts"][key].lower() == digest(path), "refresh report binding differs")
    require(zlib.crc32(fresh.read_bytes()) != zlib.crc32(previous_sidecar.read_bytes()), "refresh CRC did not change")
    request = {"target": str(target), "sidecar": str(fresh), "source": str(fresh_source),
        "exportReport": str(fresh_report), "originalBackup": str(backup), "previousReceipt": str(previous_receipt),
        "previousSidecar": str(previous_sidecar), "previousSource": str(originals["source"]),
        "validatorTools": {"helper": str(args.helper.resolve()), "readelf": str(args.readelf.resolve()),
            "llvm": str(args.llvm.resolve()), "strict": str(checker / "libexec/dwarfdump.exe"),
            "configuration": str(checker / "share/dwarfdump/dwarfdump.conf")}}
    for role, name in (("priorTargetBackup", "prior-target.backup"), ("validationEvidence", "refresh.validation.json"),
            ("receipt", "refresh.receipt.json"), ("recoveryReceipt", "refresh.recovery.json"), ("restoreImage", "refresh.restore.elf")):
        request[role] = str(directory / name)
    selected = root / "refresh.request.json"
    selected.write_text(json.dumps(request, indent=4) + "\n", encoding="utf-8")
    refreshed = run("refresh-attach", [java_bin / "java.exe", "--enable-native-access=ALL-UNNAMED", "-cp",
        str(classes) + os.pathsep + classpath, "ghidradwarfforge.output.WindowsAttachmentRefreshProbe",
        selected, root / "refresh.operation.json"])
    require(b"windows-attachment-curated-refresh=PASS changed-crc=true" in refreshed.stdout and not refreshed.stderr,
        "native refresh did not complete cleanly")
    refresh_evidence = verify_live_evidence(Path(request["validationEvidence"]))
    for role, path in (("exportOriginal", backup), ("sidecar", fresh), ("source", fresh_source), ("exportReport", fresh_report)):
        require(refresh_evidence["inputs"][role]["sha256"] == digest(path), "live refresh input binding differs")
    receipt = json.loads(Path(request["receipt"]).read_text(encoding="utf-8"))
    previous = json.loads(previous_receipt.read_text(encoding="utf-8"))
    require(receipt["mode"] == "REFRESH" and receipt["phase"] == "COMMITTED" and
        receipt["debuglinkCrc32"] == zlib.crc32(fresh.read_bytes()) and
        receipt["files"]["originalBackup"] == previous["files"]["originalBackup"] and
        receipt["files"]["previousReceipt"]["sha256"] == digest(previous_receipt) and
        receipt["files"]["previousSidecar"]["sha256"] == digest(previous_sidecar) and
        receipt["files"]["previousSource"]["sha256"] == digest(originals["source"]), "refresh ancestry differs")
    require(digest(Path(request["priorTargetBackup"])) == attached_hash, "prior target backup differs")
    payload, order = elf.debuglink_payload(target)
    name = fresh.name.encode("ascii") + b"\0"
    name += b"\0" * (-len(name) % 4)
    require(payload == name + struct.pack(order + "I", zlib.crc32(fresh.read_bytes())), "refreshed debuglink differs")
    require(run("refreshed-programs", [args.readelf, "-lW", target]).stdout == attached_programs,
        "refresh changed program headers or section mappings")
    for path, expected in preserved_generation.items():
        require(digest(Path(path)) == expected, "refresh changed previous generation: " + path)
    for path, expected in origin.items():
        require(digest(Path(path)) == expected, "source or dependency changed during refresh")
    for path, expected in protected.items():
        require(digest(Path(path)) == expected, "attachment changed original fixture input")
    (root / "result.json").write_text(json.dumps({"status": "PASS", "protectedInputs": protected,
        "cases": [case["case"] for case in results["outcomes"]] + ["saved-curation-refresh"],
        "refreshReceipt": receipt, "preservedGeneration": preserved_generation,
        "refreshValidation": refresh_evidence,
        "scope": "Windows real-export/live-validator initial attachment, rollback and saved-curation changed-CRC refresh; GDB runtime separate"}, indent=4) + "\n", encoding="utf-8")
    print("windows-attachment-operation-harness=PASS")


if __name__ == "__main__":
    main()
