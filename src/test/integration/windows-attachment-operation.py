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
    for name in ("ghidra", "original", "sidecar", "report-log", "helper", "readelf", "llvm", "checker-bundle", "results"):
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
    protected = {str(path): digest(path) for path in originals.values()}
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
        ("WindowsFileSecurityProbe.java", "WindowsAttachmentOperationProbe.java")]
    retained = [*dependencies, *sources, Path(__file__), args.report_log, module / "lib/GhidraDwarfForge-src.zip"]
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
        result = subprocess.run(command, capture_output=True, timeout=600)
        (root / (label + ".stdout")).write_bytes(result.stdout)
        (root / (label + ".stderr")).write_bytes(result.stderr)
        commands.append({"label": label, "command": command, "exit": result.returncode})
        (root / "commands.json").write_text(json.dumps(commands, indent=4) + "\n", encoding="utf-8")
        require(result.returncode == 0, label + " failed; inspect retained logs")
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
    for case in results["outcomes"]:
        require(Path(case["operation"]["selected"]["source"]) == originals["source"],
            "operation relocated the source path recorded by the exporter")
        target = Path(case["after"]["path"])
        backup = Path(case["backup"]["path"])
        require(digest(backup) == protected[str(originals["original"])], "backup changed original bytes")
        require((backup.stat().st_dev, backup.stat().st_ino) !=
            (target.stat().st_dev, target.stat().st_ino), "backup aliases target")
        directory = target.parent
        evidence = json.loads((directory / "validation.json").read_text(encoding="utf-8"))
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
    for path, expected in protected.items():
        require(digest(Path(path)) == expected, "attachment changed original fixture input")
    (root / "result.json").write_text(json.dumps({"status": "PASS", "protectedInputs": protected,
        "cases": [case["case"] for case in results["outcomes"]],
        "scope": "Windows real-export/live-validator initial attachment and rollback; GDB runtime and refresh separate"}, indent=4) + "\n", encoding="utf-8")
    print("windows-attachment-operation-harness=PASS")


if __name__ == "__main__":
    main()
