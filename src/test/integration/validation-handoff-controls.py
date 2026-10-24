#!/usr/bin/env python3
"""Run rejection controls through the actual connected fixture entry point."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def snapshot(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    state = path.stat()
    return {"sha256": digest.hexdigest(), "bytes": state.st_size,
            "mtime_ns": state.st_mtime_ns}


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=4)
        stream.write("\n")


def run_controls(args, work):
    folder = work / "validation-gate-controls"
    folder.mkdir()
    manifest = args.report_manifest.resolve(strict=True)
    base = json.loads(manifest.read_text(encoding="utf-8"))
    require(base["schemaVersion"] == 2, "gate controls require the accepted schema2 handoff")
    paths = [manifest, *(path.resolve(strict=True) for path in
        (args.original, args.gnu_candidate, args.debug_file, args.source, args.reference)),
        (args.module / "lib/GhidraDwarfForge.jar").resolve(strict=True)]
    before = {str(path): snapshot(path) for path in paths}
    sentinel = folder / "unexpected-java"
    sentinel.write_text("#!/usr/bin/env python3\nimport os\nfrom pathlib import Path\n"
        "Path(os.environ['FORGE_UNEXPECTED_JAVA_MARKER']).write_text('invoked\\n')\n"
        "raise SystemExit(97)\n", encoding="utf-8")
    sentinel.chmod(0o700)
    cases = []
    legacy = copy.deepcopy(base)
    legacy.update(schemaVersion=1)
    legacy.pop("validationEvidence")
    cases.append(("legacy-not-captured", legacy, "NOT_CAPTURED", "NOT_CAPTURED"))
    changed = copy.deepcopy(base)
    changed["validationEvidence"]["sha256"] = "0" * 64
    cases.append(("stale-index-digest", changed, "validation index digest differs", "NOT_VERIFIED"))
    changed = copy.deepcopy(base)
    changed["validationEvidence"]["path"] = str(folder / "missing-index.json")
    cases.append(("missing-index", changed, "missing-index.json", "NOT_VERIFIED"))
    changed = copy.deepcopy(base)
    changed.pop("validationEvidence")
    cases.append(("missing-schema2-evidence", changed, "invalid explicit handoff", "NOT_VERIFIED"))
    changed = copy.deepcopy(base)
    changed["schemaVersion"] = True
    cases.append(("boolean-schema", changed, "invalid explicit handoff", "NOT_VERIFIED"))
    changed = copy.deepcopy(base)
    changed["attachmentReady"] = True
    cases.append(("unexpected-approval-field", changed, "invalid explicit handoff", "NOT_VERIFIED"))
    records = []
    for label, value, diagnostic, evidence_status in cases:
        case = folder / label
        case.mkdir()
        selected_manifest = case / "handoff.json"
        write_json(selected_manifest, value)
        result = case / "consumer"
        marker = case / "unexpected-java-invoked"
        command = [sys.executable, str(Path(__file__).with_name("reported-candidate-preparation.py")),
            str(args.module), args.target, *(str(path) for path in
                (args.original, args.gnu_candidate, args.debug_file, args.source, args.reference)),
            str(result), "--report-manifest", str(selected_manifest), "--role", args.role]
        if args.retained_export:
            command.append("--retained-export")
        environment = {**os.environ, "JAVA": str(sentinel), "JAVAC": str(sentinel),
            "FORGE_UNEXPECTED_JAVA_MARKER": str(marker), "LC_ALL": "C"}
        write_json(case / "command.json", command)
        with (case / "stdout").open("xb") as stdout, (case / "stderr").open("xb") as stderr:
            completed = subprocess.run(command, stdout=stdout, stderr=stderr,
                env=environment, timeout=45, check=False)
        write_json(case / "process.json", {"returncode": completed.returncode,
            "java_sentinel": str(sentinel), "java_marker": str(marker), "timeout_seconds": 45})
        require(completed.returncode > 0, label + " did not reject normally")
        require(not marker.exists(), label + " reached Java/compiler before rejecting evidence")
        gate = json.loads((result / "validation-gate.json").read_text(encoding="utf-8"))
        require(gate["status"] == "REJECTED" and gate["writer_invoked"] is False and
                gate["evidence_status"] == evidence_status and diagnostic in gate["diagnostic"],
                label + " did not preserve its specific pre-construction failure")
        require(not any((result / name).exists() for name in ("classes", "workspace", "result.json")) and
                not list(result.glob("prepare-*")) and not list(result.rglob("candidate.elf")),
                label + " left normal preparation outputs")
        records.append({"label": label, "manifest": str(selected_manifest),
            "manifest_snapshot": snapshot(selected_manifest), "result": str(result),
            "gate": gate, "returncode": completed.returncode, "java_invocations": 0})
    require({str(path): snapshot(path) for path in paths} == before,
            "gate controls changed selected inputs or the valid handoff")
    evidence = {"status": "PASS", "records": records, "protected_before_after": before,
        "scope": "Six malformed/legacy handoffs enter the real consumer, reject before Java/compiler or normal candidate construction, and preserve selected inputs. This is separate from raw Java-probe limitation controls and core selected-byte/log/tool tampering tests."}
    write_json(folder / "result.json", evidence)
    return evidence
