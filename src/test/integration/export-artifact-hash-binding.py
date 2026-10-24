#!/usr/bin/env python3
"""Check installed report/hash observations using explicit retained fixture copies.

This never runs an exporter or infers attachment readiness. Explicitly selected
files are compared with independent Python SHA-256/CRC32/count observations;
reported path and target strings remain untrusted claims.
"""

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from urllib.parse import unquote, urlparse
import zlib


REPOSITORY = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("claims_oracle", Path(__file__).with_name("export-report-claims.py"))
READER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READER)
require, run, encoded = READER.require, READER.run, READER.encoded
ROLES = ("exec", "pie", "exec.no-build-id")
KINDS = ("input", "output", "source")
ARTIFACTS = ("original", "sidecar", "source")


def digests(path):
    sha, crc, count = hashlib.sha256(), 0, 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            sha.update(block)
            crc = zlib.crc32(block, crc)
            count += len(block)
    return {"sha256": sha.hexdigest(), "gnuDebuglinkCrc32": crc, "byteCount": count}


def snapshot(path):
    """Never open a known special file when checking the negative controls."""
    try:
        link = path.lstat()
        attributes = path.stat()
    except FileNotFoundError:
        return {"exists": False}
    result = {"exists": True, "mode": stat.S_IFMT(attributes.st_mode),
              "bytes": attributes.st_size, "mtime_ns": attributes.st_mtime_ns}
    if stat.S_ISLNK(link.st_mode):
        result.update(link=os.readlink(path), link_mtime_ns=link.st_mtime_ns)
    if stat.S_ISREG(attributes.st_mode):
        result.update(digests(path))
    return result


def expected(group):
    report, *selected = group
    claims = READER.claims(READER.DECODER.decode(report.read_text(encoding="utf-8")))
    result = {"claims": claims}
    for name, kind, path in zip(ARTIFACTS, KINDS, selected):
        observed = digests(path)
        agreement = ("MATCHING_REPORTED_SHA256" if observed["sha256"] ==
                     claims["artifacts"][kind + "Sha256"].lower() else "DIFFERENT_REPORTED_SHA256")
        result[name] = {"selectedPath": str(path), "observed": observed, "agreement": agreement}
    return result


def probe(groups, jar, gson, classes, destination, reject=False):
    before = {str(path): snapshot(path) for group in groups for path in group}
    output = run([os.environ.get("JAVA", "java"), "-Xmx64m", "-cp",
                  os.pathsep.join(map(str, (jar, gson, classes))),
                  "ghidradwarfforge.output.ExportArtifactHashBindingProbe",
                  *(["--expect-rejection"] if reject else []),
                  *(path for group in groups for path in group)], destination)
    require({path: snapshot(Path(path)) for path in before} == before, "binding observer changed selected inputs")
    lines = output.splitlines()
    require(len(lines) == len(groups) + 6, "unexpected binding protocol output")
    for index, (name, archive) in enumerate((("binding", jar), ("digests", jar), ("claims", jar), ("gson", gson))):
        require(lines[index].startswith(name + "-class-source="), "missing installed class origin")
        origin = urlparse(lines[index].split("=", 1)[1])
        require(origin.scheme == "file" and Path(unquote(origin.path)).resolve() == archive,
                "binding/dependency did not load from selected installed JAR")
    require(re.fullmatch(r"java-version=21(?:[.+-].*)?", lines[4]) is not None, "actual Java21 required")
    require(lines[5].startswith("max-heap=") and 0 < int(lines[5].split("=")[1]) <= 64 * 1024 * 1024,
            "binding heap is not bounded")
    results = []
    for line, group in zip(lines[6:], groups):
        if reject:
            match = re.fullmatch(r"rejected=([A-Za-z0-9_.$]+) diagnostic=([A-Za-z0-9+/=]+) terminal=([A-Z-]+)", line)
            require(match is not None, "expected rejection returned observations")
            message = base64.b64decode(match[2], validate=True).decode("utf-8", errors="strict")
            require(message.strip(), "empty rejection diagnostic")
            results.append({"exception": match[1], "message": message, "terminal_status": match[3]})
        else:
            require(line.startswith("binding-base64="), "missing binding result")
            value = READER.DECODER.decode(base64.b64decode(line.split("=", 1)[1], validate=True).decode("utf-8", errors="strict"))
            require(value == expected(group), "Java/Python digest, claim, selected-path or agreement differs")
            results.append(value)
    return results


def same_installation(module, receipt, current, *, reader=False):
    role = "reader_module" if reader else "producer_module"
    if str(module) != receipt[role]:
        return False
    suffixes = ("lib/GhidraDwarfForge.jar",) if reader else ("lib/GhidraDwarfForge.jar", "ghidra_scripts/GhidraDwarfForge.java")
    return all(str(module / suffix) in receipt["protected"] and
               current[str(module / suffix)]["sha256"] == receipt["protected"][str(module / suffix)]["sha256"]
               for suffix in suffixes)


def select_parent(module, target, explicit):
    if explicit:
        path = explicit / "result.json" if explicit.is_dir() else explicit
        path = path.resolve(strict=True)
    else:
        candidates = []
        for path in (REPOSITORY / "build/test-results/export-report-claims").glob(target + ".*/result.json"):
            record = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=READER.unique_object)
            if record.get("status") == "PASS" and record.get("target") == target and record.get("reader_module") == str(module):
                candidates.append(path)
        require(len(candidates) == 1, "require exactly one preceding reader result for target/installation")
        path = candidates[0].resolve(strict=True)
    record = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=READER.unique_object)
    require(record["status"] == "PASS" and record["target"] == target and
            len(record["sources"]) == 3 and len(record["retained_artifacts"]) == 9, "incomplete reader parent")
    return path, record


def retain_parent(parent_path, parent, work, protected):
    protected[str(parent_path)] = snapshot(parent_path)
    shutil.copyfile(parent_path, work / "parent-claims-result.json")
    require(snapshot(work / "parent-claims-result.json")["sha256"] == protected[str(parent_path)]["sha256"], "parent receipt copy differs")
    groups, reports, retained = [], [], []
    for role in ROLES:
        records = [record for record in parent["sources"] if record["role"] == role]
        require(len(records) == 1, "missing or repeated parent role")
        record = records[0]
        log, report_file = Path(record["retained_log"]), Path(record["report"])
        require(log.resolve(strict=True) == parent_path.parent / (role + ".export.log") and
                report_file.resolve(strict=True) == parent_path.parent / (role + ".json"), "parent evidence escapes result directory")
        protected[str(log)], protected[str(report_file)] = snapshot(log), snapshot(report_file)
        require(protected[str(log)]["sha256"] == record["log_snapshot"]["sha256"] ==
                record["retained_log_snapshot"]["sha256"] == parent["protected"][record["log"]]["sha256"],
                "parent transcript binding differs")
        require(protected[str(report_file)]["sha256"] == record["report_snapshot"]["sha256"], "parent report binding differs")
        raw_log = log.read_bytes()
        transcript = raw_log.decode("utf-8", errors="strict")
        script = str(Path(parent["producer_module"]) / "ghidra_scripts/GhidraDwarfForge.java")
        require(transcript.count("SCRIPT: " + script) == 1, "wrong parent installed exporter script")
        bodies = [line.split("GhidraDwarfForge report: ", 1)[1] for line in transcript.splitlines()
                  if "GhidraDwarfForge report: " in line]
        require(len(bodies) == 1, "ambiguous parent producer report")
        report, end = READER.DECODER.raw_decode(bodies[0])
        require(bodies[0][end:].strip() == "(GhidraScript)" and
                report_file.read_bytes() == bodies[0][:end].encode("utf-8"), "parent JSON is not exact producer body")
        READER.claims(report)
        profile = READER.PROFILES[parent["target"]]
        require(report["target"] == dict(zip(("architecture", "addressBits", "byteOrder"), profile[:3])), "parent reported target differs")
        copied_log, copied_report = work / log.name, work / report_file.name
        copied_log.write_bytes(raw_log)
        copied_report.write_bytes(report_file.read_bytes())
        group = [copied_report]
        for kind in KINDS:
            original = report["artifacts"][kind + "Path"]
            records = [item for item in parent["retained_artifacts"] if item["original"] == original]
            require(len(records) == 1, "missing or ambiguous selected parent artifact")
            source = Path(records[0]["retained"])
            require(source.resolve(strict=True) == parent_path.parent / f"{role}.{kind}.bytes", "parent byte copy escapes result")
            protected[str(source)] = snapshot(source)
            checksum = report["artifacts"][kind + "Sha256"].lower()
            require(checksum == protected[str(source)]["sha256"] == records[0]["snapshot"]["sha256"] ==
                    parent["protected"][original]["sha256"], "selected parent bytes do not match producer claim")
            destination = work / source.name
            shutil.copyfile(source, destination)
            state = snapshot(destination)
            require(state["sha256"] == checksum, "retained byte copy differs")
            retained.append({"role": role, "kind": kind, "original": original, "parent_copy": str(source),
                             "retained": str(destination), "snapshot": state})
            group.append(destination)
        with group[1].open("rb") as stream:
            header = stream.read(20)
        require(header[:4] == b"\x7fELF" and tuple(header[4:6]) == profile[3:5] and
                int.from_bytes(header[18:20], "little" if header[5] == 1 else "big") == profile[5], "parent ELF profile differs")
        groups.append(group)
        reports.append({"role": role, "parent_log": str(log), "parent_report": str(report_file),
                        "retained_log": str(copied_log), "retained_report": str(copied_report),
                        "log_snapshot": snapshot(copied_log), "report_snapshot": snapshot(copied_report)})
    return groups, reports, retained


def report_copy(work, name, value):
    path = work / (name + ".json")
    path.write_bytes(encoded(value))
    return path


def controls(base_group, work, jar, gson, classes):
    base = READER.DECODER.decode(base_group[0].read_text(encoding="utf-8"))
    changed = []
    for index, original in enumerate(base_group[1:]):
        path = work / ("changed-" + ARTIFACTS[index] + ".bytes")
        shutil.copyfile(original, path)
        with path.open("ab") as stream:
            stream.write(b"\nindependent changed role \xc3\xa9\n")
        require(digests(path)["sha256"] != base["artifacts"][KINDS[index] + "Sha256"].lower(), "mutation did not change digest")
        changed.append(path)
    groups = [[base_group[0], *(changed[index] if mask & (1 << index) else original
                               for index, original in enumerate(base_group[1:]))] for mask in range(1, 8)]
    mismatches = probe(groups, jar, gson, classes, work / "mismatch-subsets")
    for mask, result in enumerate(mismatches, 1):
        require([result[name]["agreement"] for name in ARTIFACTS] ==
                [("DIFFERENT_REPORTED_SHA256" if mask & (1 << index) else "MATCHING_REPORTED_SHA256")
                 for index in range(3)], "mismatch subset was short-circuited or misassigned")
    fifo = work / "opaque-reported-and-selected.fifo"
    os.mkfifo(fifo, mode=0o600)
    try:
        fifo_before = snapshot(fifo)
        link = work / "selected-original-link"
        link.symlink_to(base_group[1].name)
        opaque = copy.deepcopy(base)
        opaque["artifacts"].update(inputPath=str(fifo), outputPath="Z:\\unmounted\\opaque é.dbg",
                                   sourcePath="/missing/opaque\u0000source.c")
        for kind in KINDS:
            opaque["artifacts"][kind + "Sha256"] = opaque["artifacts"][kind + "Sha256"].upper()
        opaque_group = [report_copy(work, "opaque-uppercase", opaque), *base_group[1:]]
        opaque_result = probe([opaque_group], jar, gson, classes, work / "opaque-uppercase")
        require(snapshot(fifo) == fifo_before, "reported FIFO was modified")
        false_target = copy.deepcopy(base)
        false_target["target"] = {"architecture": "unsupported invented target claim",
            "addressBits": 32 if base["target"]["addressBits"] == 64 else 64,
            "byteOrder": "BIG_ENDIAN" if base["target"]["byteOrder"] == "LITTLE_ENDIAN" else "LITTLE_ENDIAN"}
        false_group = [report_copy(work, "false-target-claim", false_target), *base_group[1:]]
        false_result = probe([false_group], jar, gson, classes, work / "false-target-claim")
        rewritten = copy.deepcopy(base)
        rewritten["artifacts"]["sourceSha256"] = digests(changed[2])["sha256"]
        rewritten_group = [report_copy(work, "rewritten-source-hash", rewritten), *base_group[1:3], changed[2]]
        rewritten_result = probe([rewritten_group], jar, gson, classes, work / "rewritten-source-hash")
        plain = work / "same-selected-plain-data"
        plain.write_bytes("plain data, not ELF or synthetic-source provenance: é\n".encode("utf-8"))
        aliased = copy.deepcopy(base)
        for kind in KINDS:
            aliased["artifacts"][kind + "Sha256"] = digests(plain)["sha256"]
        alias_group = [report_copy(work, "plain-data-aliases", aliased), plain, plain, plain]
        alias_result = probe([alias_group], jar, gson, classes, work / "plain-data-aliases")
        link_group = [base_group[0], link, *base_group[2:]]
        link_result = probe([link_group], jar, gson, classes, work / "selected-symlink")
        require(link_result[0]["original"]["selectedPath"] == str(link), "selected symlink spelling was normalized")

        missing = [work / ("must-stay-missing-" + name) for name in ARTIFACTS]
        historical = copy.deepcopy(base)
        historical["counts"].pop("functionStaticVariables")
        historical_path = report_copy(work, "historical-before-missing", historical)
        terminal_groups = [[historical_path, *missing]]
        for status in ("CANCELLED", "FATAL"):
            terminal = copy.deepcopy(base)
            terminal.update(status=status, target=None, artifacts=None, counts=None,
                            native={"libdwarfVersion": None}, failure={"type": "fixture", "message": "fixture"})
            for key in ("sections", *READER.CARDINALITIES.values()):
                terminal[key] = []
            terminal_groups.append([report_copy(work, status.lower() + "-before-missing", terminal), *missing])
        malformed = work / "malformed-before-missing.json"
        malformed.write_bytes(b"{broken json}")
        terminal_groups.append([malformed, *missing])
        report_failures = probe(terminal_groups, jar, gson, classes, work / "report-first-rejections", reject=True)
        require(report_failures[0]["exception"] == "ghidradwarfforge.output.ExportReportClaims$UnsupportedReportShapeException" and
                report_failures[0]["terminal_status"] == "-", "historical report did not fail before selected paths")
        for record, status in zip(report_failures[1:3], ("CANCELLED", "FATAL")):
            require(record["exception"] == "ghidradwarfforge.output.ExportReportClaims$TerminalReportException" and
                    record["terminal_status"] == status, "terminal report was replaced by selected-file failure")
        require(report_failures[3]["exception"] == "java.io.IOException" and
                report_failures[3]["terminal_status"] == "-", "malformed report did not fail as parser IOException")
        require(all(not path.exists() for path in missing), "report-first control created selected files")
        directory = work / "selected-directory"
        directory.mkdir()
        selected_groups = [[base_group[0], missing[0], *base_group[2:]],
                           [base_group[0], directory, *base_group[2:]],
                           [base_group[0], fifo, *base_group[2:]],
                           [fifo, *base_group[1:]]]
        selected_failures = probe(selected_groups, jar, gson, classes, work / "selected-file-rejections", reject=True)
        require(selected_failures[0]["exception"] == "java.nio.file.NoSuchFileException" and
                all(record["exception"] == "java.io.IOException" for record in selected_failures[1:]) and
                all(record["terminal_status"] == "-" for record in selected_failures),
                "nonregular/missing selected input did not fail precisely")
        require(snapshot(fifo) == fifo_before, "FIFO precondition control modified the FIFO")
        for collection in (opaque_result, false_result, rewritten_result, alias_result, link_result):
            require(all(item[role]["agreement"] == "MATCHING_REPORTED_SHA256"
                        for item in collection for role in ARTIFACTS), "positive limited observation did not match")
        return {"mismatch_subsets": mismatches, "opaque_uppercase": opaque_result[0],
                "false_target_claim": false_result[0], "rewritten_source_hash": rewritten_result[0],
                "plain_data_aliases": alias_result[0], "selected_symlink": link_result[0],
                "report_first_rejections": report_failures, "selected_file_rejections": selected_failures,
                "fifo": {"path": str(fifo), "before": fifo_before, "removed_after_test": True},
                "scope": "Rewritten reports and false target/path claims can match selected bytes; no ELF or source authenticity is inferred."}
    finally:
        fifo.unlink(missing_ok=True)


def large_control(base_group, work, jar, gson, classes):
    length = (1 << 31) + 131147
    selected = work / "large-selected-original.bytes"
    writes = [(0, b"independent selected-file observation\x00\xff"),
              ((1 << 31) - 7, bytes(range(32))), (length - 9, b"large-end")]
    recipe = {"byte_count": length, "writes": [{"offset": offset, "hex": data.hex()}
              for offset, data in writes], "scope": "Sparse plain data, not an ELF or attachment fixture"}
    (work / "large-recipe.json").write_text(json.dumps(recipe, indent=4) + "\n")
    try:
        with selected.open("wb") as stream:
            for offset, data in writes:
                stream.seek(offset)
                stream.write(data)
        require(selected.stat().st_size == length and selected.stat().st_blocks * 512 < 1024 * 1024,
                "large selected file is not bounded sparse storage")
        before = snapshot(selected)
        report = READER.DECODER.decode(base_group[0].read_text(encoding="utf-8"))
        report["artifacts"]["inputSha256"] = before["sha256"]
        report_path = report_copy(work, "large-selected-claim", report)
        observations = probe([[report_path, selected, *base_group[2:]]], jar, gson, classes, work / "large")
        require(observations[0]["original"]["observed"]["byteCount"] == length and
                observations[0]["original"]["agreement"] == "MATCHING_REPORTED_SHA256", "large count/hash was truncated")
        require(snapshot(selected) == before, "large selected file changed during observation")
        return {"selected": str(selected), "snapshot": before, "recipe": recipe, "observation": observations[0],
                "removed_after_test": True, "scope": "Streamed bytes only; no native-Windows-large or ELF validity claim"}
    finally:
        selected.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=READER.PROFILES)
    parser.add_argument("--claims-result", type=Path, help="explicit earlier reader result/receipt; this is a retained-export replay")
    parser.add_argument("--large", action="store_true", help="x86-only streamed sparse file above2GiB")
    args = parser.parse_args()
    require(not args.large or args.target == "x86_64", "large installed control is x86-only")
    module = args.module.resolve(strict=True)
    jar = (module / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    script = (module / "ghidra_scripts/GhidraDwarfForge.java").resolve(strict=True)
    gson = (module.parent.parent / "Framework/Generic/lib/gson-2.9.0.jar").resolve(strict=True)
    protected = {str(path): snapshot(path) for path in (jar, script, gson)}
    require(protected[str(gson)]["sha256"] == READER.GSON_SHA256, "unexpected provided Gson")
    parent_path, parent = select_parent(module, args.target, args.claims_result)
    same_reader = same_installation(module, parent, protected, reader=True)
    same_export = same_installation(module, parent, protected)
    parent_gson = str(Path(parent["reader_module"]).parent.parent / "Framework/Generic/lib/gson-2.9.0.jar")
    require(parent["protected"][parent_gson]["sha256"] == READER.GSON_SHA256, "parent reader Gson differs")
    if not args.claims_result:
        require(same_reader and same_export and parent["same_reader_export_installation"],
                "fresh oracle must retain the same producer/reader/binder JAR and script snapshot")
    root = REPOSITORY / "build/test-results/export-artifact-hash-binding"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=args.target + ".", dir=root))
    print(f"export-artifact-hash-binding-results={work}", flush=True)
    groups, reports, retained = retain_parent(parent_path, parent, work, protected)
    classes = work / "classes"
    classes.mkdir()
    run([os.environ.get("JAVAC", "javac"), "--release", "21", "-cp", os.pathsep.join(map(str, (jar, gson))),
         "-d", classes, REPOSITORY / "src/test/java/ghidradwarfforge/output/ExportArtifactHashBindingProbe.java"], work / "compile")
    observations = probe(groups, jar, gson, classes, work / "first")
    require(probe(groups, jar, gson, classes, work / "repeat") == observations, "binding observation differs on repeat")
    require(all(item[name]["agreement"] == "MATCHING_REPORTED_SHA256" for item in observations for name in ARTIFACTS),
            "real selected copies did not match producer claims")
    negative_controls = controls(groups[0], work, jar, gson, classes)
    large = large_control(groups[0], work, jar, gson, classes) if args.large else None
    require({path: snapshot(Path(path)) for path in protected} == protected, "protected parent/module evidence changed")
    require(all(snapshot(Path(item["retained"])) == item["snapshot"] for item in retained), "retained artifact changed")
    require(all(snapshot(Path(item["retained_log"])) == item["log_snapshot"] and
                snapshot(Path(item["retained_report"])) == item["report_snapshot"] for item in reports),
            "retained producer transcript/report changed")
    result = {"status": "PASS", "target": args.target, "module": str(module),
              "parent_reader_module": parent["reader_module"], "producer_module": parent["producer_module"],
              "same_reader_installation": same_reader, "same_export_installation": same_export,
              "export_evidence": "explicit retained-export replay" if args.claims_result else "preceding same-installation reader oracle",
              "parent_claims_result": str(parent_path), "parent_claims_sha256": protected[str(parent_path)]["sha256"],
              "protected": protected, "reports": reports, "retained_artifacts": retained,
              "observations": observations, "controls": negative_controls, "large": large,
              "preservation_scope": "before/after this invocation; prior original paths and archive mtimes are not re-attested",
              "scope": "Three selected-file byte observations against unauthenticated claims; no snapshot, ELF, source, identity or attachment proof"}
    (work / "result.json").write_text(json.dumps(result, indent=4) + "\n")
    print(f"export-artifact-hash-binding-{args.target}=PASS", flush=True)


if __name__ == "__main__":
    main()
