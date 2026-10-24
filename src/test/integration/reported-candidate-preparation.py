#!/usr/bin/env python3
"""Exercise connected private preparation from one explicit retained report handoff.

These are fixture observations, never attachment approval or report authentication.
The original executable and ordinary export workflow are not modified.
"""

import argparse
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
from urllib.parse import unquote, urlparse


REPOSITORY = Path(__file__).resolve().parents[3]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


owned = load("owned_oracle", "owned-debuglink-candidate.py")
binder = load("binding_oracle", "export-artifact-hash-binding.py")
allocation = load("allocation_oracle", "matched-elf-allocations.py")
reader, prefix = binder.READER, allocation.PREFIX
content, program = owned.content, owned.program
require, record, snapshot = owned.require, owned.record, binder.snapshot
INVENTORIES = tuple(reader.CARDINALITIES.values())
ORIGINS = ("binding", "claims", "digests", "prefix", "allocations", "build-id", "elf", "target",
           "owned-candidate", "candidate-content", "program-bytes", "gson")


def inventories(report):
    result = {key: copy.deepcopy(report[key]) for key in INVENTORIES}
    for entry in result["failedFunctions"]:
        entry["address"] = hex(int(entry["address"], 16))
    for entry in result["omittedLocations"]:
        for field in ("startAddress", "endAddress"):
            entry[field] = hex(int(entry[field], 16))
    return result


def build_id(path):
    """Independently parse bounded ordinary note containers and physical provenance."""
    image = allocation.metadata(path)
    views = [("SECTION", s["index"], s["offset"], s["size"], s["alignment"])
             for s in image["sections"] if s["type"] == 7 and s["size"]]
    views += [("SEGMENT", s["index"], s["offset"], s["file_size"], s["alignment"])
              for s in image["segments"] if s["type"] == 4 and s["file_size"]]
    require(len(views) <= 128, "ordinary note oracle bound exceeded")
    found, identities = {}, set()
    with path.open("rb") as stream:
        for kind, index, offset, size, declared in views:
            alignment = max(4, declared)
            require(alignment in (4, 8) and size <= 1024 * 1024, "unsupported ordinary note view")
            stream.seek(offset)
            data = stream.read(size)
            require(len(data) == size, "truncated ordinary note container")
            position = 0
            while position < size:
                require(size - position >= 12, "truncated note header")
                names, length, tag = struct.unpack_from(image["order"] + "III", data, position)
                descriptor = position + ((12 + names + alignment - 1) // alignment) * alignment
                end = position + ((descriptor - position + length + alignment - 1) // alignment) * alignment
                require(position + 12 + names <= descriptor <= end <= size, "note fields outside container")
                if tag == 3 and data[position + 12:position + 12 + names] == b"GNU\0" and length:
                    identities.add(data[descriptor:descriptor + length].hex())
                    location = offset + position
                    value = found.setdefault(location, {"noteOffset": location,
                        "descriptorOffset": offset + descriptor, "descriptorSize": length, "containers": []})
                    require((value["descriptorOffset"], value["descriptorSize"]) ==
                            (offset + descriptor, length), "inconsistent duplicate note view")
                    value["containers"].append({"kind": kind, "index": index, "offset": offset, "size": size,
                        "declaredAlignment": declared, "alignment": alignment})
                position = end
    require(len(identities) <= 1, "ordinary fixture has conflicting build IDs")
    return {"hex": next(iter(identities), None), "occurrences": [found[key] for key in sorted(found)]}


def elf_observations(group, observed):
    _, original, sidecar, _ = group
    model = prefix.expected(original, sidecar)
    actual = observed["prefix"]
    require({key: actual[key] for key in ("status", "originalByteCount", "candidateByteCount",
            "comparedExtent", "firstDifferentOffset")} ==
            dict(zip(("status", "originalByteCount", "candidateByteCount", "comparedExtent", "firstDifferentOffset"),
                     (model["status"], model["original"], model["candidate"], model["extent"], model["different"]))),
            "connected prefix observation differs from independent bytes")
    require(actual["diagnostic"].strip(), "empty prefix diagnostic")
    actual = observed["allocations"]
    require(actual["diagnostic"].strip(), "empty allocation diagnostic")
    left_image, right_image = allocation.metadata(original), allocation.metadata(sidecar)
    unsupported_names = left_image["sections"][left_image["names"]]
    no_allocation = (not any(allocation.active(s) for s in left_image["sections"] + right_image["sections"]) and
                     not any(s["type"] == 4 for s in left_image["segments"]))
    if allocation.active(unsupported_names):
        issue = actual["issue"]
        require(actual["status"] == "UNSUPPORTED_CASE" and issue["reason"].strip() and
                (issue["origin"], issue["originalIndex"], issue["candidateIndex"], issue["field"],
                 issue["expected"], issue["observed"]) == ("ORIGINAL_SECTION", left_image["names"],
                    left_image["names"], "sh_name", "retained allocated name", ".shstrtab.old"),
                "allocated original name table did not retain its precise unsupported observation")
        projected = None
    elif no_allocation:
        require(actual["status"] == "NO_ALLOCATION_EVIDENCE" and actual["issue"] is None,
                "no allocation was promoted to matching evidence")
        projected = None
    else:
        projected = allocation.allocation_model(original, sidecar)
    if projected is not None and projected["differences"]:
        first, issue = projected["differences"][0], actual["issue"]
        require(actual["status"] == "DIFFERENT_METADATA" and issue["reason"].strip() and
                (issue["origin"], issue["originalIndex"], issue["candidateIndex"], issue["field"]) ==
                (first["origin"], first["original_index"], first["candidate_index"], first["field"]),
                "wrong indexed allocation issue")
        if first["value_kind"] in ("name", "unexpected"):
            expected = (first["expected"] if first["value_kind"] == "unexpected"
                        else allocation.display_name(first["expected"]))
            require((issue["expected"], issue["observed"]) ==
                    (expected, allocation.display_name(first["observed"])), "allocation name issue differs")
        else:
            require((int(issue["expected"], 0), int(issue["observed"], 0)) ==
                    (first["expected"], first["observed"]), "allocation numeric issue differs")
    elif projected is not None:
        require(actual["status"] == "MATCHING_ALLOCATED_METADATA" and actual["issue"] is None,
                "matching allocation model disagrees")
    left, right = build_id(original), build_id(sidecar)
    relation = ("SAME_BUILD_ID" if left["hex"] else "ABSENT_BOTH") if left["hex"] == right["hex"] else (
        "MISSING_FROM_ORIGINAL" if left["hex"] is None else "MISSING_FROM_SIDECAR" if right["hex"] is None
        else "DIFFERENT_BUILD_IDS")
    require(observed["buildIds"] == {"original": left, "sidecar": right, "relationship": relation},
            "build-ID bytes/physical provenance differ")
    image = program.image(original)
    profiles = [values for values in reader.PROFILES.values() if list(values[3:]) == image["profile"]]
    reported = observed["binding"]["claims"]["target"]
    if image["profile"][2] == 65535:
        status = "UNSUPPORTED_TARGET"
        require(observed["target"]["status"] == status and observed["target"]["reported"] == reported and
                observed["target"]["diagnostic"].strip() and "observed" not in observed["target"],
                "unknown ELF machine did not preserve target unsupported evidence")
    else:
        require(len(profiles) == 1, "unexpected ordinary fixture profile")
        target = dict(zip(("architecture", "addressBits", "byteOrder"), profiles[0][:3]))
        status = "MATCHING_REPORTED_TARGET" if target == reported else "DIFFERENT_REPORTED_TARGET"
        require(observed["target"] == {"reported": reported, "observed": target, "status": status},
                "reported target agreement differs")
    reasons = []
    for label, value, matching in (("prefix", model["status"], "MATCHING_COPIED_PREFIX"),
            ("allocations", actual["status"], "MATCHING_ALLOCATED_METADATA"), ("target", status, "MATCHING_REPORTED_TARGET")):
        if value != matching:
            reasons.append(label + ":" + value)
    if relation not in ("SAME_BUILD_ID", "ABSENT_BOTH"):
        reasons.insert(len(reasons) - (1 if status != "MATCHING_REPORTED_TARGET" else 0), "buildIds:" + relation)
    return reasons


def prepare(group, name, parent, jar, gson, classes, destination, failure=None):
    before = {str(path): snapshot(path) for path in group}
    entries = set(parent.iterdir()) if parent.is_dir() else None
    text = program.run([os.environ.get("JAVA", "java"), "-Xmx64m", "-cp",
        os.pathsep.join(map(str, (jar, gson, classes))), "ghidradwarfforge.output.ReportedCandidatePreparationProbe",
        *(["--expect-rejection"] if failure else []), *group, base64.b64encode(name).decode("ascii"), parent], destination)
    require({path: snapshot(Path(path)) for path in before} == before, "preparation changed a selected input")
    lines = text.splitlines()
    require(len(lines) == 15 and lines[14].startswith("preparation-base64="), "incomplete connected protocol")
    for index, label in enumerate(ORIGINS):
        require(lines[index].startswith(label + "-class-source="), "missing connected class origin")
        uri = urlparse(lines[index].split("=", 1)[1])
        require(uri.scheme == "file" and Path(unquote(uri.path)).resolve() == (gson if label == "gson" else jar),
                "connected helper was not loaded from installed dependency")
    require(re.fullmatch(r"java-version=21(?:[.+-].*)?", lines[12]) and lines[13].startswith("max-heap=") and
            0 < int(lines[13].split("=")[1]) <= 64 * 1024 * 1024, "actual Java21/64MiB required")
    result = json.loads(base64.b64decode(lines[14].split("=", 1)[1], validate=True).decode("utf-8", errors="strict"),
                        object_pairs_hook=reader.unique_object)
    construction = result["construction"]
    if failure:
        exception, terminal, action = failure
        require(result["failure"]["exception"] == exception and result["failure"]["terminalStatus"] == terminal and
                result["failure"]["diagnostic"].strip() and construction["action"] == action and
                construction["reasons"] == ["IO_FAILURE"], "incorrect connected typed failure or action")
        require((set(parent.iterdir()) == entries) if entries is not None else not parent.exists(),
                "failed connected invocation left scratch output")
        if "binding" in result:
            require(result["binding"] == binder.expected(group) and result["inventories"] ==
                    inventories(reader.DECODER.decode(group[0].read_text(encoding="utf-8"))),
                    "typed ELF/writer failure lost complete preceding report observations")
        if "target" in result:
            require(not elf_observations(group, result), "writer failure had mismatching earlier observations")
        return result
    require("failure" not in result, "unexpected connected failure")
    report = reader.DECODER.decode(group[0].read_text(encoding="utf-8"))
    require(result["binding"] == binder.expected(group) and result["inventories"] == inventories(report),
            "detailed binding/inventory changed or discarded report information")
    mismatches = [role + ":DIFFERENT_REPORTED_SHA256" for role in binder.ARTIFACTS
                  if result["binding"][role]["agreement"] != "MATCHING_REPORTED_SHA256"]
    if mismatches:
        require(set(result) == {"binding", "inventories", "construction"}, "hash mismatch still accessed ELF helpers")
        reasons = mismatches
    else:
        reasons = elf_observations(group, result)
    if reasons:
        require(construction == {"action": "NOT_CREATED", "reasons": reasons} and set(parent.iterdir()) == entries,
                "mismatching observations created scratch output or lost reasons")
    else:
        require(construction["action"] == "CREATED", "matching observations did not reach writer")
        directory, candidate = Path(construction["directory"]), Path(construction["candidate"])
        require(directory.is_absolute() and not directory.is_symlink() and directory.resolve(strict=True) == directory and
                directory.parent == parent.resolve(strict=True) and directory.name.startswith("forge-debuglink-") and
                candidate == directory / "candidate.elf" and not candidate.is_symlink() and candidate.is_file() and
                set(parent.iterdir()) == entries | {directory} and set(directory.iterdir()) == {candidate},
                "connected result does not transfer exactly one fresh owned candidate")
        wanted = content.expected((name, group[1], candidate, group[2]))
        require(construction["content"] == wanted and wanted["sidecar_digest"] == result["binding"]["sidecar"]["observed"],
                "returned candidate postconditions/digest disagree")
        owned.layout(group[1], candidate, group[2], name)
    return result


def handoff(manifest, target, module, jar, script, work, protected, retained_export=False):
    manifest = manifest.resolve(strict=True)
    state = snapshot(manifest)
    value = json.loads(manifest.read_text(encoding="utf-8"), object_pairs_hook=reader.unique_object)
    require(set(value) == {"schemaVersion", "target", "claimsResult"} and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and
            value["target"] == target and set(value["claimsResult"]) == {"path", "sha256"}, "invalid explicit handoff")
    selected = Path(value["claimsResult"]["path"])
    require(selected.is_absolute() and ".." not in selected.parts and selected.resolve(strict=True) == selected,
            "handoff result path must be explicit and real")
    parent, retained = reader.validate_handoff_parent(selected, target)
    require(retained[str(selected)]["sha256"] == value["claimsResult"]["sha256"], "handoff result digest differs")
    protected.update({str(manifest): state, **{path: snapshot(Path(path)) for path in retained}})
    folder = work / "reported-export"
    folder.mkdir()
    shutil.copyfile(manifest, folder / "handoff.json")
    groups, reports, copies = binder.retain_parent(selected, parent, folder, protected)
    current = {str(path): snapshot(path) for path in (jar, script)}
    same_producer = binder.same_installation(module, parent, current)
    same_reader = binder.same_installation(module, parent, current, reader=True)
    require(retained_export or (same_producer and same_reader),
            "default connected consumer requires current producer/reader identities; explicit retained replay required")
    return groups, {"manifest": str(manifest), "snapshot": state, "retained_manifest": str(folder / "handoff.json"),
        "claims_result": str(selected), "claims_result_sha256": value["claimsResult"]["sha256"],
        "producer_module": parent["producer_module"], "reader_module": parent["reader_module"],
        "same_export_installation": same_producer, "same_reader_installation": same_reader,
        "explicit_retained_export": retained_export,
        "reports": reports, "copies": copies,
        "scope": "Explicit retained completed export; same installation requires module path plus JAR and script SHA. No fresh export, authenticated receipt or atomic file snapshot is inferred."}


def controls(group, name, work, jar, gson, classes):
    folder = work / "controls"
    folder.mkdir()
    original_report = reader.DECODER.decode(group[0].read_text(encoding="utf-8"))
    records = []

    def expected_bad_dwarf(path):
        destination = folder / "invalid-dwarf-validator"
        command = ["llvm-dwarfdump", "--verify", str(path)]
        record(Path(str(destination) + ".command.json"), command)
        try:
            result = subprocess.run(command, capture_output=True, timeout=45, env={**os.environ, "LC_ALL": "C"})
        except subprocess.TimeoutExpired as failure:
            Path(str(destination) + ".stdout").write_bytes(failure.stdout or b"")
            Path(str(destination) + ".stderr").write_bytes(failure.stderr or b"")
            record(Path(str(destination) + ".status.json"), {"timeout_seconds": 45})
            raise
        Path(str(destination) + ".stdout").write_bytes(result.stdout)
        Path(str(destination) + ".stderr").write_bytes(result.stderr)
        record(Path(str(destination) + ".status.json"), {"returncode": result.returncode, "environment": {"LC_ALL": "C"}})
        text = (result.stdout + result.stderr).decode("utf-8", errors="strict")
        require(result.returncode > 0 and "error:" in text and
                (".debug_info" in text or "unit" in text.lower()), "invalid DWARF did not fail its independent validator")
        return {"prefix": str(destination), "returncode": result.returncode,
                "scope": "Expected LLVM rejection of the changed sidecar, despite matching connected content observations."}

    def check(label, report, selected=None, failure=None, missing_parent=False):
        path = folder / (label + ".json")
        path.write_bytes(report if isinstance(report, bytes) else reader.encoded(report))
        parent = folder / (label + ".workspace")
        if not missing_parent:
            parent.mkdir()
        selected = list(group[1:]) if selected is None else selected
        actual = prepare([path, *selected], name, parent, jar, gson, classes, folder / label, failure)
        records.append({"label": label, "report": str(path), "selected": list(map(str, selected)),
                        "parent": str(parent), "observation": actual})
        return actual

    changed = []
    for kind, path in zip(binder.KINDS, group[1:]):
        output = folder / ("changed-" + kind)
        shutil.copyfile(path, output)
        with output.open("ab") as stream:
            stream.write(b"independent mismatching selected bytes\n")
        changed.append(output)
    for mask in range(1, 8):
        check("hash-subset-" + str(mask), original_report,
              [changed[i] if mask & (1 << i) else path for i, path in enumerate(group[1:])])
    for label, target in (("wrong-target", {"architecture": "x86_64" if original_report["target"]["architecture"] != "x86_64" else "aarch64",
            "addressBits": 64, "byteOrder": "LITTLE_ENDIAN"}),
            ("unknown-target", {"architecture": "unknown analyst target é", "addressBits": 64, "byteOrder": "LITTLE_ENDIAN"})):
        report = copy.deepcopy(original_report)
        report["target"] = target
        check(label, report)
    for label in ("unsupported-machine", "unsupported-allocation", "no-allocation-evidence"):
        before, after = folder / (label + ".original"), folder / (label + ".sidecar")
        shutil.copyfile(group[1], before)
        shutil.copyfile(group[2], after)
        image = program.image(before)
        if label == "unsupported-machine":
            for selected in (before, after):
                with selected.open("r+b") as stream:
                    stream.seek(18)
                    stream.write(struct.pack(image["order"] + "H", 65535))
        else:
            indices = ([image["names"]] if label == "unsupported-allocation" else
                       [s["index"] for s in image["sections"] if s["flags"] & 2])
            for index in indices:
                section = image["sections"][index]
                flags = section["flags"] | 2 if label == "unsupported-allocation" else section["flags"] & ~2
                content.set_field(before, index, "flags", flags)
            if label == "no-allocation-evidence":
                for section in program.image(after)["sections"]:
                    if section["flags"] & 2:
                        content.set_field(after, section["index"], "flags", section["flags"] & ~2)
                for segment in image["programs"]:
                    if segment["type"] == 4:
                        with before.open("r+b") as stream:
                            stream.seek(image["phoff"] + segment["index"] * image["phsize"])
                            stream.write(struct.pack(image["order"] + "I", 0))
            # Preserve the matched sidecar's masked ELF header and appended table,
            # while applying exactly the original raw-table/PH changes to its prefix.
            with before.open("rb") as left, after.open("r+b") as right:
                for offset, size in ((image["shoff"], len(image["sections"]) * image["shsize"]),
                                     (image["phoff"], image["phcount"] * image["phsize"])):
                    left.seek(offset)
                    right.seek(offset)
                    right.write(left.read(size))
        report = copy.deepcopy(original_report)
        report["artifacts"].update(inputSha256=binder.digests(before)["sha256"], outputSha256=binder.digests(after)["sha256"])
        actual = check(label, report, [before, after, group[3]])
        require(actual["construction"]["action"] == "NOT_CREATED" and
                actual["prefix"]["status"] == "MATCHING_COPIED_PREFIX", "unsupported/no-evidence gate was not isolated")
    for label in ("rewritten-code", "rewritten-allocation", "rewritten-build-id", "invalid-appended-dwarf"):
        path = folder / (label + ".dbg")
        shutil.copyfile(group[2], path)
        image = program.image(path)
        if label == "rewritten-allocation":
            section = next(s for s in image["sections"] if s["name"] == ".text")
            content.set_field(path, section["index"], "address", section["address"] + 1)
        elif label == "rewritten-build-id":
            observation = build_id(path)
            require(observation["occurrences"], "exec control needs build-ID evidence")
            program.flip(path, observation["occurrences"][0]["descriptorOffset"])
        else:
            section = next(s for s in image["sections"] if s["name"] ==
                           (".text" if label == "rewritten-code" else ".debug_info") and s["size"])
            if label == "invalid-appended-dwarf":
                require(section["offset"] >= group[1].stat().st_size, "DWARF control must be outside copied original")
                with path.open("r+b") as stream:
                    stream.seek(section["offset"])
                    stream.write(b"\xff" * section["size"])
            else:
                program.flip(path, section["offset"])
        report = copy.deepcopy(original_report)
        report["artifacts"]["outputSha256"] = binder.digests(path)["sha256"]
        actual = check(label, report, [group[1], path, group[3]])
        require(actual["construction"]["action"] == ("CREATED" if label == "invalid-appended-dwarf" else "NOT_CREATED"),
                "rewritten-claim control did not demonstrate its independent limitation")
        if label == "invalid-appended-dwarf":
            records[-1]["validator_rejection"] = expected_bad_dwarf(path)
    path = folder / "unresolved-source.dbg"
    shutil.copyfile(group[2], path)
    original_source = Path(original_report["artifacts"]["sourcePath"])
    old_directory = os.fsencode(str(original_source.parent))
    missing_directory = b"/" + b"x" * (len(old_directory) - 1)
    require(len(missing_directory) > 1 and not Path(os.fsdecode(missing_directory)).exists(),
            "source-path negative requires an absent equal-length directory")
    offsets = []
    with path.open("r+b") as stream:
        for section in program.image(path)["sections"]:
            if section["name"] not in (".debug_str", ".debug_line_str", ".debug_line"):
                continue
            require(section["offset"] >= group[1].stat().st_size, "source directory must be in appended debug bytes")
            stream.seek(section["offset"])
            data = stream.read(section["size"])
            cursor = 0
            while (position := data.find(old_directory, cursor)) >= 0:
                offsets.append(section["offset"] + position)
                stream.seek(section["offset"] + position)
                stream.write(missing_directory)
                cursor = position + len(old_directory)
    require(offsets, "DWARF source-directory counterexample did not change a recorded path")
    report = copy.deepcopy(original_report)
    report["artifacts"]["outputSha256"] = binder.digests(path)["sha256"]
    actual = check("unresolved-dwarf-source", report, [group[1], path, group[3]])
    require(actual["construction"]["action"] == "CREATED", "source-path content counterexample did not create")
    candidate = Path(actual["construction"]["candidate"])
    adjacent = candidate.parent / os.fsdecode(name)
    with adjacent.open("xb") as output, path.open("rb") as selected:
        shutil.copyfileobj(selected, output)
    expected_source = str(Path(os.fsdecode(missing_directory)) / original_source.name)
    diagnostic = folder / "unresolved-source-gdb-error.json"
    gdb_script = folder / "unresolved-source-gdb.py"
    gdb_script.write_text("import gdb, json, re\nfrom pathlib import Path\n"
        "symbol = gdb.lookup_global_symbol('recovered_add') or gdb.lookup_static_symbol('recovered_add')\n"
        "assert symbol is not None and symbol.is_function and symbol.symtab is not None\n"
        f"assert Path(symbol.symtab.objfile.filename).resolve() == Path({str(adjacent)!r}).resolve()\n"
        f"assert symbol.symtab.fullname() == {expected_source!r}, symbol.symtab.fullname()\n"
        "listing = gdb.execute('list recovered_add', to_string=True)\n"
        f"assert re.fullmatch(r'warning: [0-9]+\\t' + re.escape({expected_source!r}) + r': No such file or directory\\n', listing), repr(listing)\n"
        f"Path({str(diagnostic)!r}).write_text(json.dumps({{'source': symbol.symtab.fullname(), 'warning': listing}}))\n"
        "print('unresolved-source=PASS')\n", encoding="utf-8")
    empty = folder / "empty-debug-root"
    empty.mkdir()
    stdout, stderr = owned.execute(["gdb-multiarch", "-q", "-nx", "-batch",
        "-ex", "set debuginfod enabled off", "-ex", "set auto-solib-add off",
        "-ex", f"set debug-file-directory {empty}", "-ex", f'file "{candidate}"', "-x", gdb_script],
        folder / "unresolved-source-gdb")
    require(not stderr and b"unresolved-source=PASS" in stdout, "missing recorded source was not proven by GDB")
    owned.diagnostics(stdout, stderr)
    records[-1]["source_lookup_rejection"] = {"script": str(gdb_script), "diagnostic": str(diagnostic),
        "old_directory_hex": old_directory.hex(), "new_directory_hex": missing_directory.hex(), "offsets": offsets,
        "scope": "Static automatic symbol lookup succeeds; actual GDB list fails for the changed DWARF path. No inferior execution."}
    report = copy.deepcopy(original_report)
    report["artifacts"]["sourceSha256"] = binder.digests(changed[2])["sha256"]
    report["artifacts"].update(inputPath="opaque\u0000input", outputPath="Z:\\unmounted\\é.dbg", sourcePath="/missing/é.c")
    actual = check("rewritten-source-opaque-paths", report, [group[1], group[2], changed[2]])
    require(actual["construction"]["action"] == "CREATED", "source content is not a source-correlation proof")
    report = copy.deepcopy(original_report)
    report["failedFunctions"].append({"name": "é\n雪", "address": "0xffffffffffffffff", "diagnostic": "opaque failure 雪"})
    report["skippedFunctions"] += [{"name": "é", "reason": "future reason é"}] * 2
    report["omittedLocations"].append({"function": "雪", "variable": "é", "kind": "LOCAL", "startAddress": "0x0",
        "endAddress": "0x1", "reason": "future reason", "diagnostic": "opaque omission"})
    report["unsupportedConstructs"].append({"kind": "future kind", "name": "é", "diagnostic": "opaque construct"})
    report["diagnostics"] += ["", "opaque text 雪", "opaque text 雪"]
    for count, inventory in reader.CARDINALITIES.items():
        report["counts"][count] = len(report[inventory])
    report["status"] = "PARTIAL"
    actual = check("unclassified-inventories", report)
    require(actual["construction"]["action"] == "CREATED" and actual["binding"]["claims"]["validationStatus"] == "NOT_RUN",
            "inventory text was treated as an approval or exclusion policy")
    missing = [folder / ("missing-" + kind) for kind in binder.KINDS]
    historical = copy.deepcopy(original_report)
    historical["counts"].pop("functionStaticVariables")
    check("historical-before-missing", historical, missing,
          ("ghidradwarfforge.output.ExportReportClaims$UnsupportedReportShapeException", "-", "NOT_CREATED"))
    for status in ("CANCELLED", "FATAL"):
        terminal = copy.deepcopy(original_report)
        terminal.update(status=status, target=None, artifacts=None, counts=None,
            native={"libdwarfVersion": None}, failure={"type": "fixture", "message": "fixture"})
        for key in ("sections", *INVENTORIES):
            terminal[key] = []
        check(status.lower() + "-before-missing", terminal, missing,
              ("ghidradwarfforge.output.ExportReportClaims$TerminalReportException", status, "NOT_CREATED"))
    check("late-malformed-before-missing", reader.encoded(original_report) + b" trailing", missing,
          ("java.io.IOException", "-", "NOT_CREATED"))
    check("missing-selected", original_report, missing, ("java.nio.file.NoSuchFileException", "-", "NOT_CREATED"))
    malformed = folder / "malformed.elf"
    malformed.write_bytes(b"not an ELF\n")
    report = copy.deepcopy(original_report)
    report["artifacts"]["inputSha256"] = binder.digests(malformed)["sha256"]
    check("malformed-selected-elf", report, [malformed, group[2], group[3]], ("java.io.IOException", "-", "NOT_CREATED"))
    check("missing-writer-parent", original_report, failure=("java.nio.file.NoSuchFileException", "-", "FAILED"),
          missing_parent=True)
    require(all(not path.exists() for path in missing), "rejection controls created advertised missing files")
    return {"records": records,
        "scope": "No inferior execution on control candidates. Separate expected LLVM rejection proves invalid DWARF, and one static GDB lookup/list control proves a missing recorded source path. Rewritten reports can bind invalid appended DWARF or unrelated source; matching observations never authenticate reports or approve attachment."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=reader.PROFILES)
    for name in ("original", "gnu_candidate", "debug_file", "source", "reference", "result_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--report-manifest", type=Path, required=True)
    parser.add_argument("--role", choices=binder.ROLES, required=True)
    parser.add_argument("--controls", action="store_true")
    parser.add_argument("--retained-export", action="store_true",
                        help="explicit earlier exporter/reader replay; not a new export by this installation")
    args = parser.parse_args()
    module, original, gnu, sidecar, source, reference = (path.resolve(strict=True) for path in
        (args.module, args.original, args.gnu_candidate, args.debug_file, args.source, args.reference))
    jar = (module / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    script = (module / "ghidra_scripts/GhidraDwarfForge.java").resolve(strict=True)
    gson = (module.parent.parent / "Framework/Generic/lib/gson-2.9.0.jar").resolve(strict=True)
    require(snapshot(gson)["sha256"] == reader.GSON_SHA256, "unexpected provided Gson")
    adapter = REPOSITORY / "src/test/java/ghidradwarfforge/output/ReportedCandidatePreparationProbe.java"
    work = args.result_dir.absolute()
    work.mkdir(parents=True, exist_ok=False)
    work = work.resolve(strict=True)
    print("reported-candidate-preparation-results=" + str(work), flush=True)
    protected = {str(path): snapshot(path) for path in (jar, script, gson, adapter, original, gnu, sidecar, source, reference)}
    groups, parent_report = handoff(args.report_manifest, args.target, module, jar, script, work, protected,
                                    args.retained_export)
    group = [groups[binder.ROLES.index(args.role)][0], original, sidecar, source]
    report = reader.DECODER.decode(group[0].read_text(encoding="utf-8"))
    require(all(binder.digests(path)["sha256"] == report["artifacts"][kind + "Sha256"].lower()
                for kind, path in zip(binder.KINDS, group[1:])), "selected current files differ from explicit producer report")
    parent_gnu = owned.parent_evidence(args, module, jar, script, original, gnu, sidecar, work)
    for item in parent_gnu["program_reference"]["records"] + parent_gnu["content_records"]:
        protected[item["source"]] = snapshot(Path(item["source"]))
    for path in (Path(__file__), Path(owned.__file__), Path(binder.__file__), Path(reader.__file__),
                 REPOSITORY / "src/test/integration/automatic-association-gdb.py"):
        protected[str(path)] = snapshot(path)
    with program.preserve(tuple(map(Path, protected)), work):
        copies = []
        for label, path in (("original", original), ("gnu-candidate", gnu), ("sidecar", sidecar),
                            ("synthetic-source", source), ("compiler-reference", reference)):
            output = work / ("input." + label)
            shutil.copyfile(path, output)
            require(snapshot(output)["sha256"] == protected[str(path)]["sha256"], "connected input evidence copy differs")
            copies.append({"role": label, "source": str(path), "retained": str(output), "snapshot": snapshot(output)})
        record(work / "full-unclassified-inventories.json", {"report_status": report["status"],
            "validation_status": report["validation"]["status"], "inventories": inventories(report),
            "policy": "Complete ordered text, no severity classification or attachment approval."})
        print(json.dumps({"report_status": report["status"], "validation_status": report["validation"]["status"],
                          "unclassified_inventories": inventories(report)}, ensure_ascii=False), flush=True)
        classes, workspace, empty_root = (work / name for name in ("classes", "workspace", "empty-debug-root"))
        for directory in (classes, workspace, empty_root):
            directory.mkdir()
        shutil.copyfile(adapter, work / adapter.name)
        program.run([os.environ.get("JAVAC", "javac"), "--release", "21", "-cp",
                     os.pathsep.join(map(str, (jar, gson))), "-d", classes, adapter], work / "compile")
        tools = {label: owned.tool_identity(label, name, work) for label, name in
                 (("readelf", "readelf"), ("llvm", "llvm-dwarfdump"), ("gdb", "gdb-multiarch"))}
        if args.target != "x86_64":
            tools["qemu"] = owned.tool_identity("qemu", owned.runtime_prefix(args.target)[0], work)
        name = os.fsencode(sidecar.name)
        observations = [prepare(group, name, workspace, jar, gson, classes, work / f"prepare-{index}") for index in range(2)]
        candidates = [Path(item["construction"]["candidate"]) for item in observations]
        require(candidates[0] != candidates[1] and snapshot(candidates[0])["sha256"] == snapshot(candidates[1])["sha256"],
                "connected deterministic fresh outputs differ")
        layouts = [owned.layout(original, candidate, sidecar, name) for candidate in candidates]
        candidate = candidates[0]
        candidate_before = snapshot(candidate)
        validators = []
        for label, command in (("header", ["readelf", "-h", candidate]), ("programs", ["readelf", "-lW", candidate]),
                ("sections", ["readelf", "-SW", candidate]), ("notes", ["readelf", "-n", candidate]),
                ("llvm", ["llvm-dwarfdump", "--verify", candidate])):
            stdout, stderr = owned.execute(command, work / ("candidate-" + label))
            require(not stderr and (label != "llvm" or b"No errors." in stdout), "candidate validator incomplete/diagnosed")
            owned.diagnostics(stdout, stderr)
            validators.append(label)
        adjacent = candidate.parent / sidecar.name
        with adjacent.open("xb") as destination, sidecar.open("rb") as selected:
            shutil.copyfileobj(selected, destination)
        require(content.digest(adjacent) == content.digest(sidecar), "colocated sidecar copy differs")
        stdout, stderr = owned.execute(["readelf", "-Ws", reference], work / "reference-symbols")
        require(not stderr, "compiler symbol reader diagnosed")
        addresses = {"0x" + line.split()[1] for line in stdout.decode("utf-8").splitlines()
                     if line.split() and line.split()[-1] == "recovered_add"}
        require(len(addresses) == 1, "compiler reference address ambiguous")
        runtime = owned.execution(args.target, original, candidate, work)
        debugger = owned.lookup(candidate, adjacent, source, addresses.pop(), empty_root, work / "connected-gdb",
                                runtime=args.target == "x86_64")
        tests = controls(group, name, work, jar, gson, classes) if args.controls else None
        require(snapshot(candidate) == candidate_before and content.digest(adjacent) == content.digest(sidecar),
                "connected runtime/controls changed successful output bytes")
        require({path: snapshot(Path(path)) for path in protected} == protected, "connected invocation changed protected evidence")
        result = {"status": "PASS", "target": args.target, "role": args.role, "module": str(module),
            "jar": snapshot(jar), "script": snapshot(script), "gson": snapshot(gson), "adapter": snapshot(adapter),
            "report_handoff": parent_report, "parent_gnu_reference": parent_gnu, "selected": list(map(str, group)),
            "input_copies": copies,
            "observations": observations, "layouts": layouts, "colocated_debug_file": str(adjacent),
            "colocated_digest": content.digest(adjacent), "tools": tools, "candidate_validators": validators,
            "runtime": runtime, "debugger": debugger, "controls": tests, "protected_before_after": protected,
            "scope": "One connected fixture probe uses the captured report before actual private creation. Separate observations retain PARTIAL/NOT_RUN and full unclassified inventories. GNU reference evidence remains separate. No public attachment, source/DWARF authenticity, validator receipt, snapshot or host-metadata promise."}
    record(work / "result.json", result)
    print("reported-candidate-preparation=PASS", flush=True)


if __name__ == "__main__":
    main()
