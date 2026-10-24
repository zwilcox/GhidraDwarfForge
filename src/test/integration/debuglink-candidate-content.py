#!/usr/bin/env python3
"""Independently check an existing private candidate; never invoke an attachment backend."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
from urllib.parse import unquote, urlparse
import zlib


REPOSITORY = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("program_test", Path(__file__).with_name("executable-program-bytes.py"))
program = importlib.util.module_from_spec(spec)
spec.loader.exec_module(program)
require, snapshot, run = program.require, program.snapshot, program.run
FIELDS = ("type", "flags", "address", "offset", "size", "link", "info", "alignment", "entry_size")
ELF_FIELDS = ("sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size", "sh_link", "sh_info", "sh_addralign", "sh_entsize")


def digest(path):
    sha, crc, count = hashlib.sha256(), 0, 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            sha.update(chunk)
            crc = zlib.crc32(chunk, crc)
            count += len(chunk)
    return {"sha256": sha.hexdigest(), "gnuDebuglinkCrc32": crc, "byteCount": count}


def issue(status, original, candidate, field, expected=None, observed=None):
    value = {"status": status, "original_index": original, "candidate_index": candidate, "field": field}
    if expected is not None:
        value.update(expected=str(expected), observed=str(observed))
    return value


def active(section):
    return section["index"] != 0 and section["type"] != 0 and section["flags"] & 2


def named(metadata):
    return metadata["shoff"] != 0 and metadata["names"] != 0 and metadata["shsize"] == (64 if metadata["wide"] else 40)


def allocation_expected(left, right):
    """Indexed ordinary-fixture projection; the imported model bounds PH/SH counts."""
    if not named(left) or not named(right):
        return issue("UNSUPPORTED", -1, -1, "section table")
    evidence = False
    for entry in left["sections"]:
        if not active(entry):
            continue
        evidence = True
        index = entry["index"]
        if index >= len(right["sections"]):
            return issue("DIFFERENT", index, -1, "section")
        other = right["sections"][index]
        if not active(other):
            return issue("DIFFERENT", index, index, "allocation")
        if entry["name"].encode("ascii") != other["name"].encode("ascii"):
            return issue("DIFFERENT", index, index, "sh_name")
        for key, field in zip(FIELDS, ELF_FIELDS):
            if entry[key] != other[key]:
                return issue("DIFFERENT", index, index, field, entry[key], other[key])
        if entry["type"] != 8 and entry["size"]:
            lo, hi = entry["offset"], entry["offset"] + entry["size"]
            spans = [(p["offset"], p["offset"] + p["size"]) for p in left["programs"] if p["type"] and p["size"]]
            bounds = sorted({lo, hi, *(max(lo, min(hi, point)) for span in spans for point in span)})
            if any(not any(start <= a and b <= end for start, end in spans) for a, b in zip(bounds, bounds[1:])):
                return issue("UNSUPPORTED", index, index, "allocated file coverage")
    for entry in right["sections"]:
        index = entry["index"]
        if active(entry) and (index >= len(left["sections"]) or not active(left["sections"][index])):
            return issue("DIFFERENT", -1, index, "allocation")
    return {"status": "MATCHING" if evidence else "NO_ALLOCATION_EVIDENCE"}


def payload(basename, crc, order):
    name = basename + b"\0"
    return name + bytes(-len(name) % 4) + struct.pack(order + "I", crc)


def link_expected(left, right, candidate, basename, observed_digest):
    if not named(left) or not named(right):
        return issue("UNSUPPORTED", -1, -1, "section table")
    previous = [entry for entry in left["sections"] if entry["name"] == ".gnu_debuglink"]
    if previous:
        return issue("UNSUPPORTED", previous[0]["index"], -1, "initial creation")
    links = [entry for entry in right["sections"] if entry["name"] == ".gnu_debuglink"]
    if len(links) != 1:
        return issue("DIFFERENT", -1, links[1]["index"] if links else -1, ".gnu_debuglink count")
    link = links[0]
    for key, value in (("type", 1), ("flags", 0), ("address", 0), ("link", 0), ("info", 0),
                       ("alignment", 4), ("entry_size", 0)):
        if link[key] != value:
            return issue("DIFFERENT", -1, link["index"], ELF_FIELDS[FIELDS.index(key)], value, link[key])
    wanted = payload(basename, observed_digest["gnuDebuglinkCrc32"], right["order"])
    if link["size"] != len(wanted):
        return issue("DIFFERENT", -1, link["index"], "sh_size", len(wanted), link["size"])
    actual = program.read_at(candidate, link["offset"], link["size"])
    for index, (expected_byte, actual_byte) in enumerate(zip(wanted, actual)):
        if expected_byte != actual_byte:
            return issue("DIFFERENT", -1, link["index"], f"payload byte {index}",
                         f"0x{expected_byte:02x}", f"0x{actual_byte:02x}")
    return {"status": "MATCHING"}


def expected(group):
    basename, original, candidate, sidecar = group
    left, right = program.image(original), program.image(candidate)
    observed = digest(sidecar)
    return {"program_bytes": program.expected(original, candidate),
            "allocated_sections": allocation_expected(left, right),
            "new_debuglink": link_expected(left, right, candidate, basename, observed),
            "sidecar_digest": observed}


def observation(fields, label, index):
    require(len(fields) in (5, 9) and fields[:2] == [label, str(index)], "invalid section observation")
    program.decoded(fields[3])
    result = {"status": fields[2]}
    if len(fields) == 5:
        require(fields[4] == "NONE", "invalid absent section issue")
    else:
        result.update(original_index=int(fields[4]), candidate_index=int(fields[5]),
                      field=program.decoded(fields[6]), expected=program.decoded(fields[7]),
                      observed=program.decoded(fields[8]))
    return result


def probe(groups, jar, classes, prefix, rejected=None):
    arguments = [item for name, original, candidate, sidecar in groups
                 for item in (base64.b64encode(name).decode("ascii"), original, candidate, sidecar)]
    output = run([os.environ.get("JAVA", "java"), "-Xmx64m", "-cp", os.pathsep.join(map(str, (jar, classes))),
                  "ghidradwarfforge.elf.DebuglinkCandidateContentProbe",
                  *(["--expect-argument-rejection" if rejected == "java.lang.IllegalArgumentException"
                     else "--expect-rejection"] if rejected else []), *arguments], prefix)
    lines = output.splitlines()
    require(len(lines) == 6 + len(groups) * (1 if rejected else 4), "unexpected content adapter output")
    for index, label in enumerate(("candidate-content", "program-bytes", "elf", "digests")):
        require(lines[index].startswith(label + "-class-source="), "missing production origin")
        uri = urlparse(lines[index].split("=", 1)[1])
        require(uri.scheme == "file" and Path(unquote(uri.path)).resolve() == jar, "wrong installed production origin")
    require(re.fullmatch(r"java-version=21(?:[.+-].*)?", lines[4]), "actual Java21 required")
    require(lines[5].startswith("max-heap=") and 0 < int(lines[5].split("=")[1]) <= 64 * 1024 * 1024,
            "bounded content observer heap required")
    results = []
    for index, group in enumerate(groups):
        if rejected:
            match = re.fullmatch(r"rejected=(\S+) diagnostic=(\S+)", lines[6 + index])
            require(match and match[1] == rejected, "wrong typed content rejection")
            results.append({"exception": match[1], "diagnostic": program.decoded(match[2])})
            continue
        rows = [line.split("\t") for line in lines[6 + index * 4:10 + index * 4]]
        fields = rows[0]
        require(len(fields) in (5, 8) and fields[:2] == ["program-bytes", str(index)], "invalid program row")
        program.decoded(fields[3])
        byte_result = {"status": fields[2]}
        if len(fields) == 5:
            require(fields[4] == "NONE", "invalid absent program issue")
        else:
            byte_result.update(region=fields[4], offset=None if fields[5] == "-" else int(fields[5]),
                               expected=program.decoded(fields[6]), observed=program.decoded(fields[7]))
        require(len(rows[3]) == 5 and rows[3][:2] == ["sidecar-digest", str(index)] and
                re.fullmatch(r"[0-9a-f]{64}", rows[3][2]), "invalid selected sidecar digest")
        actual = {"program_bytes": byte_result,
                  "allocated_sections": observation(rows[1], "allocated-sections", index),
                  "new_debuglink": observation(rows[2], "new-debuglink", index),
                  "sidecar_digest": {"sha256": rows[3][2], "gnuDebuglinkCrc32": int(rows[3][3]),
                                     "byteCount": int(rows[3][4])}}
        wanted = expected(group)
        for key, value in wanted.items():
            # Numeric and byte issues are exact. Non-numeric reason wording is
            # diagnostic, while status/index/field are the stable structured API.
            projected = {field: actual[key].get(field) for field in value}
            if key == "new_debuglink" and value.get("field", "").startswith("payload byte "):
                for field in ("expected", "observed"):
                    require(re.fullmatch(r"(?:0x)?[0-9a-fA-F]{2}", projected[field]), "invalid byte issue value")
                    projected[field] = f"0x{int(projected[field], 16):02x}"
            require(projected == value and set(actual[key]) - set(value) <= {"expected", "observed"},
                    f"independent content disagreement in {prefix}: {key}: {actual[key]} versus {value}")
        results.append(actual)
    return results


def set_field(path, index, field, value):
    image = program.image(path)
    offsets = (0, 4, 8, 16, 24, 32, 40, 44, 48, 56) if image["wide"] else tuple(range(0, 40, 4))
    keys = ("name_offset", *FIELDS)
    position = keys.index(field)
    width = "Q" if image["wide"] and position in (2, 3, 4, 5, 8, 9) else "I"
    program.write_number(path, image["sections"][index]["header"] + offsets[position], image["order"] + width, value)


def link_section(path):
    return next(entry for entry in program.image(path)["sections"] if entry.get("name") == ".gnu_debuglink")


def replace_payload(path, value):
    link = link_section(path)
    with path.open("ab") as stream:
        offset = stream.tell()
        stream.write(value)
    set_field(path, link["index"], "offset", offset)
    set_field(path, link["index"], "size", len(value))


def controls(name, original, candidate, sidecar, work, jar, classes):
    folder = work / "controls"
    folder.mkdir()
    groups, labels = [], []

    def add(label, before=original, after=None, selected=sidecar, basename=name):
        if after is None:
            after = folder / label
            shutil.copyfile(candidate, after)
        labels.append(label)
        groups.append((basename, before, after, selected))
        return after

    image = program.image(candidate)
    link = link_section(candidate)
    text = next(entry for entry in image["sections"] if entry.get("name") == ".text" and entry["size"])
    path = add("program-code")
    program.flip(path, text["offset"])
    path = add("allocated-address")
    set_field(path, text["index"], "address", text["address"] + 1)
    path = add("link-crc")
    program.flip(path, link["offset"] + link["size"] - 1)
    for field, value in (("type", 8), ("flags", 2), ("address", 1234), ("link", 1), ("info", 1),
                         ("alignment", 8), ("entry_size", 1), ("size", link["size"] + 1)):
        path = add("link-" + field)
        set_field(path, link["index"], field, value)
    path = add("link-name")
    set_field(path, link["index"], "name_offset", text["name_offset"])
    spare = next(entry for entry in image["sections"] if entry["index"] and not active(entry) and
                 entry["index"] not in (image["names"], link["index"]) and entry["type"] != 0)
    path = add("link-duplicate")
    set_field(path, spare["index"], "name_offset", link["name_offset"])
    path = add("link-early-nul")
    program.write_number(path, link["offset"], "B", 0)
    path = add("link-trailer")
    replace_payload(path, program.read_at(candidate, link["offset"], link["size"]) + b"\0")
    short_name = b"x"
    path = add("literal-short", basename=short_name)
    replace_payload(path, payload(short_name, digest(sidecar)["gnuDebuglinkCrc32"], image["order"]))
    bad_padding = add("link-padding", basename=short_name)
    shutil.copyfile(path, bad_padding)
    program.flip(bad_padding, link_section(bad_padding)["offset"] + 2)
    opaque_name = b"\xfe\\opaque"
    path = add("literal-opaque", basename=opaque_name)
    replace_payload(path, payload(opaque_name, digest(sidecar)["gnuDebuglinkCrc32"], image["order"]))
    add("literal-uppercase", after=candidate, basename=name.upper())
    add("existing-association", before=candidate, after=candidate)
    add("no-attachment", after=original)
    changed = folder / "changed-sidecar"
    shutil.copyfile(sidecar, changed)
    program.flip(changed, 0)
    add("changed-sidecar", after=candidate, selected=changed)
    plain = folder / "plain-text-sidecar"
    plain.write_bytes(b"This selected file is plain text, not DWARF.\n")
    path = add("plaintext-crc-match", selected=plain)
    replace_payload(path, payload(name, digest(plain)["gnuDebuglinkCrc32"], image["order"]))
    uncovered = folder / "uncovered.original"
    shutil.copyfile(original, uncovered)
    source_text = next(entry for entry in program.image(original)["sections"] if entry.get("name") == ".text")
    with uncovered.open("ab") as stream:
        offset = stream.tell()
        stream.write(program.read_at(original, source_text["offset"], source_text["size"]))
    set_field(uncovered, source_text["index"], "offset", offset)
    path = add("uncovered-allocation", before=uncovered)
    set_field(path, source_text["index"], "offset", offset)
    # Candidate must remain structurally readable at the changed, unprotected extent.
    with path.open("ab") as stream:
        if stream.tell() < offset + source_text["size"]:
            stream.write(bytes(offset + source_text["size"] - stream.tell()))
    protected = {str(path): snapshot(path) for group in groups for path in group[1:]}
    results = probe(groups, jar, classes, work / "controls-installed")
    require(results[0]["program_bytes"]["status"] == "DIFFERENT_PROGRAM_BYTES" and
            results[1]["program_bytes"]["status"] == results[2]["program_bytes"]["status"] == "MATCHING_PROGRAM_BYTES",
            "complementary predicates were not exercised")
    by_label = dict(zip(labels, results))
    require(all(by_label["plaintext-crc-match"][key]["status"] == "MATCHING" for key in
                ("allocated_sections", "new_debuglink")), "plaintext counterexample failed")
    require(by_label["uncovered-allocation"]["allocated_sections"]["status"] == "UNSUPPORTED",
            "uncovered original allocation was not unsupported")
    malformed = folder / "malformed"
    malformed.write_bytes(b"not an ELF\n")
    invalid = probe([(name, malformed, candidate, sidecar), (name, original, malformed, sidecar)],
                    jar, classes, work / "malformed", "java.io.IOException")
    require(malformed.read_bytes() == b"not an ELF\n", "malformed input changed")
    missing = folder / "missing"
    invalid_names = (b"", b".", b"..", b"a/b", b"nul\0tail", b"x" * 65537)
    arguments = probe([(value, missing, missing, missing) for value in invalid_names], jar, classes,
                      work / "invalid-basenames", "java.lang.IllegalArgumentException")
    require(not os.path.lexists(missing), "argument guard created a selected file")
    require({path: snapshot(Path(path)) for path in protected} == protected, "content controls modified their inputs")
    return {"labels": labels, "groups": [[value.hex(), *map(str, paths)] for value, *paths in groups],
            "results": results, "input_snapshots": protected, "malformed": invalid,
            "invalid_basename_hex": [value.hex() for value in invalid_names], "argument_rejections": arguments,
            "scope": "Plaintext and raw literal names are intentional counterexamples, not DWARF or host-encoding proof."}


def large_control(name, original, candidate, work, jar, classes):
    selected = work / "large.sidecar"
    altered = work / "large.candidate"
    length = (1 << 31) + 131147
    writes = [(0, b"independent selected-file observation\0\xff"), ((1 << 31) - 7, bytes(range(32))),
              (length - 9, b"large-end")]
    try:
        with selected.open("xb") as stream:
            stream.truncate(length)
            for offset, value in writes:
                stream.seek(offset)
                stream.write(value)
        shutil.copyfile(candidate, altered)
        first = digest(selected)
        metadata = program.image(candidate)
        replace_payload(altered, payload(name, first["gnuDebuglinkCrc32"], metadata["order"]))
        before = snapshot(altered)
        first_state = selected.stat()
        matched = probe([(name, original, altered, selected)], jar, classes, work / "large-match")[0]
        after_match = selected.stat()
        require(matched["new_debuglink"]["status"] == "MATCHING" and matched["sidecar_digest"] == first and
                (first_state.st_size, first_state.st_mtime_ns) == (after_match.st_size, after_match.st_mtime_ns),
                "large selected sidecar digest or metadata changed during observation")
        program.flip(selected, length - 1)
        second = digest(selected)
        second_state = selected.stat()
        changed = probe([(name, original, altered, selected)], jar, classes, work / "large-changed")[0]
        after_change = selected.stat()
        require(first != second and changed["sidecar_digest"] == second and
                (second_state.st_size, second_state.st_mtime_ns) == (after_change.st_size, after_change.st_mtime_ns) and
                changed["new_debuglink"]["status"] == "DIFFERENT" and snapshot(altered) == before,
                "large digest complement failed")
        recipe = {"length": length, "writes": [{"offset": offset, "hex": value.hex()} for offset, value in writes],
                  "changed_offset": length - 1, "xor": 1, "first_digest": first, "second_digest": second,
                  "invocation_metadata": [{"bytes": value.st_size, "mtime_ns": value.st_mtime_ns}
                                          for value in (first_state, after_match, second_state, after_change)],
                  "basename_hex": name.hex(), "match": matched, "changed": changed,
                  "candidate": str(altered), "candidate_snapshot": before,
                  "scope": "Full sparse sidecar SHA/CRC/count; unchanged small program input; no DWARF or Windows-large claim."}
        (work / "large-recipe.json").write_text(json.dumps(recipe, indent=4) + "\n")
        return recipe
    finally:
        selected.unlink(missing_ok=True)


def parent_binding(args, module, jar, script, original, candidate, sidecar, work):
    parent_dir = original.parent / "program-bytes"
    receipt = parent_dir / "result.json"
    parent = json.loads(receipt.read_text(encoding="utf-8"))
    require(parent["status"] == "PASS" and parent["target"] == args.target and parent["module"] == str(module),
            "parent program receipt does not describe this invocation")
    require([parent[key] for key in ("original", "candidate", "debug_file")] == list(map(str, (original, candidate, sidecar))),
            "parent selected paths disagree")
    require(parent["jar"]["sha256"] == snapshot(jar)["sha256"] and parent["script"]["sha256"] == snapshot(script)["sha256"],
            "parent observer used a different installed snapshot")
    before = json.loads((parent_dir / "protected-before.json").read_text())
    after = json.loads((parent_dir / "protected-after.json").read_text())
    require(before == after and before == parent["protected_before_after"], "parent protection evidence disagrees")
    for path in (original, sidecar):
        require(snapshot(path) == before[str(path)], "parent input changed before content observation")
    require(snapshot(candidate) == parent["candidate_snapshot"] and
            parent["program_bytes"] == [{"status": "MATCHING_PROGRAM_BYTES"}] * 2 and
            parent["indexed_allocated_metadata_equal"] and parent["separate_debuglink_check"]["exact_creation_contract"],
            "parent candidate binding failed")
    retained = work / "parent-program"
    retained.mkdir()
    names = ["result.json", "protected-before.json", "protected-after.json", "ExecutableProgramBytesProbe.java"]
    names += [stem + suffix for stem in ("objcopy", "objcopy-version") for suffix in
              (".command.json", ".stdout", ".stderr", ".status.json")]
    names += ["installed" + suffix for suffix in (".command.json", ".stdout", ".stderr")]
    records = []
    for name in names:
        source, output = parent_dir / name, retained / name
        shutil.copyfile(source, output)
        records.append({"source": str(source), "retained": str(output), "sha256": snapshot(source)["sha256"]})
        require(snapshot(output)["sha256"] == records[-1]["sha256"], "parent evidence copy changed")
    for stem in ("objcopy", "objcopy-version"):
        status = json.loads((retained / (stem + ".status.json")).read_text())
        require(status.get("returncode") == 0 and status.get("environment") == parent["explicit_tool_environment"] and
                not (retained / (stem + ".stderr")).read_bytes(),
                "parent backend was not quiet and successful")
    require(not (retained / "objcopy.stdout").read_bytes(), "parent backend emitted unexplained stdout")
    command = json.loads((retained / "objcopy.command.json").read_text())
    require(command == [parent["tool"], "--add-gnu-debuglink=" + str(sidecar), str(original), str(candidate)],
            "parent backend command differs")
    require(json.loads((retained / "objcopy-version.command.json").read_text()) == [parent["tool"], "--version"] and
            (retained / "objcopy-version.stdout").read_text() == parent["tool_version"], "parent tool version differs")
    require(snapshot(retained / "ExecutableProgramBytesProbe.java")["sha256"] == parent["adapter"]["sha256"],
            "parent adapter provenance differs")
    command = json.loads((retained / "installed.command.json").read_text())
    require(command[1:4] == ["-Xmx64m", "-cp", str(jar) + os.pathsep + str(parent_dir / "classes")] and
            command[4:] == ["ghidradwarfforge.elf.ExecutableProgramBytesProbe", str(original), str(candidate),
                            str(original), str(candidate)], "parent installed invocation differs")
    lines = (retained / "installed.stdout").read_text(encoding="utf-8").splitlines()
    require(len(lines) == 6 and not (retained / "installed.stderr").read_bytes(), "parent installed output differs")
    for index, label in enumerate(("program-bytes", "elf")):
        require(lines[index].startswith(label + "-class-source="), "parent origin missing")
        uri = urlparse(lines[index].split("=", 1)[1])
        require(uri.scheme == "file" and Path(unquote(uri.path)).resolve() == jar, "parent production origin differs")
    require(re.fullmatch(r"java-version=21(?:[.+-].*)?", lines[2]) and lines[3].startswith("max-heap=") and
            0 < int(lines[3].split("=")[1]) <= 64 * 1024 * 1024, "parent runtime differs")
    for index, line in enumerate(lines[4:]):
        fields = line.split("\t")
        require(len(fields) == 5 and fields[:3] == ["program-bytes", str(index), "MATCHING_PROGRAM_BYTES"] and
                fields[4] == "NONE", "parent byte observations differ")
        program.decoded(fields[3])
    return {"receipt": str(receipt), "records": records, "export_installation_identity_claimed": False,
            "same_observer_installation": True,
            "scope": "Same current candidate/observer snapshot; existing earlier Forge export provenance is not promoted."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=program.common.PROFILES)
    for name in ("original", "candidate", "debug_file", "result_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--controls", action="store_true")
    parser.add_argument("--large", action="store_true")
    args = parser.parse_args()
    require(not args.large or args.target == "x86_64", "large control is Linux x86 only")
    module, original, candidate, sidecar = (value.resolve(strict=True) for value in
                                          (args.module, args.original, args.candidate, args.debug_file))
    jar = (module / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    script = (module / "ghidra_scripts/GhidraDwarfForge.java").resolve(strict=True)
    adapter = REPOSITORY / "src/test/java/ghidradwarfforge/elf/DebuglinkCandidateContentProbe.java"
    work = args.result_dir.absolute()
    work.mkdir(parents=True, exist_ok=False)
    print(f"debuglink-candidate-content-results={work}", flush=True)
    parent = parent_binding(args, module, jar, script, original, candidate, sidecar, work)
    classes = work / "classes"
    classes.mkdir()
    protected = (original, candidate, sidecar, jar, script, adapter,
                 *(Path(record["source"]) for record in parent["records"]))
    with program.preserve(protected, work) as before:
        shutil.copyfile(adapter, work / adapter.name)
        copies = []
        for label, source in (("original", original), ("candidate", candidate), ("sidecar", sidecar)):
            output = work / ("input." + label)
            shutil.copyfile(source, output)
            require(snapshot(output)["sha256"] == before[str(source)]["sha256"], "content evidence copy changed")
            copies.append({"role": label, "source": str(source), "retained": str(output), "snapshot": snapshot(output)})
        require(program.image(original)["profile"] == list(program.common.PROFILES[args.target]), "wrong fixture target")
        run([os.environ.get("JAVAC", "javac"), "--release", "21", "-cp", jar, "-d", classes, adapter], work / "compile")
        basename = os.fsencode(sidecar.name)
        group = (basename, original, candidate, sidecar)
        results = probe([group, group], jar, classes, work / "installed")
        require(results[0] == results[1] and results[0]["program_bytes"]["status"] == "MATCHING_PROGRAM_BYTES" and
                all(results[0][key]["status"] == "MATCHING" for key in ("allocated_sections", "new_debuglink")),
                "ordinary candidate content predicates failed")
        result = {"target": args.target, "module": str(module), "jar": before[str(jar)], "script": before[str(script)],
                  "adapter": before[str(adapter)], "parent_program": parent, "input_copies": copies,
                  "original": str(original), "candidate": str(candidate), "debug_file": str(sidecar),
                  "literal_basename_hex": basename.hex(), "observations": results,
                  "scope": "Separate read-only content predicates on a private backend candidate; no replacement, DWARF, runtime or readiness approval."}
        if args.controls:
            result["controls"] = controls(basename, original, candidate, sidecar, work, jar, classes)
        if args.large:
            result["large"] = large_control(basename, original, candidate, work, jar, classes)
            require(not (work / "large.sidecar").exists(), "large selected-sidecar cleanup failed")
        result["protected_before_after"] = before
    result["status"] = "PASS"
    (work / "result.json").write_text(json.dumps(result, indent=4) + "\n")
    print("debuglink-candidate-content=PASS")


if __name__ == "__main__":
    main()
