#!/usr/bin/env python3
"""Observe owned objcopy candidates before the existing automatic-association GDB test."""

import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
from urllib.parse import unquote, urlparse
import zlib


REPOSITORY = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("prefix_test", Path(__file__).with_name("matched-elf-prefix.py"))
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
require, snapshot, run = common.require, common.snapshot, common.run


def tool_run(command, prefix):
    """Retain backend failure status as well as its exact command and diagnostics."""
    command = list(map(str, command))
    Path(str(prefix) + ".command.json").write_text(json.dumps(command) + "\n")
    evidence = {"environment": {"LC_ALL": "C", **({"LD_LIBRARY_PATH": os.environ["LD_LIBRARY_PATH"]}
                if "LD_LIBRARY_PATH" in os.environ else {})}}
    try:
        result = subprocess.run(command, capture_output=True, timeout=180,
                                env={**os.environ, "LC_ALL": "C"})
    except subprocess.TimeoutExpired as failure:
        Path(str(prefix) + ".stdout").write_bytes(failure.stdout or b"")
        Path(str(prefix) + ".stderr").write_bytes(failure.stderr or b"")
        Path(str(prefix) + ".status.json").write_text(json.dumps({**evidence, "timeout_seconds": 180}) + "\n")
        raise
    Path(str(prefix) + ".stdout").write_bytes(result.stdout)
    Path(str(prefix) + ".stderr").write_bytes(result.stderr)
    Path(str(prefix) + ".status.json").write_text(json.dumps({**evidence, "returncode": result.returncode}) + "\n")
    require(result.returncode == 0 and not result.stderr, f"backend failed or diagnosed input: {prefix}")
    return result.stdout.decode("utf-8", errors="strict")


def read_at(path, offset, count):
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(count)
    require(len(data) == count, "short independent fixture read")
    return data


def image(path):
    """Bounded ordinary fixture metadata; all file-byte comparisons remain streamed."""
    result = common.metadata(path)
    wide, order = result["wide"], result["order"]
    header = bytes.fromhex(result["header_hex"])
    result["ehsize"] = struct.unpack_from(order + "H", header, 52 if wide else 40)[0]
    require(len(header) <= result["ehsize"] <= result["bytes"], "bad declared fixture header")
    count = result["phcount"]
    if count == 0xffff:
        require(result["sections"], "missing extended-count section zero")
        count = result["sections"][0]["info"]
    # This quadratic test projection is intentionally for the small integration
    # fixtures. Genuine PN_XNUM tables have separate Java focused coverage.
    require(0 <= count <= 128, "program table exceeds ordinary-oracle bound of 128")
    canonical = 56 if wide else 32
    require(not count or (result["phsize"] >= canonical and result["phoff"] >= result["ehsize"] and
            result["phoff"] + count * result["phsize"] <= result["bytes"]), "bad fixture program table")
    result["program_count"] = count
    programs = []
    with path.open("rb") as stream:
        for index in range(count):
            location = result["phoff"] + index * result["phsize"]
            stream.seek(location)
            values = struct.unpack(order + ("IIQQQQQQ" if wide else "IIIIIIII"), stream.read(canonical))
            kind, offset, length = (values[0], values[2], values[5]) if wide else (values[0], values[1], values[4])
            require(kind == 0 or offset + length <= result["bytes"], "fixture payload outside file")
            programs.append({"index": index, "header": location, "type": kind,
                             "offset": offset, "size": length})
    result["programs"] = programs
    return result


def first_difference(original, candidate, start, end, excluded=()):
    """Independent physical-byte predicate with an explicit coverage set."""
    with original.open("rb") as left, candidate.open("rb") as right:
        left.seek(start)
        right.seek(start)
        at = start
        while at < end:
            count = min(1024 * 1024, end - at)
            a, b = bytearray(left.read(count)), bytearray(right.read(count))
            require(len(a) == len(b) == count, "short selected program-byte span")
            for lo, hi in excluded:
                lo, hi = max(lo, at), min(hi, at + count)
                if lo < hi:
                    a[lo - at:hi - at] = b[lo - at:hi - at] = bytes(hi - lo)
            if a != b:
                delta = next(i for i, values in enumerate(zip(a, b)) if values[0] != values[1])
                return {"offset": at + delta, "expected": f"0x{a[delta]:02x}", "observed": f"0x{b[delta]:02x}"}
            at += count
    return None


def expected(original, candidate):
    left, right = image(original), image(candidate)
    masks = ((40, 48), (58, 64)) if left["wide"] else ((32, 36), (46, 52))
    difference = first_difference(original, candidate, 0, min(left["ehsize"], right["ehsize"]), masks)
    if difference:
        return {"status": "DIFFERENT_PROGRAM_BYTES", "region": "ELF_HEADER", **difference}
    require(left["ehsize"] == right["ehsize"], "header-size difference must be observed in header bytes")
    if left["program_count"] != right["program_count"]:
        return {"status": "DIFFERENT_PROGRAM_BYTES", "region": "PROGRAM_COUNT", "offset": None,
                "expected": str(left["program_count"]), "observed": str(right["program_count"])}
    table_end = left["phoff"] + left["phsize"] * left["program_count"]
    difference = first_difference(original, candidate, left["phoff"], table_end)
    if difference:
        return {"status": "DIFFERENT_PROGRAM_BYTES", "region": "PROGRAM_TABLE", **difference}
    # Sweep independent boundary partitions instead of deriving byte coverage from sections.
    spans = [(p["offset"], p["offset"] + p["size"]) for p in left["programs"] if p["type"] and p["size"]]
    boundaries = sorted({point for span in spans for point in span})
    for start, end in zip(boundaries, boundaries[1:]):
        if not any(lo <= start and end <= hi for lo, hi in spans):
            continue
        difference = first_difference(original, candidate, start, end,
                                      ((0, left["ehsize"]), (left["phoff"], table_end)))
        if difference:
            return {"status": "DIFFERENT_PROGRAM_BYTES", "region": "PROGRAM_PAYLOAD", **difference}
    evidence = any(p["type"] == 1 and p["size"] for p in left["programs"])
    return {"status": "MATCHING_PROGRAM_BYTES" if evidence else "NO_FILE_BACKED_LOAD_EVIDENCE"}


def decoded(value):
    text = base64.b64decode(value, validate=True).decode("utf-8", errors="strict")
    require(text.strip(), "empty typed diagnostic")
    return text


def probe(pairs, jar, classes, prefix, reject=False):
    output = run([os.environ.get("JAVA", "java"), "-Xmx64m", "-cp",
        os.pathsep.join(map(str, (jar, classes))), "ghidradwarfforge.elf.ExecutableProgramBytesProbe",
        *(["--expect-rejection"] if reject else []), *(path for pair in pairs for path in pair)], prefix)
    lines = output.splitlines()
    require(len(lines) == len(pairs) + 4, "unexpected program-byte adapter output")
    for index, label in enumerate(("program-bytes", "elf")):
        require(lines[index].startswith(label + "-class-source="), "missing installed origin")
        uri = urlparse(lines[index].split("=", 1)[1])
        require(uri.scheme == "file" and Path(unquote(uri.path)).resolve() == jar,
                "helper did not load from selected installed JAR")
    require(re.fullmatch(r"java-version=21(?:[.+-].*)?", lines[2]), "actual Java21 required")
    require(lines[3].startswith("max-heap=") and 0 < int(lines[3].split("=")[1]) <= 64 * 1024 * 1024,
            "bounded observer heap required")
    observations = []
    for index, (line, pair) in enumerate(zip(lines[4:], pairs)):
        if reject:
            match = re.fullmatch(r"rejected=java.io.IOException diagnostic=(\S+)", line)
            require(match is not None, "malformed ELF did not reject precisely")
            observations.append({"exception": "java.io.IOException", "diagnostic": decoded(match[1])})
            continue
        fields = line.split("\t")
        require(len(fields) in (5, 8) and fields[:2] == ["program-bytes", str(index)], "invalid TSV record")
        decoded(fields[3])
        actual = {"status": fields[2]}
        if len(fields) == 5:
            require(fields[4] == "NONE", "invalid absent issue")
        else:
            actual.update(region=fields[4], offset=None if fields[5] == "-" else int(fields[5]),
                          expected=decoded(fields[6]), observed=decoded(fields[7]))
        wanted = expected(*pair)
        require(actual == wanted, f"independent byte disagreement at {prefix}: {actual} versus {wanted}")
        observations.append(actual)
    return observations


def allocated(path):
    fields = ("index", "name", "type", "flags", "address", "offset", "size", "link", "info", "alignment", "entry_size")
    return [{key: entry.get(key, "") for key in fields} for entry in image(path)["sections"]
            if entry["type"] and entry["flags"] & 2]


def debuglink(path, debug_file):
    metadata = image(path)
    links = [section for section in metadata["sections"] if section.get("name") == ".gnu_debuglink"]
    name = os.fsencode(debug_file.name)
    require(b"\0" not in name and b"/" not in name, "invalid literal basename")
    crc = 0
    with debug_file.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            crc = zlib.crc32(chunk, crc)
    payload = name + b"\0"
    payload += bytes(-len(payload) % 4)
    payload += struct.pack(metadata["order"] + "I", crc)
    fields = {"type": 1, "flags": 0, "address": 0, "link": 0, "info": 0, "alignment": 4, "entry_size": 0}
    matching = (len(links) == 1 and all(links[0][key] == value for key, value in fields.items()) and
                links[0]["size"] == len(payload) and
                read_at(path, links[0]["offset"], links[0]["size"]) == payload)
    return {"exact_creation_contract": matching, "literal_basename_hex": name.hex(), "crc32": crc,
            "expected_payload_hex": payload.hex(), "section_count": len(links)}


def write_number(path, offset, fmt, value):
    with path.open("r+b") as stream:
        stream.seek(offset)
        stream.write(struct.pack(fmt, value))


def flip(path, offset):
    value = read_at(path, offset, 1)[0]
    write_number(path, offset, "B", value ^ 1)


@contextmanager
def preserve(paths, work):
    before = {str(path): snapshot(path) for path in paths}
    (work / "protected-before.json").write_text(json.dumps(before, indent=4) + "\n")
    try:
        yield before
    finally:
        after = {}
        for path in before:
            try:
                after[path] = snapshot(Path(path))
            except OSError as failure:
                after[path] = {"error": type(failure).__name__, "errno": failure.errno,
                               "diagnostic": str(failure)}
        (work / "protected-after.json").write_text(json.dumps(after, indent=4) + "\n")
        require(after == before, "protected input/tool/installation changed")


def no_load_control(work, jar, classes):
    header = bytearray(96)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, 62, 1)
    struct.pack_into("<Q", header, 32, 96)
    struct.pack_into("<HHH", header, 52, 96, 56, 1)
    # One non-LOAD payload plus a declared header tail outside all payloads.
    program = struct.pack("<IIQQQQQQ", 4, 4, 256, 0, 0, 16, 16, 4)
    data = header + program + bytes(256 - len(header) - len(program)) + bytes(16)
    original, candidate = work / "no-load.original", work / "no-load.candidate"
    original.write_bytes(data)
    candidate.write_bytes(data)
    snapshots = []
    def observe(label):
        before = {str(path): snapshot(path) for path in (original, candidate)}
        result = probe([(original, candidate)], jar, classes, work / label)[0]
        require({str(path): snapshot(path) for path in (original, candidate)} == before,
                "no-LOAD observation changed inputs")
        snapshots.append({"label": label, "inputs": before})
        return result
    absent = observe("no-load-match")
    require(absent["status"] == "NO_FILE_BACKED_LOAD_EVIDENCE", "empty LOAD evidence became a match")
    flip(candidate, 256)
    different = observe("no-load-difference")
    require(different["region"] == "PROGRAM_PAYLOAD" and different["offset"] == 256,
            "difference did not take precedence over absent LOAD evidence")
    flip(candidate, 80)
    tail = observe("declared-header-tail")
    require(tail["region"] == "ELF_HEADER" and tail["offset"] == 80, "declared header tail ignored")
    return {"absent": absent, "difference": different, "header_tail": tail,
            "original_hex": data.hex(), "candidate_xor_offsets_in_order": [256, 80], "snapshots": snapshots,
            "scope": "Synthetic ELF64 metadata only, not executed."}


def controls(original, candidate, debug_file, work, jar, classes):
    metadata = image(candidate)
    text = common.named(metadata, ".text")
    link = common.named(metadata, ".gnu_debuglink")
    mutants = []
    for label in ("code", "header", "program-table", "active-address", "crc"):
        path = work / (label + ".candidate")
        shutil.copy2(candidate, path)
        if label == "code":
            flip(path, text["offset"])
        elif label == "header":
            flip(path, 9)
        elif label == "program-table":
            # Physical address is a raw PHDR field not interpreted by the test's metadata projection.
            flip(path, metadata["phoff"] + (24 if metadata["wide"] else 12))
        elif label == "active-address":
            write_number(path, text["header"] + (16 if metadata["wide"] else 12),
                         metadata["order"] + ("Q" if metadata["wide"] else "I"), text["address"] + 256)
        else:
            flip(path, link["offset"] + link["size"] - 1)
        mutants.append((label, path))
    before = {str(path): snapshot(path) for _, path in mutants}
    observations = probe([(original, path) for _, path in mutants], jar, classes, work / "mutations")
    require([item["status"] for item in observations] == ["DIFFERENT_PROGRAM_BYTES"] * 3 +
            ["MATCHING_PROGRAM_BYTES"] * 2, "limited-property counterexamples changed")
    require([item.get("region") for item in observations[:3]] ==
            ["PROGRAM_PAYLOAD", "ELF_HEADER", "PROGRAM_TABLE"], "wrong first-difference phase")
    require(allocated(original) != allocated(mutants[3][1]), "active-address mutation escaped metadata check")
    require(not debuglink(mutants[4][1], debug_file)["exact_creation_contract"], "CRC mutation escaped link check")
    require({str(path): snapshot(path) for _, path in mutants} == before, "observer changed owned mutants")

    # A controlled NOTE outside every LOAD demonstrates the old LOAD-only gap.
    notes = [p for p in metadata["programs"] if p["type"] == 4 and p["size"] >= 16]
    require(notes, "fixture needs a nonempty NOTE for outside-LOAD control")
    note = notes[-1]
    location = (max(original.stat().st_size, candidate.stat().st_size) + 71) & ~7
    require(all(not (p["offset"] <= location < p["offset"] + p["size"])
                for p in metadata["programs"] if p["type"] == 1), "controlled note still inside LOAD")
    payload = read_at(candidate, note["offset"], note["size"])
    pair = (work / "outside-load.original", work / "outside-load.candidate")
    for source, destination in zip((original, candidate), pair):
        shutil.copy2(source, destination)
        with destination.open("r+b") as stream:
            stream.seek(location)
            stream.write(payload)
        write_number(destination, note["header"] + (8 if metadata["wide"] else 4),
                     metadata["order"] + ("Q" if metadata["wide"] else "I"), location)
    flip(pair[1], location + 12)
    note_before = {str(path): snapshot(path) for path in pair}
    outside = probe([pair], jar, classes, work / "outside-load")[0]
    require(outside["region"] == "PROGRAM_PAYLOAD" and outside["offset"] == location + 12,
            "non-LOAD payload difference was not observed")
    require({str(path): snapshot(path) for path in pair} == note_before, "outside-LOAD control changed")
    unchanged = probe([(original, original)], jar, classes, work / "unchanged-no-attachment")[0]
    require(unchanged["status"] == "MATCHING_PROGRAM_BYTES" and
            not debuglink(original, debug_file)["exact_creation_contract"], "unchanged file became attachment proof")
    malformed = work / "malformed.elf"
    malformed.write_bytes(b"not an ELF\n")
    malformed_before = snapshot(malformed)
    rejected = probe([(original, malformed), (malformed, candidate)], jar, classes, work / "malformed", True)
    require(snapshot(malformed) == malformed_before, "malformed input changed")
    return {"mutations": [{"name": label, "path": str(path), "snapshot": before[str(path)], "result": result}
            for (label, path), result in zip(mutants, observations)],
            "outside_load": {"inputs": note_before, "result": outside, "moved_note_offset": location,
                             "scope": "Controlled metadata copies; not executed or claimed runtime-valid."},
            "unchanged_without_attachment": unchanged, "malformed": rejected,
            "no_load": no_load_control(work, jar, classes)}


def sparse_control(work, jar, classes):
    """High-offset selected payload; no whole-file/prefix or native-Windows-large claim."""
    offset, length = (1 << 31) + 4096, 2 * 1024 * 1024 + 17
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, 62, 1)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HHH", header, 52, 64, 56, 1)
    program = struct.pack("<IIQQQQQQ", 1, 5, offset, 0x500000, 0x500000, length, length, 1)
    payload = (bytes(range(256)) * ((length + 255) // 256))[:length]
    pair = (work / "large.original", work / "large.candidate")
    recipe = {"header_hex": header.hex(), "program_hex": program.hex(), "payload_offset": offset,
              "payload_bytes": length, "pattern_hex": bytes(range(256)).hex(),
              "logical_bytes": offset + length, "changed_offset": offset + length - 1}
    (work / "large-recipe.json").write_text(json.dumps(recipe, indent=4) + "\n")
    def selected_state(path):
        state = path.stat()
        return {"bytes": state.st_size, "mtime_ns": state.st_mtime_ns,
                "header_and_table_sha256": hashlib.sha256(read_at(path, 0, 120)).hexdigest(),
                "selected_payload_sha256": hashlib.sha256(read_at(path, offset, length)).hexdigest()}
    try:
        for path in pair:
            with path.open("xb") as stream:
                stream.write(header + program)
                stream.seek(offset)
                stream.write(payload)
        before = {str(path): selected_state(path) for path in pair}
        matched = probe([pair], jar, classes, work / "large-match")[0]
        require(matched["status"] == "MATCHING_PROGRAM_BYTES", "large selected range did not match")
        require({str(path): selected_state(path) for path in pair} == before, "large input changed")
        flip(pair[1], offset + length - 1)
        changed = selected_state(pair[1])
        different = probe([pair], jar, classes, work / "large-difference")[0]
        require(different["region"] == "PROGRAM_PAYLOAD" and different["offset"] == offset + length - 1,
                "high payload offset truncated")
        require(selected_state(pair[0]) == before[str(pair[0])] and selected_state(pair[1]) == changed,
                "large difference observer changed inputs")
        return {"recipe": recipe, "before": before, "changed_candidate": changed,
                "match": matched, "difference": different, "full_file_hash_claimed": False}
    finally:
        for path in pair:
            path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=common.PROFILES)
    parser.add_argument("original", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("debug_file", type=Path)
    parser.add_argument("result_dir", type=Path)
    parser.add_argument("--objcopy", required=True)
    parser.add_argument("--controls", action="store_true")
    parser.add_argument("--large", action="store_true")
    args = parser.parse_args()
    module, original, debug_file = (path.resolve(strict=True) for path in
                                   (args.module, args.original, args.debug_file))
    candidate = args.candidate.absolute()
    require(not os.path.lexists(candidate), "candidate must be a fresh explicit output")
    require(not args.large or args.target == "x86_64", "large control is Linux x86 only")
    jar = (module / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    script = (module / "ghidra_scripts/GhidraDwarfForge.java").resolve(strict=True)
    work = args.result_dir.absolute()
    work.mkdir(parents=True, exist_ok=False)
    print(f"executable-program-bytes-results={work}", flush=True)
    classes = work / "classes"
    classes.mkdir()
    tool = shutil.which(args.objcopy)
    require(tool is not None, "objcopy tool is unavailable")
    tool = Path(tool).absolute()
    adapter = REPOSITORY / "src/test/java/ghidradwarfforge/elf/ExecutableProgramBytesProbe.java"
    with preserve((original, debug_file, jar, script, tool, adapter), work) as protected:
        result = execute(args, module, original, candidate, debug_file, work, classes, tool, adapter,
                         jar, script, protected)
    result["status"] = "PASS"
    (work / "result.json").write_text(json.dumps(result, indent=4) + "\n")
    print("executable-program-bytes=PASS")


def execute(args, module, original, candidate, debug_file, work, classes, tool, adapter,
            jar, script, protected):
    shutil.copy2(adapter, work / adapter.name)
    version = tool_run([tool, "--version"], work / "objcopy-version")
    require(version.strip(), "objcopy produced no version")
    output = tool_run([tool, "--add-gnu-debuglink=" + str(debug_file), original, candidate], work / "objcopy")
    require(not output, "objcopy issued an unexplained stdout diagnostic")
    require(candidate.is_file() and not candidate.is_symlink(), "objcopy did not create an ordinary candidate")
    require(image(original)["profile"] == list(common.PROFILES[args.target]), "wrong fixture target")
    run([os.environ.get("JAVAC", "javac"), "--release", "21", "-cp", jar, "-d", classes, adapter], work / "compile")
    candidate_before = snapshot(candidate)
    observations = probe([(original, candidate), (original, candidate)], jar, classes, work / "installed")
    require(all(item["status"] == "MATCHING_PROGRAM_BYTES" for item in observations), "objcopy changed program bytes")
    metadata_equal = allocated(original) == allocated(candidate)
    association = debuglink(candidate, debug_file)
    require(metadata_equal and association["exact_creation_contract"], "independent metadata/debuglink check failed")
    result = {"target": args.target, "module": str(module), "jar": protected[str(jar)],
              "script": protected[str(script)], "adapter": protected[str(adapter)],
              "original": str(original), "candidate": str(candidate), "debug_file": str(debug_file),
              "candidate_snapshot": candidate_before, "tool": str(tool), "tool_version": version,
              "explicit_tool_environment": {"LC_ALL": "C", **({"LD_LIBRARY_PATH": os.environ["LD_LIBRARY_PATH"]}
                  if "LD_LIBRARY_PATH" in os.environ else {})},
              "program_bytes": observations, "indexed_allocated_metadata_equal": metadata_equal,
              "separate_debuglink_check": association,
              "scope": "Owned backend candidate observation before GDB; no attachment transaction or runtime-equivalence claim."}
    if args.controls:
        result["controls"] = controls(original, candidate, debug_file, work, jar, classes)
    if args.large:
        result["large"] = sparse_control(work, jar, classes)
        require(not (work / "large.original").exists() and not (work / "large.candidate").exists(), "large cleanup failed")
    require(snapshot(candidate) == candidate_before, "observer changed backend candidate")
    result["protected_before_after"] = protected
    return result


if __name__ == "__main__":
    main()
