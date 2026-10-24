#!/usr/bin/env python3
"""Check the installed copied-prefix observer against independent ELF/byte reads."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from urllib.parse import unquote, urlparse


REPOSITORY = Path(__file__).resolve().parents[3]
PROFILES = {"x86_64": (2, 1, 62), "aarch64": (2, 1, 183), "arm32": (1, 1, 40),
            "mips32be": (1, 2, 8), "mips32le": (1, 1, 8)}
ROLES = ("exec", "partial", "exec.no-build-id", "exec.no-sections", "pie", "shared")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def snapshot(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    stat = path.stat()
    return {"sha256": digest.hexdigest(), "bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def run(command, prefix):
    command = list(map(str, command))
    Path(str(prefix) + ".command.json").write_text(json.dumps(command) + "\n")
    try:
        result = subprocess.run(command, capture_output=True, timeout=180,
                                env={**os.environ, "LC_ALL": "C"})
    except subprocess.TimeoutExpired as failure:
        Path(str(prefix) + ".stdout").write_bytes(failure.stdout or b"")
        Path(str(prefix) + ".stderr").write_bytes(failure.stderr or b"")
        Path(str(prefix) + ".timeout").write_text("180 seconds\n")
        raise
    Path(str(prefix) + ".stdout").write_bytes(result.stdout)
    Path(str(prefix) + ".stderr").write_bytes(result.stderr)
    require(result.returncode == 0 and not result.stderr, f"command failed or diagnosed input: {prefix}")
    return result.stdout.decode("utf-8", errors="strict")


def metadata(path):
    """Independent bounded metadata for the small fixture tables, including escapes."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        header = stream.read(64)
        require(len(header) >= 52 and header[:4] == b"\x7fELF" and
                header[4] in (1, 2) and header[5] in (1, 2), "invalid fixture ELF")
        wide = header[4] == 2
        order = "<" if header[5] == 1 else ">"
        header = header[:64 if wide else 52]
        require(len(header) == (64 if wide else 52), "short fixture header")
        phoff, shoff = struct.unpack_from(order + ("QQ" if wide else "II"), header, 32 if wide else 28)
        phsize, phcount, shsize, raw_count, raw_names = struct.unpack_from(order + "HHHHH", header,
                                                                         54 if wide else 42)
        fmt = order + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
        canonical = struct.calcsize(fmt)
        entries, names = [], 0
        if shoff:
            require(shsize >= canonical and shoff + shsize <= size, "invalid fixture section zero")
            stream.seek(shoff)
            zero = struct.unpack(fmt, stream.read(canonical))
            count = raw_count or zero[5]
            names = zero[6] if raw_names == 0xffff else raw_names
            require(0 < count <= 4096 and shoff + shsize * count <= size and names < count,
                    "fixture table exceeds oracle bounds")
            for index in range(count):
                stream.seek(shoff + index * shsize)
                fields = struct.unpack(fmt, stream.read(canonical))
                entries.append({"index": index, "header": shoff + index * shsize,
                    "name_offset": fields[0], "type": fields[1], "flags": fields[2],
                    "address": fields[3], "offset": fields[4], "size": fields[5],
                    "link": fields[6], "info": fields[7], "alignment": fields[8], "entry_size": fields[9]})
            if names:
                table = entries[names]
                require(table["type"] == 3 and table["size"] <= 1024 * 1024 and
                        table["offset"] + table["size"] <= size, "invalid fixture name table")
                stream.seek(table["offset"])
                strings = stream.read(table["size"])
                for entry in entries:
                    start = entry["name_offset"]
                    end = strings.find(b"\0", start)
                    require(end >= start, "unterminated fixture name")
                    entry["name"] = strings[start:end].decode("ascii")
        else:
            require(raw_count == raw_names == 0, "invalid sectionless fixture")
    return {"bytes": size, "wide": wide, "order": order, "header_hex": header.hex(),
            "profile": [header[4], header[5], struct.unpack_from(order + "H", header, 18)[0]],
            "phoff": phoff, "phsize": phsize, "phcount": phcount,
            "shoff": shoff, "shsize": shsize, "names": names, "sections": entries}


def expected(original, candidate):
    left, right = metadata(original), metadata(candidate)
    common = {"original": left["bytes"], "candidate": right["bytes"], "extent": 0, "different": None}
    if (left["wide"], left["order"]) != (right["wide"], right["order"]):
        return {**common, "status": "DIFFERENT_LAYOUT"}
    if right["bytes"] < left["bytes"]:
        return {**common, "status": "SHORTER_CANDIDATE"}
    if (right["phoff"] or right["phsize"] or right["phcount"] or not right["names"] or
            right["shoff"] < left["bytes"] or right["shsize"] != (64 if right["wide"] else 40)):
        return {**common, "status": "DIFFERENT_LAYOUT"}
    exemptions = ((32, 48), (54, 64)) if left["wide"] else ((28, 36), (42, 52))
    with original.open("rb") as first, candidate.open("rb") as second:
        position = 0
        while position < left["bytes"]:
            count = min(1024 * 1024, left["bytes"] - position)
            a, b = bytearray(first.read(count)), bytearray(second.read(count))
            require(len(a) == len(b) == count, "fixture changed while checking prefix")
            if position == 0:
                for start, end in exemptions:
                    a[start:end] = b[start:end] = bytes(end - start)
            if a != b:
                delta = next(index for index, pair in enumerate(zip(a, b)) if pair[0] != pair[1])
                return {**common, "status": "DIFFERENT_PREFIX", "different": position + delta,
                        "extent": position + delta + 1}
            position += count
    return {**common, "status": "MATCHING_COPIED_PREFIX", "extent": left["bytes"]}


def probe(pairs, jar, classes, prefix, *, reject=False):
    output = run([os.environ.get("JAVA", "java"), "-Xmx64m", "-cp",
        os.pathsep.join(map(str, (jar, classes))), "ghidradwarfforge.elf.MatchedElfPrefixProbe",
        *(["--expect-rejection"] if reject else []), *(path for pair in pairs for path in pair)], prefix)
    lines = output.splitlines()
    for index, kind in enumerate(("prefix", "elf-image")):
        require(lines[index].startswith(kind + "-class-source="), "missing installed class origin")
        origin = urlparse(lines[index].split("=", 1)[1])
        require(origin.scheme == "file" and Path(unquote(origin.path)).resolve() == jar,
                "observer/ELF reader did not load from installed JAR")
    require(re.fullmatch(r"java-version=21(?:[.+-].*)?", lines[2]) is not None, "actual Java21 required")
    require(lines[3].startswith("max-heap=") and int(lines[3].split("=")[1]) <= 64 * 1024 * 1024,
            "unbounded observer heap")
    require(len(lines) == len(pairs) + 4, "unexpected observer output")
    observations = []
    for index, (line, pair) in enumerate(zip(lines[4:], pairs)):
        if reject:
            match = re.fullmatch(r"rejected=java.io.IOException diagnostic=(\S+)", line)
            require(match is not None and base64.b64decode(match[1], validate=True).decode().strip(),
                    "malformed ELF did not fail precisely")
            continue
        match = re.fullmatch(r"prefix=(\d+) status=(\w+) original=(\d+) candidate=(\d+) "
                             r"extent=(\d+) different=(-|\d+) diagnostic=(\S+)", line)
        require(match is not None and int(match[1]) == index and
                base64.b64decode(match[7], validate=True).decode().strip(), "invalid observation protocol")
        actual = {"status": match[2], "original": int(match[3]), "candidate": int(match[4]),
                  "extent": int(match[5]), "different": None if match[6] == "-" else int(match[6])}
        require(actual == expected(*pair), f"Java/Python prefix disagreement: {prefix}: {actual}")
        observations.append(actual)
    return observations


def named(image, name):
    matches = [section for section in image["sections"] if section.get("name") == name]
    require(len(matches) == 1, "missing/duplicate fixture section " + name)
    return matches[0]


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate report key")
        result[key] = value
    return result


def large_control(work, jar, classes):
    """Independent sparse ELF64 recipe; retain recipes/results, not multi-GiB upload inputs."""
    length = (1 << 31) + 65537
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, 62, 1)
    struct.pack_into("<H", header, 52, 64)
    original, candidate = work / "large-original.elf", work / "large-candidate.elf"
    names = b"\0.shstrtab\0"
    table_offset = (length + len(names) + 7) & ~7
    appended = names + bytes(table_offset - length - len(names)) + bytes(64)
    appended += struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, length, len(names), 0, 0, 1, 0)
    changed = bytearray(header)
    struct.pack_into("<Q", changed, 40, table_offset)
    struct.pack_into("<HHH", changed, 58, 64, 2, 1)
    recipe = {"original_bytes": length, "last_original_byte": 0xa5,
              "original_header_hex": header.hex(), "candidate_header_hex": changed.hex(),
              "appended_hex": appended.hex(), "appended_offset": length,
              "changed_offset": length - 1, "changed_byte": 0x5a}
    (work / "large-recipe.json").write_text(json.dumps(recipe, indent=4) + "\n")
    try:
        for path, first in ((original, header), (candidate, changed)):
            with path.open("wb") as stream:
                stream.write(first)
                stream.seek(length - 1)
                stream.write(b"\xa5")
                if path == candidate:
                    stream.write(appended)
        before = {str(path): snapshot(path) for path in (original, candidate)}
        matched = probe([(original, candidate)], jar, classes, work / "large-match")
        require(matched[0]["status"] == "MATCHING_COPIED_PREFIX", "large matching control failed")
        require({str(path): snapshot(path) for path in (original, candidate)} == before,
                "large observer changed its inputs")
        with candidate.open("r+b") as stream:
            stream.seek(length - 1)
            stream.write(b"\x5a")
        mutated = snapshot(candidate)
        different = probe([(original, candidate)], jar, classes, work / "large-difference")
        require(different[0]["different"] == length - 1 and
                different[0]["status"] == "DIFFERENT_PREFIX", "large offset was truncated")
        require(snapshot(original) == before[str(original)] and snapshot(candidate) == mutated,
                "large mismatch check changed its inputs")
        return {"before": before, "candidate_after_owned_mutation": mutated,
                "match": matched[0], "difference": different[0], "recipe": recipe}
    finally:
        original.unlink(missing_ok=True)
        candidate.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=PROFILES)
    parser.add_argument("--producer-module", type=Path, help="explicit installation for earlier retained exports")
    parser.add_argument("--fixture-root", type=Path, default=REPOSITORY / "build/fixtures")
    parser.add_argument("--export-logs", type=Path, default=REPOSITORY / "build/test-results/headless-symbol-export")
    parser.add_argument("--large", action="store_true")
    args = parser.parse_args()
    module = args.module.resolve(strict=True)
    producer = (args.producer_module or args.module).resolve(strict=True)
    jar = (module / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    producer_jar = (producer / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    script = producer / "ghidra_scripts/GhidraDwarfForge.java"
    root = REPOSITORY / "build/test-results/matched-elf-prefix"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=args.target + ".", dir=root))
    print(f"matched-elf-prefix-results={work}", flush=True)
    classes = work / "classes"
    classes.mkdir()
    run([os.environ.get("JAVAC", "javac"), "--release", "21", "-cp", jar, "-d", classes,
         REPOSITORY / "src/test/java/ghidradwarfforge/elf/MatchedElfPrefixProbe.java"], work / "compile")
    run(["readelf", "--version"], work / "gnu-version")
    protected = {str(path): snapshot(path) for path in (jar, producer_jar, script)}
    pairs, reports, copies = [], [], []
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
    for role in ROLES:
        log = args.export_logs.resolve(strict=True) / f"{args.target}.{role}.log"
        protected[str(log)] = snapshot(log)
        transcript = log.read_bytes()
        retained_log = work / (role + ".export.log")
        retained_log.write_bytes(transcript)
        text = transcript.decode("utf-8", errors="strict")
        require(text.count("SCRIPT: " + str(script)) == 1, "wrong installed exporter script")
        bodies = [line.split("GhidraDwarfForge report: ", 1)[1] for line in text.splitlines()
                  if "GhidraDwarfForge report: " in line]
        require(len(bodies) == 1, "expected one production report")
        report, end = decoder.raw_decode(bodies[0])
        require(bodies[0][end:].strip() == "(GhidraScript)" and
                report["status"] in ("SUCCESS", "PARTIAL"), "invalid completed report")
        stem = "libsemantic.so" if role == "shared" else "semantic." + role
        paths = []
        for label, suffix in (("input", "stripped"), ("output", "ghidra-forge.dbg"),
                              ("source", "ghidra-forge.dbg.c")):
            path = args.fixture_root.resolve(strict=True) / args.target / (stem + "." + suffix)
            protected[str(path)] = snapshot(path)
            require(report["artifacts"][label + "Path"] == str(path) and
                    report["artifacts"][label + "Sha256"].lower() == protected[str(path)]["sha256"],
                    "report does not describe the selected fixture bytes")
            retained = work / f"{role}.{label}.bytes"
            shutil.copyfile(path, retained)
            copied = snapshot(retained)
            require(copied["sha256"] == protected[str(path)]["sha256"], "retained copy differs")
            copies.append({"original": str(path), "retained": str(retained), "snapshot": copied})
            paths.append(retained)
        require(tuple(metadata(paths[0])["profile"]) == PROFILES[args.target], "mislabeled target")
        pairs.append(paths[:2])
        run(["readelf", "-h", "-SW", paths[1]], work / (role + "-gnu-layout"))
        reports.append({"role": role, "source_log": str(log), "retained_log": str(retained_log),
                        "log_sha256": hashlib.sha256(transcript).hexdigest(), "report": report})
    observed = probe(pairs, jar, classes, work / "pairs")
    require(all(item["status"] == "MATCHING_COPIED_PREFIX" for item in observed), "real pair did not match")
    require(probe(pairs, jar, classes, work / "repeat") == observed, "repeated observation differs")

    original, sidecar = pairs[0]
    before, after = metadata(original), metadata(sidecar)
    text_section = named(before, ".text")
    changed_code = work / "changed-code.elf"
    shutil.copyfile(original, changed_code)
    with changed_code.open("r+b") as stream:
        stream.seek(text_section["offset"])
        byte = stream.read(1)
        require(len(byte) == 1, "empty fixture .text")
        stream.seek(text_section["offset"])
        stream.write(bytes([byte[0] ^ 0x80]))
    require(metadata(changed_code) == before, "code control changed ELF metadata")
    ids = []
    for label, path in (("original", original), ("code", changed_code), ("sidecar", sidecar)):
        output = run(["readelf", "-n", path], work / (label + "-gnu-notes"))
        ids.append(set(re.findall(r"Build ID: ([0-9a-f]+)", output)))
    require(len(ids[0]) == 1 and ids[0] == ids[1] == ids[2], "code control changed build identity bytes")
    code_result = probe([(changed_code, sidecar)], jar, classes, work / "changed-code")
    require(code_result[0]["different"] == text_section["offset"], "changed code was not detected")

    changed_address = work / "changed-active-address.elf"
    shutil.copyfile(sidecar, changed_address)
    active_text = named(after, ".text")
    delta = max(0x10000000, active_text["alignment"])
    require(delta % max(1, active_text["alignment"]) == 0 and active_text["header"] >= before["bytes"],
            "active address control not appended/aligned")
    with changed_address.open("r+b") as stream:
        stream.seek(active_text["header"] + (16 if after["wide"] else 12))
        stream.write(struct.pack(after["order"] + ("Q" if after["wide"] else "I"), active_text["address"] + delta))
    shifted = named(metadata(changed_address), ".text")
    require(shifted == {**active_text, "address": active_text["address"] + delta}, "wrong active metadata control")
    run(["readelf", "-h", "-SW", changed_address], work / "changed-address-gnu-layout")
    output = run(["readelf", "-n", changed_address], work / "changed-address-gnu-notes")
    require(set(re.findall(r"Build ID: ([0-9a-f]+)", output)) == ids[0], "active control changed build ID")
    address_result = probe([(original, changed_address)], jar, classes, work / "changed-address")
    require(address_result[0]["status"] == "MATCHING_COPIED_PREFIX", "appended bytes entered prefix proof")

    # A valid original used as its own candidate is structurally parseable but
    # lacks the required appended-table/zero-program-table envelope.
    layout_result = probe([(original, original), (sidecar, original)], jar, classes, work / "layout-controls")
    require([item["status"] for item in layout_result] == ["DIFFERENT_LAYOUT", "SHORTER_CANDIDATE"],
            "layout/short-candidate controls failed")
    malformed = work / "malformed.elf"
    malformed.write_bytes(b"\x7fELF")
    probe([(malformed, sidecar), (original, malformed)], jar, classes, work / "malformed", reject=True)
    large = large_control(work, jar, classes) if args.large else None
    require({path: snapshot(Path(path)) for path in protected} == protected, "protected input changed")
    require(all(snapshot(Path(item["retained"])) == item["snapshot"] for item in copies), "retained input changed")
    (work / "result.json").write_text(json.dumps({"status": "PASS", "target": args.target,
        "module": str(module), "producer_module": str(producer), "same_export_installation": module == producer,
        "protected": protected, "retained_artifacts": copies, "reports": reports, "pairs": observed,
        "changed_code": {"observation": code_result[0], "same_metadata": True, "gnu_build_id": sorted(ids[0])},
        "changed_active_address": {"observation": address_result[0], "before": active_text, "after": shifted},
        "layout_controls": layout_result, "malformed_rejections": 2, "large": large,
        "preservation_scope": "before/after this oracle; later steps may reuse fixture/log paths",
        "scope": "current Forge retained prefix only; no snapshot, active allocation, DWARF or attachment proof"
    }, indent=4) + "\n")
    print(f"matched-elf-prefix-{args.target}=PASS", flush=True)


if __name__ == "__main__":
    main()
