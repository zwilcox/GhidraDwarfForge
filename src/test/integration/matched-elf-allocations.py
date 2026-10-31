#!/usr/bin/env python3
"""Compare installed allocation observations with independently projected ELF fields.

Consumes a preceding prefix oracle, retaining its complete producer transcripts
and all eighteen selected byte copies. No exporter, original target or old result
is modified. An explicit --prefix-result is a replay of earlier exports, never
a claim that the current observer installation produced those exports.
"""

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
import tempfile
from urllib.parse import unquote, urlparse


REPOSITORY = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("prefix_oracle", Path(__file__).with_name("matched-elf-prefix.py"))
PREFIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREFIX)
require, snapshot, run = PREFIX.require, PREFIX.snapshot, PREFIX.run
FIELDS = ("name", "type", "flags", "address", "offset", "size", "link", "info", "alignment", "entry_size")
ELF_FIELDS = ("sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size",
              "sh_link", "sh_info", "sh_addralign", "sh_entsize")


def metadata(path):
    """Read only bounded headers/names; resolve ELF's three section-zero escapes."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        def read(offset, count):
            require(0 <= offset <= size and 0 <= count <= size - offset, "metadata outside fixture")
            stream.seek(offset)
            data = stream.read(count)
            require(len(data) == count, "short fixture metadata read")
            return data

        ident = read(0, 16)
        require(ident[:4] == b"\x7fELF" and ident[4] in (1, 2) and ident[5] in (1, 2), "invalid ELF fixture")
        wide, order = ident[4] == 2, "<" if ident[5] == 1 else ">"
        header = read(0, 64 if wide else 52)
        phoff, shoff = struct.unpack_from(order + ("QQ" if wide else "II"), header, 32 if wide else 28)
        phsize, raw_phcount, shsize, raw_shcount, raw_names = struct.unpack_from(
            order + "HHHHH", header, 54 if wide else 42)
        sfmt = order + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
        sections, names, count, phcount = [], 0, 0, raw_phcount
        if shoff:
            require(shsize >= struct.calcsize(sfmt), "short section record")
            zero = struct.unpack(sfmt, read(shoff, struct.calcsize(sfmt)))
            count = raw_shcount or zero[5]
            names = zero[6] if raw_names == 0xffff else raw_names
            phcount = zero[7] if raw_phcount == 0xffff else raw_phcount
            require(0 < count <= 262144 and count * shsize <= 64 * 1024 * 1024 and names < count,
                    "section metadata exceeds independent oracle bound")
            require(shoff + count * shsize <= size, "truncated section table")
            for index in range(count):
                fields = struct.unpack(sfmt, read(shoff + index * shsize, struct.calcsize(sfmt)))
                sections.append(dict(zip(("name_offset", *FIELDS[1:]), fields),
                                     index=index, header=shoff + index * shsize, name=""))
            if names:
                table = sections[names]
                require(table["type"] == 3 and table["size"] <= 16 * 1024 * 1024, "invalid name table")
                strings = read(table["offset"], table["size"])
                for section in sections:
                    start = section["name_offset"]
                    end = strings.find(b"\0", start)
                    require(0 <= start <= end and end - start <= 65536, "invalid used name")
                    section["name"] = strings[start:end].hex()
        else:
            require(raw_shcount == raw_names == 0 and raw_phcount != 0xffff, "invalid absent table")
        pfmt = order + ("IIQQQQQQ" if wide else "IIIIIIII")
        segments = []
        if phcount:
            require(phsize >= struct.calcsize(pfmt) and phcount <= 262144 and
                    phcount * phsize <= 64 * 1024 * 1024 and phoff + phcount * phsize <= size,
                    "program metadata exceeds independent oracle bound")
            keys = (("type", "flags", "offset", "address", "physical", "file_size", "memory_size", "alignment")
                    if wide else ("type", "offset", "address", "physical", "file_size", "memory_size", "flags", "alignment"))
            for index in range(phcount):
                fields = struct.unpack(pfmt, read(phoff + index * phsize, struct.calcsize(pfmt)))
                segments.append(dict(zip(keys, fields), index=index))
        target = {"class": ident[4], "order": ident[5], "osabi": ident[7], "abi_version": ident[8],
                  "type": struct.unpack_from(order + "H", header, 16)[0],
                  "machine": struct.unpack_from(order + "H", header, 18)[0],
                  "entry": struct.unpack_from(order + ("Q" if wide else "I"), header, 24)[0],
                  "flags": struct.unpack_from(order + "I", header, 48 if wide else 36)[0]}
    return {"bytes": size, "wide": wide, "order": order, "target": target,
            "phoff": phoff, "phsize": phsize, "phcount": phcount, "raw_phcount": raw_phcount,
            "shoff": shoff, "shsize": shsize, "names": names, "raw_shcount": raw_shcount,
            "raw_names": raw_names, "sections": sections, "segments": segments}


def active(section):
    return section["type"] != 0 and bool(section["flags"] & 2)


def projection(section):
    return {field: section[field] for field in FIELDS}


def merged(intervals):
    result = []
    for start, end in sorted(intervals):
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(end, result[-1][1]))
        else:
            result.append((start, end))
    return result


def original_unwind(path, source):
    """Independently decode the small fixtures' GNU search-table/frame headers.

    Only the fixtures' version-1 1b/03/3b encoding is accepted here. Unsupported
    inputs fail the oracle; they are never inferred from the candidate's table.
    No CFI instruction is interpreted or synthesized.
    """
    headers = [segment for segment in source["segments"] if segment["type"] == 0x6474e550]
    if not headers:
        return None
    require(len(headers) == 1, "ambiguous fixture unwind header")
    header = headers[0]
    order = source["order"]
    with path.open("rb") as stream:
        def locate(address, size):
            require(0 < size <= 64 * 1024 * 1024, "unbounded fixture unwind extent")
            overlaps = [segment for segment in source["segments"] if segment["type"] == 1 and
                        segment["address"] < address + size and address < segment["address"] + segment["memory_size"]]
            require(len(overlaps) == 1, "ambiguous fixture unwind load mapping")
            load = overlaps[0]
            relative = address - load["address"]
            require(0 <= relative and relative + size <= load["file_size"], "unwind bytes are not file backed")
            offset = load["offset"] + relative
            require(0 <= offset and offset + size <= source["bytes"], "unwind bytes outside fixture")
            return offset

        def read(address, size):
            stream.seek(locate(address, size))
            data = stream.read(size)
            require(len(data) == size, "short fixture unwind read")
            return data

        require(12 <= header["file_size"] <= 16 * 1024 * 1024 and
                locate(header["address"], header["file_size"]) == header["offset"], "invalid fixture unwind header view")
        data = read(header["address"], header["file_size"])
        require(data[:4] == bytes((1, 0x1b, 3, 0x3b)), "unsupported independent fixture unwind encoding")
        displacement, count = struct.unpack_from(order + "iI", data, 4)
        start = header["address"] + 4 + displacement
        require(0 < count <= 262144 and 12 + count * 8 <= len(data), "invalid fixture unwind table count")
        entries = [struct.unpack_from(order + "ii", data, 12 + index * 8) for index in range(count)]
        require(all(entries[index - 1][0] < entries[index][0] for index in range(1, count)),
                "unordered fixture unwind search table")
        referenced = {header["address"] + entry[1] for entry in entries}
        require(len(referenced) == count, "duplicate fixture unwind FDE")

        def length(address):
            value, = struct.unpack(order + "I", read(address, 4))
            require(4 <= value <= 64 * 1024 * 1024, "unsupported fixture unwind record length")
            return value

        require(all(start <= address < start + 64 * 1024 * 1024 - 8 for address in referenced),
                "fixture unwind FDE outside bounded frame extent")
        end = max(address + 4 + length(address) for address in referenced)
        offset = locate(start, end - start)
        cies, fdes = set(), set()
        cursor = start
        while cursor < end:
            require(len(cies) + len(fdes) < 262144 and end - cursor >= 8, "invalid fixture unwind record boundary")
            size, identity = struct.unpack(order + "II", read(cursor, 8))
            require(4 <= size <= end - cursor - 4, "fixture unwind record crosses frame extent")
            if identity == 0:
                require(size >= 9, "short fixture CIE")
                version = read(cursor + 8, 1)[0]
                require(version in (1, 3, 4) and (version != 4 or size >= 11), "unsupported fixture CIE")
                cies.add(cursor)
            else:
                require(size >= 6 and cursor + 4 - identity in cies, "fixture FDE lacks earlier CIE")
                fdes.add(cursor)
            cursor += 4 + size
        require(cursor == end and fdes == referenced, "fixture frame records disagree with search table")
    return {"origin": "ORIGINAL_SEGMENT", "original_index": header["index"],
            "fields": {"name": b".eh_frame".hex(), "type": 1, "flags": 2,
                       "address": start, "offset": offset, "size": end - start,
                       "link": 0, "info": 0, "alignment": 1, "entry_size": 0}}


def allocation_model(original, candidate):
    """Normal fixture relation: indexed fields plus physical note coverage.

    This deliberately refuses unsupported source views instead of inferring
    intent from the candidate. Synthetic unsupported cases belong to the Java
    smoke; this oracle proves the six ordinary exporter roles independently.
    """
    left, right = metadata(original), metadata(candidate)
    require(left["target"] == right["target"], "fixture target identity changed")
    require(not any(right[key] for key in ("phoff", "phsize", "phcount")) and right["names"] and
            right["shoff"] >= left["bytes"] and right["shsize"] == (64 if right["wide"] else 40),
            "candidate is outside matched-writer envelope")
    expected, relocations, loads, notes = {}, 0, 0, 0
    if left["sections"]:
        for section in left["sections"][1:]:
            if not active(section):
                continue
            index = section["index"]
            name = bytes.fromhex(section["name"]).decode("utf-8", errors="strict")
            require(index != left["names"] and not name.startswith((".debug_", ".zdebug_")) and
                    name not in (".gdb_index", ".gnu_debuglink", ".gnu_debugaltlink", ".gnu_debugdata"),
                    "fixture needs unsupported allocation transformation")
            fields = projection(section)
            if section["type"] in (4, 9):
                fields.update(type=8, flags=2, link=0, info=0, entry_size=0)
                relocations += 1
            expected[index] = {"origin": "ORIGINAL_SECTION", "original_index": index, "fields": fields}
        next_index = len(left["sections"])
    else:
        next_index = 1
        for segment in left["segments"]:
            if segment["type"] != 1 or not segment["memory_size"]:
                continue
            fields = {"name": (".forge.load." + str(segment["index"])).encode().hex(), "type": 8,
                      "flags": 2 | (1 if segment["flags"] & 2 else 0) | (4 if segment["flags"] & 1 else 0),
                      "address": segment["address"], "offset": segment["offset"], "size": segment["memory_size"],
                      "alignment": 1, "link": 0, "info": 0, "entry_size": 0}
            expected[next_index] = {"origin": "ORIGINAL_SEGMENT", "original_index": segment["index"], "fields": fields}
            next_index += 1
            loads += 1
        unwind = original_unwind(original, left)
        if unwind is not None:
            expected[next_index] = unwind
            next_index += 1
    typed = [section for section in left["sections"] if section["type"] == 7 and section["size"]]
    views = [segment for segment in left["segments"] if segment["type"] == 4 and segment["file_size"]]
    # Only the small six-role fixtures use this quadratic independent check;
    # production's bounded interval implementation is not reused here.
    require(len(typed) + len(views) < 128, "fixture note views exceed independent small-model bound")
    for view in views:
        for other in typed + views:
            end = other["offset"] + other.get("file_size", other.get("size", 0))
            if max(view["offset"], other["offset"]) < min(view["offset"] + view["file_size"], end):
                require(other["address"] - other["offset"] == view["address"] - view["offset"] and
                        (other in views or active(other)), "ambiguous fixture note address view")
    covered = merged((item["offset"], item["offset"] + item["size"]) for item in typed)
    for view in views:
        cursor, end = view["offset"], view["offset"] + view["file_size"]
        gaps = []
        for start, stop in covered:
            if stop <= cursor:
                continue
            if start >= end:
                break
            if start > cursor:
                gaps.append((cursor, min(start, end)))
            cursor = max(cursor, min(stop, end))
        if cursor < end:
            gaps.append((cursor, end))
        for start, stop in gaps:
            alignment = max(1, view["alignment"])
            require(stop - start >= 12 and (start - view["offset"]) % alignment == 0, "invalid fixture note gap")
            fields = {"name": (".note.forge." + str(notes)).encode().hex(), "type": 7, "flags": 2,
                      "address": view["address"] + start - view["offset"], "offset": start, "size": stop - start,
                      "alignment": alignment, "link": 0, "info": 0, "entry_size": 0}
            expected[next_index] = {"origin": "ORIGINAL_SEGMENT", "original_index": view["index"], "fields": fields}
            next_index += 1
            notes += 1
        covered = merged(covered + gaps)
    differences = []
    for index, record in expected.items():
        require(index < len(right["sections"]), "missing candidate index")
        for field, elf_field in zip(FIELDS, ELF_FIELDS):
            if record["fields"][field] != right["sections"][index][field]:
                differences.append({"origin": record["origin"], "original_index": record["original_index"],
                    "candidate_index": index, "field": elf_field, "value_kind": field,
                    "expected": record["fields"][field], "observed": right["sections"][index][field]})
    for section in right["sections"]:
        if active(section) and section["index"] not in expected:
            differences.append({"origin": "CANDIDATE_SECTION", "original_index": -1,
                "candidate_index": section["index"], "field": "sh_flags", "value_kind": "unexpected",
                "expected": "no additional allocation", "observed": section["name"]})
    require(expected, "ordinary fixture has no allocation evidence")
    return {"records": expected, "differences": differences, "relocation_placeholders": relocations,
            "reconstructed_loads": loads, "reconstructed_notes": notes}


def display_name(hex_name):
    return f"bytes[{len(hex_name) // 2}]=" + hex_name[:64] + ("..." if len(hex_name) > 64 else "")


def decoded(value):
    return base64.b64decode(value, validate=True).decode("utf-8", errors="strict")


def probe(pairs, jar, classes, destination, reject=False, state=snapshot):
    before = {str(path): state(path) for pair in pairs for path in pair}
    output = run([os.environ.get("JAVA", "java"), "-Xmx64m", "-cp", os.pathsep.join(map(str, (jar, classes))),
                  "ghidradwarfforge.elf.MatchedElfAllocationsProbe", *(["--expect-rejection"] if reject else []),
                  *(path for pair in pairs for path in pair)], destination)
    lines = output.splitlines()
    for line, kind in zip(lines[:2], ("allocation", "elf-image")):
        require(line.startswith(kind + "-class-source="), "missing allocation class origin")
        origin = urlparse(line.split("=", 1)[1])
        require(origin.scheme == "file" and Path(unquote(origin.path)).resolve() == jar, "wrong installed class origin")
    require(re.fullmatch(r"java-version=21(?:[.+-].*)?", lines[2]) is not None, "actual Java21 required")
    require(lines[3].startswith("max-heap=") and 0 < int(lines[3].split("=")[1]) <= 64 * 1024 * 1024,
            "allocation observer heap is not bounded")
    require(len(lines) == len(pairs) + 4, "unexpected allocation output")
    observations = []
    for index, (line, pair) in enumerate(zip(lines[4:], pairs)):
        parts = line.split("\t")
        if reject:
            require(len(parts) == 3 and parts[:2] == ["rejected", "java.io.IOException"] and
                    decoded(parts[2]).strip(), "malformed ELF did not fail with IOException")
            observations.append({"exception": parts[1], "diagnostic": decoded(parts[2])})
            continue
        require(len(parts) in (5, 11) and parts[:2] == ["allocation", str(index)], "invalid allocation protocol")
        actual = {"status": parts[2], "diagnostic": decoded(parts[3]), "issue": None}
        require(actual["diagnostic"].strip(), "empty allocation diagnostic")
        model = allocation_model(*pair)
        if model["differences"]:
            require(len(parts) == 11, "allocation difference lacks a structured issue")
            first = model["differences"][0]
            issue = {"origin": parts[4], "original_index": int(parts[5]), "candidate_index": int(parts[6]),
                     **dict(zip(("field", "reason", "expected", "observed"), map(decoded, parts[7:])))}
            require(actual["status"] == "DIFFERENT_METADATA" and all(issue[key] == first[key] for key in
                    ("origin", "original_index", "candidate_index", "field")), "wrong indexed allocation issue")
            if first["value_kind"] == "unexpected":
                wanted, found = first["expected"], display_name(first["observed"])
            elif first["value_kind"] == "name":
                wanted = (bytes.fromhex(first["expected"]).decode("ascii") if first["origin"] == "ORIGINAL_SEGMENT"
                          else display_name(first["expected"]))
                found = display_name(first["observed"])
            else:
                wanted, found = first["expected"], first["observed"]
                require((int(issue["expected"], 0), int(issue["observed"], 0)) == (wanted, found),
                        "wrong numeric allocation values")
            if first["value_kind"] in ("unexpected", "name"):
                require((issue["expected"], issue["observed"]) == (wanted, found), "wrong allocation name evidence")
            require(issue["reason"].strip(), "allocation issue has no reason")
            actual["issue"] = issue
        else:
            require(parts[2:] == ["MATCHING_ALLOCATED_METADATA", parts[3], "NONE"], "ordinary pair did not match")
        observations.append(actual)
    require({path: state(Path(path)) for path in before} == before, "allocation observer modified an input")
    return observations


def parent_result(module, target, explicit):
    if explicit:
        selected = explicit / "result.json" if explicit.is_dir() else explicit
        selected = selected.resolve(strict=True)
    else:
        matches = []
        root = REPOSITORY / "build/test-results/matched-elf-prefix"
        for path in root.glob(target + ".*/result.json"):
            item = json.loads(path.read_text(), object_pairs_hook=PREFIX.reject_duplicates)
            if item.get("status") == "PASS" and item.get("target") == target and item.get("module") == str(module):
                matches.append(path)
        require(len(matches) == 1, "require exactly one preceding prefix result for target/module")
        selected = matches[0].resolve(strict=True)
    receipt = json.loads(selected.read_text(encoding="utf-8"), object_pairs_hook=PREFIX.reject_duplicates)
    require(receipt["status"] == "PASS" and receipt["target"] == target and
            len(receipt["pairs"]) == 6 and all(item["status"] == "MATCHING_COPIED_PREFIX" for item in receipt["pairs"]),
            "parent prefix result is not a completed six-role observation")
    if not explicit:
        require(receipt["module"] == receipt["producer_module"] == str(module) and receipt["same_export_installation"],
                "fresh CI oracle must use the same installed producer and observers")
    return selected, receipt


def retain_parent(path, receipt, work, protected):
    protected[str(path)] = snapshot(path)
    shutil.copyfile(path, work / "parent-prefix-result.json")
    require(snapshot(work / "parent-prefix-result.json")["sha256"] == protected[str(path)]["sha256"], "parent receipt copy differs")
    require(len(receipt["retained_artifacts"]) == 18 and len(receipt["reports"]) == 6, "incomplete parent inputs")
    pairs, retained, reports = [], [], []
    decoder = json.JSONDecoder(object_pairs_hook=PREFIX.reject_duplicates)
    for role in PREFIX.ROLES:
        records = [item for item in receipt["reports"] if item["role"] == role]
        require(len(records) == 1, "duplicate/missing parent role")
        record = records[0]
        log = Path(record["retained_log"])
        require(log.resolve(strict=True) == path.parent / (role + ".export.log"), "parent log escapes result")
        protected[str(log)] = snapshot(log)
        transcript = log.read_bytes()
        require(hashlib.sha256(transcript).hexdigest() == record["log_sha256"] ==
                receipt["protected"][record["source_log"]]["sha256"], "parent transcript hash differs")
        text = transcript.decode("utf-8", errors="strict")
        script = Path(receipt["producer_module"]) / "ghidra_scripts/GhidraDwarfForge.java"
        require(text.count("SCRIPT: " + str(script)) == 1, "wrong parent installed exporter")
        bodies = [line.split("GhidraDwarfForge report: ", 1)[1] for line in text.splitlines()
                  if "GhidraDwarfForge report: " in line]
        require(len(bodies) == 1, "ambiguous production report")
        report, end = decoder.raw_decode(bodies[0])
        require(bodies[0][end:].strip() == "(GhidraScript)" and report == record["report"] and
                report["status"] in ("SUCCESS", "PARTIAL"), "parent report/transcript mismatch")
        copied_log = work / (role + ".export.log")
        copied_log.write_bytes(transcript)
        role_paths = []
        for label in ("input", "output", "source"):
            original = report["artifacts"][label + "Path"]
            candidates = [item for item in receipt["retained_artifacts"] if item["original"] == original]
            require(len(candidates) == 1, "ambiguous parent selected input")
            source = Path(candidates[0]["retained"])
            require(source.resolve(strict=True) == path.parent / f"{role}.{label}.bytes", "parent input escapes result")
            protected[str(source)] = snapshot(source)
            wanted = report["artifacts"][label + "Sha256"].lower()
            require(wanted == protected[str(source)]["sha256"] == candidates[0]["snapshot"]["sha256"] ==
                    receipt["protected"][original]["sha256"] and
                    protected[str(source)]["bytes"] == candidates[0]["snapshot"]["bytes"], "parent byte binding differs")
            destination = work / source.name
            shutil.copyfile(source, destination)
            copied = snapshot(destination)
            require(copied["sha256"] == wanted, "owned input copy differs")
            retained.append({"role": role, "kind": label, "original": original, "parent_copy": str(source),
                             "retained": str(destination), "snapshot": copied})
            role_paths.append(destination)
        source_image = metadata(role_paths[0])
        profile = source_image["target"]
        require((profile["class"], profile["order"], profile["machine"]) == PREFIX.PROFILES[receipt["target"]],
                "parent fixture profile differs")
        require(profile["type"] == (3 if role in ("pie", "shared") else 2) and
                bool(source_image["sections"]) == (role != "exec.no-sections"),
                "parent fixture role differs")
        pairs.append(role_paths[:2])
        reports.append({**record, "parent_retained_log": str(log), "retained_log": str(copied_log)})
    return pairs, retained, reports


def mutations(pair, work):
    original, sidecar = pair
    image = metadata(sidecar)
    def named(name):
        matches = [section for section in image["sections"] if section["name"] == name.encode().hex()]
        require(len(matches) == 1, "fixture lacks unique " + name)
        return matches[0]

    text, data, debug = named(".text"), named(".data"), named(".debug_info")
    offsets = {"name_offset": 0, "type": 4, "flags": 8, "address": 16 if image["wide"] else 12,
               "offset": 24 if image["wide"] else 16, "size": 32 if image["wide"] else 20,
               "link": 40 if image["wide"] else 24, "info": 44 if image["wide"] else 28,
               "alignment": 48 if image["wide"] else 32, "entry_size": 56 if image["wide"] else 36}
    cases = [("text-" + key, text, key, value) for key, value in (
        ("name_offset", data["name_offset"]), ("type", 8), ("flags", text["flags"] & ~2),
        ("address", text["address"] + 0x100000), ("offset", text["offset"] + 1),
        ("size", text["size"] - 1), ("link", 1), ("info", 1),
        ("alignment", 1 if text["alignment"] != 1 else 2), ("entry_size", 1))]
    cases.append(("unexpected-debug-allocation", debug, "flags", debug["flags"] | 2))
    relocations = [section for section in metadata(original)["sections"] if active(section) and section["type"] in (4, 9)]
    if relocations:
        placeholder = image["sections"][relocations[0]["index"]]
        cases.append(("relocation-flags", placeholder, "flags", 3))
    results = []
    for label, section, field, value in cases:
        require(section["header"] >= original.stat().st_size and section[field] != value, "mutation is not an appended change")
        path = work / (label + ".dbg")
        shutil.copyfile(sidecar, path)
        with path.open("r+b") as stream:
            stream.seek(section["header"] + offsets[field])
            wide_field = image["wide"] and field not in ("name_offset", "type", "link", "info")
            stream.write(struct.pack(image["order"] + ("Q" if wide_field else "I"), value))
        require(allocation_model(original, path)["differences"], "active mutation has no independent difference")
        results.append({"name": label, "pair": [original, path], "changed_index": section["index"], "field": field})
    swapped = work / "swapped-indices.dbg"
    shutil.copyfile(sidecar, swapped)
    with swapped.open("r+b") as stream:
        stream.seek(text["header"])
        first = stream.read(image["shsize"])
        stream.seek(data["header"])
        second = stream.read(image["shsize"])
        stream.seek(text["header"])
        stream.write(second)
        stream.seek(data["header"])
        stream.write(first)
    def multiset(value):
        return sorted(json.dumps(projection(section), sort_keys=True) for section in value["sections"] if active(section))
    require(multiset(image) == multiset(metadata(swapped)), "index swap changed allocated multiset")
    results.append({"name": "swapped-indices", "pair": [original, swapped], "same_allocated_multiset": True})
    return results


def unwind_mutations(pair, work):
    original, sidecar = pair
    source = metadata(original)
    require(not source["sections"], "unwind mutation control requires sectionless input")
    if original_unwind(original, source) is None:
        return []
    image = metadata(sidecar)
    frame, = [section for section in image["sections"] if section["name"] == b".eh_frame".hex()]
    offsets = (0, 4, 8, 16, 24, 32, 40, 44, 48, 56) if image["wide"] else tuple(range(0, 40, 4))
    results = []
    for field, offset in zip(("name_offset", *FIELDS[1:]), offsets):
        value = 0 if field == "name_offset" else frame[field] - 1 if field == "size" else frame[field] + 1
        path = work / ("unwind-" + field + ".dbg")
        shutil.copyfile(sidecar, path)
        with path.open("r+b") as stream:
            stream.seek(frame["header"] + offset)
            wide = image["wide"] and field not in ("name_offset", "type", "link", "info")
            stream.write(struct.pack(image["order"] + ("Q" if wide else "I"), value))
        model = allocation_model(original, path)
        require(model["differences"] and model["differences"][0]["candidate_index"] == frame["index"],
                "unwind field mutation escaped independent oracle")
        results.append({"name": "unwind-" + field, "pair": [original, path], "field": field})
    return results


def same_installation(module, receipt, current):
    if str(module) != receipt["producer_module"]:
        return False
    for suffix in ("lib/GhidraDwarfForge.jar", "ghidra_scripts/GhidraDwarfForge.java"):
        key = str(module / suffix)
        if key not in receipt["protected"] or current[key]["sha256"] != receipt["protected"][key]["sha256"]:
            return False
    return True


def metadata_snapshot(path):
    """Hash only bounded active metadata, explicitly not the whole sparse file."""
    image = metadata(path)
    ranges = {(0, 64 if image["wide"] else 52),
              (image["shoff"], image["shsize"] * len(image["sections"]))}
    if image["names"]:
        names = image["sections"][image["names"]]
        ranges.add((names["offset"], names["size"]))
    records = []
    with path.open("rb") as stream:
        for offset, length in sorted(ranges):
            stream.seek(offset)
            data = stream.read(length)
            require(len(data) == length, "short sparse metadata read")
            records.append({"offset": offset, "bytes": length, "sha256": hashlib.sha256(data).hexdigest()})
    stat = path.stat()
    return {"bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns, "allocated_disk_bytes": stat.st_blocks * 512,
            "selected_metadata_ranges": records, "whole_file_sha256": None}


def large_control(work, jar, classes):
    """Independent sparse recipe: original and active tables above signed int range."""
    old_names = b"\0.bss\0.shstrtab\0"
    new_names = old_names + b".shstrtab.old\0"
    names_offset = (1 << 31) + 4096
    table_offset = (names_offset + len(old_names) + 7) & ~7
    original_size = table_offset + 3 * 64
    new_names_offset = original_size
    new_table_offset = (new_names_offset + len(new_names) + 7) & ~7
    def header(table, count, names):
        result = bytearray(64)
        result[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHI", result, 16, 2, 62, 1)
        struct.pack_into("<Q", result, 40, table)
        struct.pack_into("<HHHHHH", result, 52, 64, 0, 0, 64, count, names)
        return bytes(result)

    def section(name, kind, flags, address, offset, size):
        return struct.pack("<IIQQQQIIQQ", name, kind, flags, address, offset, size, 0, 0, 1, 0)

    allocation = section(1, 8, 3, 0x500000, names_offset - 1, 4096)
    old_table = bytes(64) + allocation + section(6, 3, 0, 0, names_offset, len(old_names))
    new_table = (bytes(64) + allocation + section(len(old_names), 3, 0, 0, names_offset, len(old_names)) +
                 section(6, 3, 0, 0, new_names_offset, len(new_names)))
    original, candidate = work / "large-original.elf", work / "large-candidate.elf"
    recipes = {
        "original": [(0, header(table_offset, 3, 2)), (names_offset, old_names), (table_offset, old_table)],
        "candidate": [(0, header(new_table_offset, 4, 3)), (names_offset, old_names), (table_offset, old_table),
                      (new_names_offset, new_names), (new_table_offset, new_table)]}
    recipe = {"scope": "sparse metadata-only input; no whole-file hash or large prefix claim",
              "writes": {key: [{"offset": offset, "hex": data.hex(), "sha256": hashlib.sha256(data).hexdigest()}
                               for offset, data in chunks] for key, chunks in recipes.items()},
              "changed_offset": new_table_offset + 64 + 16, "changed_address": 0x600000}
    (work / "large-recipe.json").write_text(json.dumps(recipe, indent=4) + "\n")
    try:
        for key, path in (("original", original), ("candidate", candidate)):
            with path.open("wb") as stream:
                for offset, data in recipes[key]:
                    stream.seek(offset)
                    stream.write(data)
            require(path.stat().st_size > (1 << 31) and path.stat().st_blocks * 512 < 1024 * 1024,
                    "metadata control is not a bounded sparse file")
        before = {str(path): metadata_snapshot(path) for path in (original, candidate)}
        matched = probe([(original, candidate)], jar, classes, work / "large-match", state=metadata_snapshot)
        require(matched[0]["status"] == "MATCHING_ALLOCATED_METADATA", "large metadata did not match")
        with candidate.open("r+b") as stream:
            stream.seek(recipe["changed_offset"])
            stream.write(struct.pack("<Q", recipe["changed_address"]))
        shifted = metadata_snapshot(candidate)
        difference = probe([(original, candidate)], jar, classes, work / "large-difference", state=metadata_snapshot)
        require(difference[0]["issue"]["field"] == "sh_addr" and difference[0]["issue"]["candidate_index"] == 1,
                "large active-table mutation was not detected")
        require(metadata_snapshot(original) == before[str(original)] and metadata_snapshot(candidate) == shifted,
                "large metadata observer changed input")
        return {"before": before, "candidate_after_owned_mutation": shifted, "match": matched[0],
                "difference": difference[0], "recipe": recipe, "inputs_removed_after_test": True}
    finally:
        original.unlink(missing_ok=True)
        candidate.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=PREFIX.PROFILES)
    parser.add_argument("--prefix-result", type=Path, help="explicit earlier prefix result/receipt; replay, not fresh export")
    parser.add_argument("--large", action="store_true", help="x86-only sparse metadata control above 2 GiB")
    args = parser.parse_args()
    module = args.module.resolve(strict=True)
    jar = (module / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    script = (module / "ghidra_scripts/GhidraDwarfForge.java").resolve(strict=True)
    parent_path, receipt = parent_result(module, args.target, args.prefix_result)
    installation = {str(path): snapshot(path) for path in (jar, script)}
    same_export_installation = same_installation(module, receipt, installation)
    if not args.prefix_result:
        require(same_export_installation, "producer JAR/script changed after prefix oracle")
    require(not args.large or args.target == "x86_64", "large metadata control is x86-only")
    root = REPOSITORY / "build/test-results/matched-elf-allocations"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=args.target + ".", dir=root))
    print(f"matched-elf-allocations-results={work}", flush=True)
    protected = installation
    pairs, retained, reports = retain_parent(parent_path, receipt, work, protected)
    classes = work / "classes"
    classes.mkdir()
    run([os.environ.get("JAVAC", "javac"), "--release", "21", "-cp", jar, "-d", classes,
         REPOSITORY / "src/test/java/ghidradwarfforge/elf/MatchedElfAllocationsProbe.java",
         REPOSITORY / "src/test/java/ghidradwarfforge/elf/MatchedElfPrefixProbe.java"], work / "compile")
    models = [allocation_model(*pair) for pair in pairs]
    require(all(not model["differences"] for model in models), "real pair fails independent metadata relation")
    positive = probe(pairs, jar, classes, work / "pairs")
    require(probe(pairs, jar, classes, work / "repeat") == positive, "allocation observation is nondeterministic")
    prefix_results = PREFIX.probe(pairs, jar, classes, work / "prefix-pairs")
    require(all(item["status"] == "MATCHING_COPIED_PREFIX" for item in prefix_results), "retained pair prefix differs")
    changed = mutations(pairs[0], work)
    changed_pairs = [item["pair"] for item in changed]
    mutation_snapshots = {str(path): snapshot(path) for pair in changed_pairs for path in pair}
    differences = probe(changed_pairs, jar, classes, work / "metadata-mutations")
    prefix_changes = PREFIX.probe(changed_pairs, jar, classes, work / "metadata-mutation-prefixes")
    require(all(item["status"] == "MATCHING_COPIED_PREFIX" for item in prefix_changes), "metadata control changed retained prefix")
    sectionless, = [pair for pair in pairs if not metadata(pair[0])["sections"]]
    unwind_changed = unwind_mutations(sectionless, work)
    unwind_pairs = [item["pair"] for item in unwind_changed]
    unwind_differences = probe(unwind_pairs, jar, classes, work / "unwind-mutations") if unwind_pairs else []
    unwind_prefixes = PREFIX.probe(unwind_pairs, jar, classes, work / "unwind-prefixes") if unwind_pairs else []
    require(all(item["status"] == "MATCHING_COPIED_PREFIX" for item in unwind_prefixes),
            "unwind field mutation changed copied prefix")
    original, sidecar = pairs[0]
    before = metadata(original)
    text = next(section for section in before["sections"] if section["name"] == b".text".hex())
    code = work / "changed-code.elf"
    shutil.copyfile(original, code)
    with code.open("r+b") as stream:
        stream.seek(text["offset"])
        byte = stream.read(1)
        require(len(byte) == 1, "empty fixture code")
        stream.seek(text["offset"])
        stream.write(bytes([byte[0] ^ 0x80]))
    require(metadata(code) == before, "code control changed metadata")
    code_snapshot = snapshot(code)
    code_result = probe([(code, sidecar)], jar, classes, work / "changed-code")
    code_prefix = PREFIX.probe([(code, sidecar)], jar, classes, work / "changed-code-prefix")
    require(code_prefix[0]["status"] == "DIFFERENT_PREFIX" and code_prefix[0]["different"] == text["offset"],
            "code control did not expose independent prefix difference")
    require(snapshot(code) == code_snapshot, "metadata/prefix observers changed code control")
    malformed = work / "malformed.elf"
    malformed.write_bytes(b"\x7fELF")
    malformed_result = probe([(malformed, sidecar), (original, malformed)], jar, classes, work / "malformed", reject=True)
    large = large_control(work, jar, classes) if args.large else None
    require({path: snapshot(Path(path)) for path in protected} == protected, "allocation oracle changed protected input")
    require({path: snapshot(Path(path)) for path in mutation_snapshots} == mutation_snapshots,
            "metadata observers changed a mutation input")
    require(all(snapshot(Path(item["retained"])) == item["snapshot"] for item in retained), "retained fixture changed")
    for record in reports:
        require(snapshot(Path(record["retained_log"]))["sha256"] == record["log_sha256"], "retained transcript changed")
    result = {"status": "PASS", "target": args.target, "module": str(module), "producer_module": receipt["producer_module"],
              "same_export_installation": same_export_installation,
              "export_evidence": "explicit retained-export replay" if args.prefix_result else "preceding same-installation prefix oracle",
              "parent_prefix_result": str(parent_path), "parent_prefix_sha256": protected[str(parent_path)]["sha256"],
              "protected": protected, "retained_artifacts": retained, "reports": reports, "models": models,
              "mutation_snapshots": mutation_snapshots,
              "pairs": positive, "prefix_pairs": prefix_results,
              "unwind_metadata_mutations": [{**item, "pair": list(map(str, item["pair"])), "allocation": difference, "prefix": prefix}
                  for item, difference, prefix in zip(unwind_changed, unwind_differences, unwind_prefixes)],
              "metadata_mutations": [{**item, "pair": list(map(str, item["pair"])), "allocation": difference, "prefix": prefix}
                  for item, difference, prefix in zip(changed, differences, prefix_changes)],
              "changed_code": {"allocation": code_result[0], "prefix": code_prefix[0], "same_metadata": True,
                               "snapshot": code_snapshot},
              "malformed": malformed_result, "large": large,
              "preservation_scope": "before/after this invocation; prior originals and archive mtimes are not re-attested",
              "scope": "indexed active metadata correspondence only; not copied-byte, DWARF, file identity or attachment proof"}
    (work / "result.json").write_text(json.dumps(result, indent=4) + "\n")
    print(f"matched-elf-allocations-{args.target}=PASS", flush=True)


if __name__ == "__main__":
    main()
