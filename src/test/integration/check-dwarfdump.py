#!/usr/bin/env python3
"""Require complete checker results with no uncorroborated diagnostics."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import struct
import sys


class ValidationFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ValidationFailure(message)


FRAME_DIAGNOSTIC = re.compile(
    r"\*\*\* DWARF CHECK: DW_DLE_DEBUG_FRAME_LENGTH_NOT_MULTIPLE "
    r"len=0x[0-9a-f]+, len size=0x[0-9a-f]+, extn size=0x[0-9a-f]+, "
    r"totl length=0x[0-9a-f]+, addr size=0x[0-9a-f]+, mod=0x[0-9a-f]+ "
    r"must be zero in (?:fde|cie), offset 0x[0-9a-f]+\. \*\*\*")

COMMON_CHECK_CATEGORIES = frozenset({
    "pubname_attr", "attr_tag", "attr_formclass", "tag_tree", "type_offset",
    "decl_file", "ranges", "line_table", "fde_table", "aranges", "names",
    "frames", "locations", "harmless_errors", "abbreviations", "dwarf_constants",
    "debug_info_gaps", "forward_declarations", "self_references", "attr_encoding",
    "duplicated_attributes"})


def frame_diagnostics(text):
    return [line.strip() for line in text.splitlines()
        if FRAME_DIAGNOSTIC.fullmatch(line.strip())]


def validate_output(text, inherited=(), original=False):
    """Recognize libdwarf 20210528/2.3.2 summaries; never trust exit status alone."""
    require(text.strip(), "checker output is empty")
    require(Counter(frame_diagnostics(text)) == Counter(inherited),
        "uncorroborated inherited frame diagnostics")
    remaining = "\n".join(line for line in text.splitlines() if line.strip() not in inherited)
    require(not re.search(r"\*\*\* DWARF CHECK:|\bDW_DLE_|\b(?:warning|error|fatal):",
        remaining, re.IGNORECASE), "checker reported a diagnostic")
    inherited_count = len(inherited)
    harmless = re.findall(r"HARMLESS ERROR COUNT:\s*(\d+)", text)
    require((not harmless and inherited_count == 0) or harmless == [str(inherited_count)],
        "checker reported uncorroborated harmless errors")
    detected = re.findall(r"^\s*(\d+) Compilers detected:\s*$", text, re.MULTILINE)
    verified = re.findall(r"^\s*(\d+) Compilers verified:\s*$", text, re.MULTILINE)
    require(len(detected) == len(verified) == 1 and
        int(detected[0]) == int(verified[0]) >= (0 if original else 1),
        "missing or inconsistent compiler completion")
    compilers = int(verified[0])
    errors = re.findall(r"^\s*\d+: errors\s*=\s*(\d+), .+$", text, re.MULTILINE)
    require(len(errors) == compilers, "incomplete compiler error records")
    require(sum(map(int, errors)) == (inherited_count if compilers else 0),
        "compiler reported uncorroborated errors")
    require(text.count("*** ERRORS PER COMPILER ***") == 1 and
        text.count("*** TOTAL ERRORS FOR ALL COMPILERS ***") == 1,
        "missing per-compiler or total summary")
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line.strip() == "DWARF CHECK RESULT"]
    require(len(starts) == compilers + 1, "incomplete check tables")
    total_position = next(index for index, line in enumerate(lines)
        if line.strip() == "*** TOTAL ERRORS FOR ALL COMPILERS ***")
    require((not compilers or starts[-2] < total_position) and total_position < starts[-1],
        "misplaced total summary")
    modern_format = "Number of TAG records" in text
    required_rows = COMMON_CHECK_CATEGORIES | ({"function_coverage"} if modern_format else set())
    for start, expected_errors in zip(starts, [*map(int, errors), inherited_count]):
        require(start + 1 < len(lines) and
            lines[start + 1].split() == ["<item>", "<checks>", "<errors>"],
            "malformed check table header")
        rows = {}
        completed = False
        for line in lines[start + 2:]:
            summary = re.fullmatch(r"\s*\*\* Summarize \*\*\s+(\d+)\s+(\d+)\s*", line)
            if summary:
                require(required_rows == rows.keys(),
                    "check table categories differ: missing=" +
                    ",".join(sorted(required_rows - rows.keys())) + "; unexpected=" +
                    ",".join(sorted(rows.keys() - required_rows)))
                require(sum(count for count, _ in rows.values()) == int(summary[1]) > 0,
                    "inconsistent or empty check totals")
                require(int(summary[2]) == expected_errors and
                    rows["harmless_errors"][1] == expected_errors and
                    all(error == 0 for name, (_, error) in rows.items() if name != "harmless_errors"),
                    "check table reported uncorroborated errors")
                completed = True
                break
            row = re.fullmatch(r"\s*([a-z_]+)\s+(\d+)\s+(\d+)\s*", line)
            require(row is not None and row[1] not in rows, "malformed or truncated check table")
            rows[row[1]] = (int(row[2]), int(row[3]))
        require(completed, "check table has no completed summary")
    # Both supported output formats finish the -ka usage report after checking.
    # Require its last complete record as well, not just an early zero table.
    if modern_format:
        tail = text.rsplit("Number of TAG records", 1)[1]
        count = re.match(r"\s*(\d+)", tail)
        instances = re.search(r"Number of distinct TAGs in object\s+(\d+)", tail)
        records = re.findall(r"^\[\s*\d+\]\s+0x[0-9a-f]+\s+DW_TAG_\w+\s+\d+\s+[0-9.]+\s*$",
            tail, re.MULTILINE)
        uses = re.findall(r"^\[\s*\d+\]\s+0x[0-9a-f]+\s+DW_TAG_\w+\s+(\d+)\s+[0-9.]+\s*$",
            tail, re.MULTILINE)
        empty_original = original and not compilers and tail.strip() == "0"
        require(empty_original or (count is not None and instances is not None and
            len(records) == int(count[1]) > 0 and sum(map(int, uses)) == int(instances[1]) and
            tail.rstrip().endswith(records[-1].strip())), "truncated final tag usage report")
    else:
        require("*** COUNT BY ATTRIBUTE ***" in text, "missing final usage report")
        tail = text.rsplit("*** COUNT BY ATTRIBUTE ***", 1)[1]
        require(re.search(r"^\[\s*\d+\] Sum found:\s+\d+\s+100%\s*\Z", tail,
            re.MULTILINE) is not None, "truncated final attribute usage report")
    return {"compilers": compilers, "check_tables": len(starts),
        "reported_errors": inherited_count, "uncorroborated_errors": 0}


def elf_frame_identity(path):
    """Read bounded ELF metadata and the named frame section without rewriting input."""
    with path.open("rb") as stream:
        length = os.fstat(stream.fileno()).st_size

        def region(offset, size):
            require(0 <= offset <= length and 0 <= size <= 64 * 1024 * 1024 and
                size <= length - offset, "invalid or oversized ELF metadata region")
            stream.seek(offset)
            data = stream.read(size)
            require(len(data) == size, "truncated ELF metadata")
            return data

        header = region(0, min(64, length))
        require(len(header) >= 52 and header[:4] == b"\x7fELF" and
            header[4] in (1, 2) and header[5] in (1, 2), "invalid original/sidecar ELF identity")
        wide = header[4] == 2
        endian = "<" if header[5] == 1 else ">"
        require(not wide or len(header) >= 64, "truncated ELF64 header")
        section_offset = struct.unpack_from(endian + ("Q" if wide else "I"), header,
            40 if wide else 32)[0]
        entry_size, count, names_index = struct.unpack_from(endian + "HHH", header,
            58 if wide else 46)
        section_format = endian + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
        require(section_offset > 0 and struct.calcsize(section_format) <= entry_size <= 256,
            "no usable named ELF section table for frame corroboration")
        first = struct.unpack_from(section_format, region(section_offset, entry_size))
        count = first[5] if count == 0 else count
        names_index = first[6] if names_index == 0xffff else names_index
        require(0 < count <= 262144 and 0 < names_index < count,
            "invalid ELF extended section count/name index")
        table = region(section_offset, count * entry_size)
        sections = [struct.unpack_from(section_format, table, index * entry_size)
            for index in range(count)]
        strings = sections[names_index]
        require(strings[1] == 3, "ELF section-name table is not STRTAB")
        names = region(strings[4], strings[5])
        frames = []
        for section in sections:
            require(section[0] < len(names), "invalid ELF section-name offset")
            end = names.find(b"\0", section[0])
            require(end >= 0, "unterminated ELF section name")
            if names[section[0]:end] == b".eh_frame":
                frames.append(section)
        require(len(frames) == 1 and frames[0][1] == 1 and frames[0][5] > 0,
            "frame corroboration requires one nonempty PROGBITS .eh_frame")
        section = frames[0]
        payload = region(section[4], section[5])
        return {"class": header[4], "byte_order": header[5], "os_abi": header[7],
            "abi_version": header[8], "machine": struct.unpack_from(endian + "H", header, 18)[0],
            "flags": struct.unpack_from(endian + "I", header, 48 if wide else 36)[0],
            "section_address": section[3], "section_size": section[5],
            "section_sha256": hashlib.sha256(payload).hexdigest()}, payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("log", type=Path)
    parser.add_argument("--tool", default=os.environ.get("DWARFDUMP", "dwarfdump"))
    parser.add_argument("--original", type=Path,
        help="corroborate only byte-identical inherited .eh_frame alignment diagnostics")
    arguments = parser.parse_args()
    tool = shutil.which(arguments.tool)
    require(tool is not None, "dwarfdump executable was not found: " + arguments.tool)
    artifact = arguments.artifact.resolve(strict=True)
    original = arguments.original.resolve(strict=True) if arguments.original is not None else None
    log = arguments.log.absolute()
    command = [tool, "--no-follow-debuglink", "-ka", "-ki", "-kd", str(artifact)]
    metadata = {"command": command, "cwd": str(Path.cwd()), "status": "FAILED"}
    metadata_path = log.with_name(log.name + ".check.json")
    stderr_path = log.with_name(log.name + ".stderr")
    original_log = log.with_name(log.name + ".original.txt")
    original_stderr = original_log.with_name(original_log.name + ".stderr")
    inputs = [artifact] + ([original] if original is not None else [])
    destinations = [log, stderr_path, metadata_path] + (
        [original_log, original_stderr] if original is not None else [])

    def aliases(first, second):
        return first.resolve() == second.resolve() or (
            first.exists() and second.exists() and os.path.samefile(first, second))

    require(original is None or not aliases(original, artifact),
        "original must be distinct from the artifact being checked")
    for index, destination in enumerate(destinations):
        require(not any(aliases(destination, source) for source in inputs),
            "checker log aliases an ELF input: " + str(destination))
        require(not any(aliases(destination, other) for other in destinations[:index]),
            "checker log destinations alias each other: " + str(destination))
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log.open("wb") as output, stderr_path.open("wb") as errors:
            result = subprocess.run(command, stdout=output, stderr=errors, check=False)
        metadata["exit_status"] = result.returncode
        metadata["stderr_log"] = str(stderr_path)
        require(result.returncode == 0, "checker exited with status " + str(result.returncode))
        require(stderr_path.stat().st_size == 0, "checker wrote to stderr: " + str(stderr_path))
        text = log.read_text(encoding="utf-8", errors="strict")
        inherited = frame_diagnostics(text)
        if inherited and original is not None:
            actual_identity, actual_bytes = elf_frame_identity(artifact)
            original_identity, original_bytes = elf_frame_identity(original)
            require(actual_identity == original_identity and actual_bytes == original_bytes,
                "original and sidecar ELF/frame identities or bytes differ")
            original_command = [*command[:-1], str(original)]
            with original_log.open("wb") as output, original_stderr.open("wb") as errors:
                original_result = subprocess.run(original_command, stdout=output,
                    stderr=errors, check=False)
            metadata["original_check"] = {"command": original_command,
                "log": str(original_log), "stderr_log": str(original_stderr),
                "exit_status": original_result.returncode}
            require(original_result.returncode == 0, "original checker exited nonzero")
            require(original_stderr.stat().st_size == 0,
                "original checker wrote to stderr: " + str(original_stderr))
            validate_output(original_log.read_text(encoding="utf-8", errors="strict"),
                inherited, original=True)
            metadata["inherited_frame_evidence"] = {"original": str(original),
                "identity": original_identity, "diagnostics": inherited}
        else:
            inherited = []
        metadata.update(validate_output(text, inherited))
        metadata["status"] = "PASS"
    except (OSError, UnicodeError, ValidationFailure) as failure:
        metadata["failure"] = str(failure)
        raise ValidationFailure(str(failure) + "; full output: " + str(log)) from failure
    finally:
        metadata_path.write_text(json.dumps(metadata, indent=4) + "\n", encoding="utf-8")
    print("strict-dwarfdump=PASS reported-errors=" + str(metadata["reported_errors"]) +
        " corroborated-frame-errors=" + str(metadata["reported_errors"]) + " log=" + str(log))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValidationFailure) as failure:
        print("strict-dwarfdump=FAIL: " + str(failure), file=sys.stderr)
        sys.exit(1)
