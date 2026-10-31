#!/usr/bin/env python3
"""Check local DIEs, persisted preparation metadata and both exporter reports."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


FUNCTIONS = {"stack_scope": "second", "zero_stack": "zero"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def text_value(value):
    # GNU readelf can include form annotations and indirect-string offsets.
    value = value.rsplit(": ", 1)[-1]
    return re.sub(r"^(?:\([^)]*\)\s*)+", "", value).strip()


def number(value):
    value = text_value(value)
    found = re.match(r"(0x[0-9a-fA-F]+|[0-9]+)(?:\s|$)", value)
    require(found is not None, "missing numeric attribute: " + value)
    return int(found[1], 16 if found[1].startswith("0x") else 10)


def parse_dies(text):
    records = []
    offsets = set()
    for line in text.splitlines():
        header = re.match(r"^\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+"
            r"(?: \((DW_TAG_\w+)\))?", line)
        if header:
            offset = int(header[2], 16)
            require(offset not in offsets, "duplicate DIE offset")
            offsets.add(offset)
            records.append({"depth": int(header[1]), "offset": offset,
                "tag": header[3], "attributes": {}})
        elif records:
            attribute = re.match(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)", line)
            if attribute:
                require(attribute[1] not in records[-1]["attributes"], "duplicate DIE attribute")
                records[-1]["attributes"][attribute[1]] = attribute[2]
    require(sum(record["tag"] == "DW_TAG_compile_unit" for record in records) == 1,
        "expected one emitted compilation unit")
    return records


def check_dies(text, labels, fixed):
    records = parse_dies(text)
    by_offset = {record["offset"]: record for record in records}
    found = {}
    for index, record in enumerate(records):
        attributes = record["attributes"]
        name = text_value(attributes.get("DW_AT_name", ""))
        if record["tag"] != "DW_TAG_subprogram" or name not in FUNCTIONS:
            continue
        require(name not in found, "duplicate fixture function: " + name)
        require("DW_AT_declaration" not in attributes, "fixture definition became a declaration")
        low = number(attributes["DW_AT_low_pc"])
        high = number(attributes["DW_AT_high_pc"])
        if not attributes["DW_AT_high_pc"].lstrip().startswith("(addr)"):
            high += low
        require((low, high) == (labels[name]["entry"], labels[name]["end"]),
            "fixture function bounds differ from compiler symbols: " + name)
        children = []
        for child in records[index + 1:]:
            if child["depth"] <= record["depth"]:
                break
            if child["tag"] == "DW_TAG_variable" and text_value(
                    child["attributes"].get("DW_AT_name", "")) == FUNCTIONS[name]:
                require(child["depth"] == record["depth"] + 1,
                    "curated local acquired an invented nested scope")
                children.append(child)
        require(len(children) == 1, "missing or duplicate local: " + name + "::" + FUNCTIONS[name])
        local = children[0]["attributes"]
        reference = re.search(r"<(?:0x)?([0-9a-fA-F]+)>", local.get("DW_AT_type", ""))
        require(reference is not None, "local lost its type reference")
        type_die = by_offset.get(int(reference[1], 16))
        require(type_die is not None and type_die["tag"] == "DW_TAG_base_type",
            "curated integer local lost its base type")
        require(number(type_die["attributes"]["DW_AT_byte_size"]) == 4 and
            number(type_die["attributes"]["DW_AT_encoding"]) == 5,
            "curated local is not a signed four-byte integer")
        require("DW_AT_const_value" not in local and "DW_AT_start_scope" not in local,
            "fixture local acquired a guessed value or scope start")
        location = local.get("DW_AT_location")
        expected_location = name == "zero_stack" or not fixed
        require(bool(location) == expected_location,
            "incorrect location policy for " + name + "::" + FUNCTIONS[name])
        found[name] = {"name": FUNCTIONS[name], "type_offset": type_die["offset"],
            "location_present": expected_location}
    require(set(found) == set(FUNCTIONS), "fixture function inventory incomplete")
    return found


def check_report(text, labels, storage, fixed, artifact_hash):
    first_use = labels["stack_scope"]["second_live"] - labels["stack_scope"]["entry"]
    require(first_use > 0, "fixture must record an explicit later stack first-use")
    prepared = re.findall(r"stack-first-use-local=(\w+) first-use=(-?\d+) storage=(-?\d+)(?=\s|$)", text)
    require(sorted(prepared) == sorted([
        ("second", str(first_use), str(storage["scope_offset"])),
        ("zero", "0", str(storage["zero_offset"]))]),
        "preparation did not confirm exact stored first-use/stack offsets")
    require(text.count("stack-first-use-preparation=PASS") == 1,
        "preparation did not complete exactly once")
    reports = []
    marker = "GhidraDwarfForge report: "
    for line in text.splitlines():
        if marker in line:
            reports.append(json.JSONDecoder().raw_decode(line.split(marker, 1)[1])[0])
    require(len(reports) == 1, "expected exactly one structured export report")
    report = reports[0]
    require(report["schemaVersion"] == 1 and report["status"] in ("SUCCESS", "PARTIAL") and
        report["failure"] is None and report["failedFunctions"] == [] and
        report["counts"]["functionsFailed"] == 0,
        "fixture export did not complete with decompiled functions")
    require(report["artifacts"]["outputSha256"] == artifact_hash,
        "report is not for the inspected sidecar bytes")
    require(report["counts"]["omittedLocationRanges"] == len(report["omittedLocations"]),
        "reported omission count disagrees with its inventory")
    own = [item for item in report["omittedLocations"] if
        item["function"] in FUNCTIONS and item["variable"] == FUNCTIONS[item["function"]]]
    diagnostic = "stack local has unsupported nonzero first-use offset " + str(first_use) + \
        "; its lifetime is not established"
    full_diagnostic = "Omitted location for stack_scope::second: " + diagnostic
    if fixed:
        require(len(own) == 1, "missing or additional fixture omission")
        item = own[0]
        require(item["function"] == "stack_scope" and item["variable"] == "second" and
            item["kind"] == "LOCAL" and item["reason"] == "UNKNOWN_LIFETIME" and
            item["diagnostic"] == diagnostic and
            int(item["startAddress"], 0) == labels["stack_scope"]["entry"] and
            int(item["endAddress"], 0) == labels["stack_scope"]["end"],
            "unsupported stack first-use did not omit the whole local lifetime")
        require(report["diagnostics"].count(full_diagnostic) == 1,
            "exact unsupported-stack-first-use diagnostic missing or duplicated")
    else:
        require(not own, "baseline unexpectedly omitted a fixture stack local")
        require(not any("unsupported nonzero first-use offset" in item
            for item in report["diagnostics"]), "baseline unexpectedly reports the fixed guard")
    return {"status": report["status"], "fixture_omissions": own,
        "first_use_offset": first_use}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    parser.add_argument("expectation", choices=("fixed", "baseline-reproducer"))
    arguments = parser.parse_args()
    case = arguments.case
    labels = json.loads((case / "labels.json").read_text())
    storage = json.loads((case / "compiler-storage.json").read_text())
    require(set(storage) == {"scope_offset", "zero_offset"} and
        all(isinstance(value, int) and -4096 <= value < 0 for value in storage.values()),
        "missing measured compiler stack storage")
    results = {}
    for iteration, name in (("first", "first.dbg"), ("repeat", "stack.dbg")):
        artifact = case / name
        result = subprocess.run(["readelf", "--debug-dump=info", str(artifact)],
            text=True, capture_output=True, check=True, timeout=60)
        require(not result.stderr, "readelf reported a diagnostic: " + result.stderr)
        artifact_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
        fixed = arguments.expectation == "fixed"
        results[iteration] = {
            "dies": check_dies(result.stdout, labels, fixed),
            "report": check_report((case / ("export-" + iteration + ".log")).read_text(),
                labels, storage, fixed, artifact_hash),
            "sha256": artifact_hash}
    require(results["first"]["sha256"] == results["repeat"]["sha256"],
        "repeated fixture sidecars differ")
    print(json.dumps({"stack_first_use_structure": "PASS", "expectation": arguments.expectation,
        "exports": results}, indent=4))


if __name__ == "__main__":
    main()
