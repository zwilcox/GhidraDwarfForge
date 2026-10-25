#!/usr/bin/env python3
"""Compare the actual prep API inventory with the production omission report."""
import collections
import json
import pathlib
import sys


def single(lines, marker):
    values = []
    for line in lines:
        if marker not in line:
            continue
        body = line.split(marker, 1)[1]
        value, end = json.JSONDecoder().raw_decode(body)
        if body[end:].strip() != "(GhidraScript)":
            raise AssertionError(f"unexpected logging suffix after {marker!r}")
        values.append(value)
    if len(values) != 1:
        raise AssertionError(f"expected one {marker!r}, found {len(values)}")
    return values[0]


def check(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    expected = single(lines, "External function inventory: ")
    report = single(lines, "GhidraDwarfForge report: ")
    assert expected == sorted(expected) and all(isinstance(name, str) for name in expected)
    for name in ("fixture_imports::curated_external_function",
                 "fixture_other_imports::curated_external_function"):
        assert expected.count(name) == 1, ("missing real unreferenced fixture", name, expected)
    assert "fixture_imports::external_counter" not in expected
    skipped = report["skippedFunctions"]
    actual = [row["name"] for row in skipped if row["reason"] == "EXTERNAL_IMPORT"]
    assert actual == expected, ("external inventory mismatch", expected, actual)
    assert report["counts"]["functionsSkipped"] == len(skipped)
    assert report["status"] == "PARTIAL" and report["validation"]["status"] == "NOT_RUN"
    diagnostics = collections.Counter(report["diagnostics"])
    for name in expected:
        message = (f"Skipped external/import function {name}; "
                   "no in-image definition; curated declarations are emitted separately")
        assert diagnostics[message] == 1, ("missing report diagnostic", message)
    assert all(row["reason"] != "EXTERNAL_IMPORT" or "::" in row["name"] for row in skipped)
    print(f"external-function-inventory=PASS external={len(expected)} skipped={len(skipped)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-external-function-inventory.py <headless.log>")
    check(pathlib.Path(sys.argv[1]))
