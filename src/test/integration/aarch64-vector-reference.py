#!/usr/bin/env python3
"""Explain only the pinned checker's empty GNU-vector form table in compiler DWARF.

The original report and FAILED strict receipt remain untouched. Forge sidecars
always use the ordinary strict checker without this reference-only accounting.
"""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

source = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, source / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


strict = module("strict", "check-dwarfdump.py")
dies = module("dies", "check-stack-first-use.py")
DIAGNOSTIC = "*** DWARF CHECK: DW_AT_GNU_vector -> DW_FORM_CLASS_FLAG: check the attr-formclass combination ***"
BLOCK = re.compile(
    re.escape(DIAGNOSTIC) + r"\n\nCU Name = [^\n]+\nCU Producer = GNU [^\n]+\n"
    r"DIE OFF = 0x([0-9a-f]+) GOFF = 0x([0-9a-f]+), Low PC = 0x[0-9a-f]+, High PC = 0x[0-9a-f]+\n"
    r"DW_AT_GNU_vector\s+yes\(1\)"
)


def account(text, offsets, frames):
    records = BLOCK.findall(text)
    assert len(records) == text.count(DIAGNOSTIC) == len(offsets) == 2
    assert all(local == global_offset for local, global_offset in records)
    assert sorted(int(global_offset, 16) for _, global_offset in records) == sorted(offsets)
    normalized = text.replace(DIAGNOSTIC, "")

    def errors(match):
        value = int(match[2])
        assert value >= 2
        return match[1] + str(value - 2) + match[3]

    normalized, count = re.subn(r"(?m)^(\s*\d+: errors\s*=\s*)(\d+)(, GNU .+)$", errors, normalized)
    assert count == 1

    def row(match):
        assert int(match[2]) == 2
        return match[1] + "0"

    normalized, count = re.subn(r"(?m)^(attr_formclass\s+\d+\s+)(\d+)\s*$", row, normalized)
    assert count == 2
    normalized, count = re.subn(
        r"(?m)^(\*\* Summarize \*\*\s+\d+\s+)(\d+)(\s*)$", errors, normalized
    )
    assert count == 2
    strict.validate_output(normalized, frames)
    return normalized


def main(case):
    reference, original = case / "abi.reference", case / "abi.input"
    log = case / "compiler-strict.log"
    with (case / "compiler-strict-driver.log").open("w") as out, (
        case / "compiler-strict-driver.stderr"
    ).open("w") as err:
        status = subprocess.run(
            [sys.executable, source / "check-dwarfdump.py", reference, log, "--original", original],
            stdout=out,
            stderr=err,
            check=False,
        ).returncode
    if status == 0:
        receipt = {"status": "PASS", "explainedGnuVectorDiagnostics": 0}
    else:
        assert status == 1
        metadata = json.loads(log.with_name(log.name + ".check.json").read_text())
        assert (
            metadata["status"] == "FAILED"
            and metadata["failure"] == "checker reported a diagnostic"
        )
        assert metadata["exit_status"] == 0 and not Path(metadata["stderr_log"]).read_bytes()
        text = log.read_text()
        frames = strict.frame_diagnostics(text)
        if frames:
            assert metadata["inherited_frame_evidence"]["diagnostics"] == frames
            assert metadata["original_check"]["exit_status"] == 0
        result = subprocess.run(
            ["readelf", "--wide", "--debug-dump=info", reference],
            capture_output=True,
            text=True,
            check=True,
        )
        assert not result.stderr
        records = dies.parse_dies(result.stdout)
        nodes = {item["offset"]: item for item in records}
        vectors = [item for item in records if "DW_AT_GNU_vector" in item["attributes"]]
        assert len(vectors) == 2
        encodings = set()
        for item in vectors:
            attrs = item["attributes"]
            assert (
                item["tag"] == "DW_TAG_array_type"
                and attrs["DW_AT_GNU_vector"] == "(flag_present) 1"
            )
            element = nodes[int(re.search(r"<0x([0-9a-f]+)>", attrs["DW_AT_type"])[1], 16)]
            assert (
                element["tag"] == "DW_TAG_base_type"
                and dies.number(element["attributes"]["DW_AT_byte_size"]) == 4
            )
            encodings.add(dies.number(element["attributes"]["DW_AT_encoding"]))
            children = []
            for child in records[records.index(item) + 1 :]:
                if child["depth"] <= item["depth"]:
                    break
                if child["tag"] == "DW_TAG_subrange_type":
                    children.append(child)
            (child,) = children
            assert dies.number(child["attributes"]["DW_AT_upper_bound"]) == 3
        assert encodings == {4, 5}
        offsets = [item["offset"] for item in vectors]
        normalized = account(text, offsets, frames)
        # These mutations prove the explanation cannot hide other attributes,
        # mismatched DIEs, extra diagnostics or incomplete checker output.
        mutants = [
            text + "\nwarning: unrelated problem\n",
            text.replace("DW_FORM_CLASS_FLAG:", "DW_FORM_CLASS_CONSTANT:"),
            text.replace("attr_formclass", "unexpected_category"),
            text[: text.index("*** TOTAL ERRORS FOR ALL COMPILERS ***")],
        ]
        rejected = 0
        for altered, expected in [(value, offsets) for value in mutants] + [
            (text, [offsets[0], offsets[1] + 1])
        ]:
            try:
                account(altered, expected, frames)
            except (AssertionError, strict.ValidationFailure):
                rejected += 1
            else:
                raise AssertionError("reference diagnostic mutation was accepted")
        assert rejected == 5
        (case / "compiler-strict-accounted.txt").write_text(normalized)
        receipt = {
            "status": "EXPLAINED_COMPILER_EXTENSION",
            "explainedGnuVectorDiagnostics": 2,
            "vectorDieOffsets": offsets,
            "mutationControls": rejected,
            "inheritedFrameDiagnostics": len(frames),
            "rawStrictReport": str(log),
            "rawStrictStatus": metadata["status"],
            "explanation": "libdwarf 2.3.2 src/bin/attr_form/attr_formclass_ext.list gives DW_AT_GNU_vector no allowed form class",
        }
    (case / "compiler-reference-review.json").write_text(json.dumps(receipt, indent=4) + "\n")
    print(
        "aarch64-vector-reference=PASS explained=" + str(receipt["explainedGnuVectorDiagnostics"])
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
