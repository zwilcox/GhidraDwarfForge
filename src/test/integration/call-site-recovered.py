#!/usr/bin/env python3
"""Strict runtime oracle for recovered call-site plans; known gaps remain failures."""
import argparse
import json
import runpy
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parent
reference = runpy.run_path(str(SCRIPTS / "call-site-reference.py"))
capture = runpy.run_path(str(SCRIPTS / "call-site-evidence.py"))


def check(observed, scenario):
    expected = ("cs_checkpoint", "cs_leaf", *reference["EXPECTED_FRAMES"][scenario], "cs_driver", "main")
    frames = observed["frames"]
    assert tuple(f["name"] for f in frames) == expected, "frame structure differs from compiler reference"
    assert observed["sink"] == reference["EXPECTED_SINK"][scenario] and observed["exitCode"] == 0
    for index, frame in enumerate(frames):
        tail = 2 <= index < len(frames) - 2 and (scenario in (1, 5, 7) or scenario == 4 and index == 2)
        assert frame["tail"] == tail and ("tail call frame" in frame["info"]) == tail
    entries = reference["EXPECTED_ENTRY"][scenario]
    if scenario == 4:
        # Compiler GDB output cannot match the leaf parameter in this case.
        # Forge has an independently checked forwarded-register binding, so
        # require the source/runtime value rather than copying that limitation.
        entries = (43, 43, 42, 41, 40)
    for frame, expected_entry in zip(frames[1:-2], entries, strict=True):
        value = frame["entryValue"]
        assert value["available"] == (expected_entry is not None), (frame["name"], expected_entry, value)
        if expected_entry is not None:
            assert value["value"] == expected_entry, (frame["name"], expected_entry, value)
        if frame["value"]["available"]:
            actual_parameter = reference["EXPECTED_SINK"][scenario] if frame["name"] == "cs_leaf" else expected_entry
            assert frame["value"]["value"] == actual_parameter, "available current parameter is incorrect"
    if scenario in (4, 5):
        depths = [f["entryDepth"] for f in frames if "entryDepth" in f]
        assert all(d["available"] for d in depths)
        assert tuple(d["value"] for d in depths) == ((0, 1, 2, 3) if scenario == 4 else (3,))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path)
    parser.add_argument("capture", type=Path, help="existing saved-project capture root")
    parser.add_argument("--report-name", default="forge-plan")
    args = parser.parse_args()
    assert args.report_name in ("forge-plan", "entry-locations", "switch-plan", "switch-regression")
    compiler = json.loads((args.reference / "result.json").read_text())
    work = args.capture.resolve() / args.report_name
    model = json.loads((work / "result.json").read_text())
    assert model["status"] == "PASS_RECOVERED_PLAN_STRUCTURAL"
    binary = (args.reference / "input").resolve()
    digest = reference["digest"]
    assert digest(binary) == model["inputSha256"]
    assert capture["program_hashes"](args.capture / "project") == model["savedProgramSha256"]
    rows, failures = [], []
    for view in model["reports"]:
        variant = view["variant"]
        sidecar = work / (variant + ".json.dbg")
        assert digest(sidecar) == view["artifact"]["sidecarSha256"]
        assert digest(Path(str(sidecar) + ".c")) == view["artifact"]["sourceSha256"]
        for scenario in range(8):
            output = work / f"{variant}-runtime-{scenario}"
            observed = reference["debugger"](compiler["target"], binary, scenario, output, sidecar)
            issue = None
            try:
                check(observed, scenario)
            except AssertionError as error:
                issue = str(error)
                failures.append({"variant": variant, "scenario": scenario, "reason": issue})
            rows.append({"variant": variant, "scenario": scenario, "status": "FAIL" if issue else "PASS",
                         "resultSha256": digest(output.with_suffix(".json")), "observation": observed})
        assert digest(sidecar) == view["artifact"]["sidecarSha256"]
    assert digest(binary) == model["inputSha256"]
    assert capture["program_hashes"](args.capture / "project") == model["savedProgramSha256"]
    report = {"status": "FAIL_RECOVERED_RUNTIME" if failures else "PASS_RECOVERED_RUNTIME",
              "target": compiler["target"], "role": compiler["role"], "failures": failures, "sessions": rows}
    (work / "runtime-result.json").write_text(json.dumps(report, indent=4) + "\n")
    print(f"recovered-runtime={report['status']} target={compiler['target']} role={compiler['role']} sessions={len(rows)} failures={len(failures)}")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
