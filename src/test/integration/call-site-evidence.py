#!/usr/bin/env python3
"""Compare current Ghidra transfer capture with compiler reference instruction PCs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[3]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, prefix, env):
    command = list(map(str, command))
    prefix.with_suffix(".command.json").write_text(json.dumps(command) + "\n")
    with prefix.with_suffix(".log").open("wb") as log:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    text = prefix.with_suffix(".log").read_text()
    assert result.returncode == 0 and "ERROR " not in text and "Traceback" not in text, prefix
    return text


def compare(reference, captured):
    functions = {row["name"]: row for row in captured["functions"]}
    assert len(functions) == len(captured["functions"]), "ambiguous fixture names"
    rows = []
    for call in reference["calls"]:
        function = functions[call["caller"]]
        instruction, = [row for row in function["instructions"] if int(row["elfAddress"], 16) == int(call["pc"], 16)]
        expected_kind = "THUNK_TRANSFER" if call["caller"] in ("cs_forward", "cs_indirect") else (
            "DIRECT_TAIL_CANDIDATE" if call["tail"] else "DIRECT_CALL")
        assert instruction["kind"] == expected_kind, (call, instruction)
        assert instruction["callee"] == call["callee"], (call, instruction)
        assert instruction["original"] is not None and instruction["original"]["address"] == int(call["pc"], 16)
        if call["tail"]:
            assert instruction["returnPc"] is None, "tail candidate fabricated an ordinary return PC"
        else:
            assert int(instruction["returnPc"], 16) == int(call["returnPc"], 16)
        if call["callee"] is None:
            assert instruction["target"] is None, "indirect transfer inherited an analyst/thunk target"
        else:
            assert int(instruction["target"], 16) == int(functions[call["callee"]]["entry"], 16) - captured["rebaseDelta"]
        rows.append({"caller": call["caller"], "pc": call["pc"], "kind": instruction["kind"],
                     "callee": instruction["callee"], "originalSha256": instruction["original"]["sha256"]})
    return rows


def compare_tails(reference, captured):
    expected = {(call["caller"], call["callee"], int(call["pc"], 16))
                for call in reference["calls"] if call["tail"] and call["callee"] is not None}
    actual = {(tail["caller"], tail["callee"], int(tail["pc"], 16)) for tail in captured["tails"]}
    assert len(actual) == len(captured["tails"]) and actual == expected, (expected, actual)
    instructions = {int(row["elfAddress"], 16): row for function in captured["functions"]
                    for row in function["instructions"]}
    for tail in captured["tails"]:
        assert tail["originalSha256"] == instructions[int(tail["pc"], 16)]["original"]["sha256"]
    omissions = captured["tailOmissions"]
    assert "external branch lacks a decoded exact callee entry" in omissions["cs_indirect"]
    if reference["target"] == "x86_64":
        assert "incomplete instruction inventory" in omissions["cs_driver"]
        assert "unproved incoming non-call transfer" in omissions["cs_driver.cold"]
    return captured["tails"]


def program_hashes(project):
    data = project / "Calls.rep/idata"
    result = {str(path.relative_to(data)): digest(path) for path in sorted(data.rglob("*")) if path.is_file()}
    assert result, "missing saved program database"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path, help="completed call-site-reference.py output")
    parser.add_argument("output", type=Path)
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--reuse-project", action="store_true", help="read an existing capture project; write fresh tail-state reports")
    args = parser.parse_args()
    reference = args.reference.resolve()
    compiler = json.loads((reference / "result.json").read_text())
    assert compiler["status"] == "PASS_COMPILER_REFERENCE"
    original = reference / "input"
    protected = digest(original)
    work = args.output.resolve()
    if not args.reuse_project:
        work.mkdir(parents=True, exist_ok=False)
    scripts = work / "scripts"
    observer = ROOT / "src/test/integration/ghidra_scripts/ObserveCallSiteEvidence.java"
    project = work / "project"
    if not args.reuse_project:
        scripts.mkdir()
        shutil.copyfile(observer, scripts / observer.name)
        project.mkdir()
    # Reuse only accounted tool/cache paths locally. CI can use its job temp.
    cache = Path(os.environ.get("FORGE_CACHE_DIR", work / "cache")) / "ghidra-user"
    cache.mkdir(parents=True, exist_ok=True)
    temporary = os.environ.get("TMPDIR", str(work / "temporary"))
    Path(temporary).mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GHIDRA_INSTALL_DIR": str(args.ghidra.resolve()),
           "JAVA_TOOL_OPTIONS": f"-Duser.home={cache} -Djava.io.tmpdir={temporary}"}
    if not args.reuse_project:
        text = run([args.ghidra.resolve() / "support/analyzeHeadless", project, "Calls", "-import", original,
                    "-scriptPath", scripts, "-postScript", observer.name, work / "observations.json",
                    "-max-cpu", "2", "-log", work / "headless.log", "-scriptlog", work / "script.log"], work / "import", env)
        assert "call-site-observations=PASS functions=" in text
    saved = program_hashes(project)
    reports_root = work / "tail-state" if args.reuse_project else work
    if args.reuse_project:
        reports_root.mkdir(exist_ok=False)
    # Read-only reopen through the current source runtime; do not overwrite a
    # user's installed extension or build another Ghidra installation.
    reports = []
    for variant, shift in (("original", 0), ("rebased", 0x400000)):
        output = reports_root / (variant + ".json")
        text = run([ROOT / "gradlew", "--no-daemon", "callSiteEvidenceProbe",
                    "-PcallSiteProject=" + str(project), "-PcallSiteInput=" + str(original),
                    "-PcallSiteReport=" + str(output), "-PcallSiteRebase=" + str(shift)], reports_root / (variant + "-capture"), env)
        assert "call-site-evidence-probe=PASS" in text
        captured = json.loads(output.read_text())
        assert "/build/classes/java/main/" in captured["classOrigin"], captured["classOrigin"]
        reports.append({"variant": variant, "delta": captured["rebaseDelta"], "calls": compare(compiler, captured),
                        "tails": compare_tails(compiler, captured), "tailOmissions": captured["tailOmissions"],
                        "omissions": {f["name"]: f["omissions"] for f in captured["functions"] if f["omissions"]}})
    assert reports[0]["calls"] == reports[1]["calls"], "rebase changed transfer identities or original bytes"
    assert reports[0]["tails"] == reports[1]["tails"], "rebase changed proved tail identities or original bytes"
    assert reports[1]["delta"] - reports[0]["delta"] == 0x400000
    assert digest(original) == protected, "capture changed the original executable"
    assert program_hashes(project) == saved, "capture changed the saved program database"
    (reports_root / "result.json").write_text(json.dumps({
        "status": "PASS_CAPTURE_TAIL_STATE_REFERENCE", "target": compiler["target"], "role": compiler["role"],
        "scope": "Raw transfers and direct tail boundary states; actual arguments and DWARF emission remain incomplete",
        "inputSha256": protected, "savedProgramSha256": saved, "reports": reports,
    }, indent=4) + "\n")
    print(f"call-site-evidence-reference=PASS target={compiler['target']} role={compiler['role']}")


if __name__ == "__main__":
    main()
