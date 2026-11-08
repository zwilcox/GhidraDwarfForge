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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path, help="completed call-site-reference.py output")
    parser.add_argument("output", type=Path)
    parser.add_argument("--ghidra", required=True, type=Path)
    args = parser.parse_args()
    reference = args.reference.resolve()
    compiler = json.loads((reference / "result.json").read_text())
    assert compiler["status"] == "PASS_COMPILER_REFERENCE"
    original = reference / "input"
    protected = digest(original)
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    scripts = work / "scripts"
    scripts.mkdir()
    observer = ROOT / "src/test/integration/ghidra_scripts/ObserveCallSiteEvidence.java"
    shutil.copyfile(observer, scripts / observer.name)
    project = work / "project"
    project.mkdir()
    # Reuse only accounted tool/cache paths locally. CI can use its job temp.
    cache = Path(os.environ.get("FORGE_CACHE_DIR", work / "cache")) / "ghidra-user"
    cache.mkdir(parents=True, exist_ok=True)
    temporary = os.environ.get("TMPDIR", str(work / "temporary"))
    Path(temporary).mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GHIDRA_INSTALL_DIR": str(args.ghidra.resolve()),
           "JAVA_TOOL_OPTIONS": f"-Duser.home={cache} -Djava.io.tmpdir={temporary}"}
    text = run([args.ghidra.resolve() / "support/analyzeHeadless", project, "Calls", "-import", original,
                "-scriptPath", scripts, "-postScript", observer.name, work / "observations.json",
                "-max-cpu", "2", "-log", work / "headless.log", "-scriptlog", work / "script.log"], work / "import", env)
    assert "call-site-observations=PASS functions=" in text
    # Read-only reopen through the current source runtime; do not overwrite a
    # user's installed extension or build another Ghidra installation.
    reports = []
    for variant, shift in (("original", 0), ("rebased", 0x400000)):
        output = work / (variant + ".json")
        text = run([ROOT / "gradlew", "--no-daemon", "callSiteEvidenceProbe",
                    "-PcallSiteProject=" + str(project), "-PcallSiteInput=" + str(original),
                    "-PcallSiteReport=" + str(output), "-PcallSiteRebase=" + str(shift)], work / (variant + "-capture"), env)
        assert "call-site-evidence-probe=PASS" in text
        captured = json.loads(output.read_text())
        assert "/build/classes/java/main/" in captured["classOrigin"], captured["classOrigin"]
        reports.append({"variant": variant, "delta": captured["rebaseDelta"], "calls": compare(compiler, captured),
                        "omissions": {f["name"]: f["omissions"] for f in captured["functions"] if f["omissions"]}})
    assert reports[0]["calls"] == reports[1]["calls"], "rebase changed transfer identities or original bytes"
    assert reports[1]["delta"] - reports[0]["delta"] == 0x400000
    assert digest(original) == protected, "capture changed the original executable"
    (work / "result.json").write_text(json.dumps({
        "status": "PASS_CAPTURE_REFERENCE", "target": compiler["target"], "role": compiler["role"],
        "scope": "Raw transfers and branch candidates only; tail-state proofs and DWARF emission remain incomplete",
        "inputSha256": protected, "reports": reports,
    }, indent=4) + "\n")
    print(f"call-site-evidence-reference=PASS target={compiler['target']} role={compiler['role']}")


if __name__ == "__main__":
    main()
