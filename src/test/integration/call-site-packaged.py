#!/usr/bin/env python3
"""Validate call-site behavior through the installed production script and native package."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import runpy
import shlex
import subprocess
import zipfile


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parents[2]
reference = runpy.run_path(str(SCRIPTS / "call-site-reference.py"))
capture = runpy.run_path(str(SCRIPTS / "call-site-evidence.py"))
recovered = runpy.run_path(str(SCRIPTS / "call-site-recovered.py"))
digest = reference["digest"]


def installed_package(archive_path, module):
    """Require the installed files to match the supplied release ZIP byte-for-byte."""
    expected = {}
    total = 0
    with zipfile.ZipFile(archive_path) as archive:
        for item in archive.infolist():
            path = PurePosixPath(item.filename)
            assert path.parts and path.parts[0] == "GhidraDwarfForge" and ".." not in path.parts
            if item.is_dir():
                continue
            assert len(path.parts) > 1 and item.file_size <= 64 * 1024 * 1024
            total += item.file_size
            assert total <= 256 * 1024 * 1024, "package inventory exceeds test budget"
            relative = str(PurePosixPath(*path.parts[1:]))
            assert relative not in expected, "duplicate ZIP member"
            destination = (module / relative).resolve(strict=True)
            assert destination.is_relative_to(module)
            expected[relative] = hashlib.sha256(archive.read(item)).hexdigest()
            assert digest(destination) == expected[relative], "installed package differs: " + relative
    assert "lib/GhidraDwarfForge.jar" in expected and "ghidra_scripts/GhidraDwarfForge.java" in expected
    assert expected["ghidra_scripts/GhidraDwarfForge.java"] == digest(ROOT / "ghidra_scripts/GhidraDwarfForge.java")
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path, help="completed compiler reference directory")
    parser.add_argument("capture", type=Path, help="existing saved Calls project; never modified")
    parser.add_argument("output", type=Path, help="new packaged validation directory")
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--package", required=True, type=Path, help="release ZIP already installed in this Ghidra")
    parser.add_argument("--probe-report", required=True, help="independent recovered-plan report directory name")
    parser.add_argument("--dwarfdump", required=True, type=Path)
    args = parser.parse_args()
    assert args.probe_report in ("forge-plan", "switch-plan", "origin-alias")
    ghidra = args.ghidra.resolve(strict=True)
    module = (ghidra / "Ghidra/Extensions/GhidraDwarfForge").resolve(strict=True)
    archive = args.package.resolve(strict=True)
    expected = installed_package(archive, module)
    package_hash = digest(archive)
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    project = (args.capture / "project").resolve(strict=True)
    binary = (args.reference / "input").resolve(strict=True)
    compiler = json.loads((args.reference / "result.json").read_text())
    assert compiler["status"] == "PASS_COMPILER_REFERENCE"
    saved = capture["program_hashes"](project)
    (work / "saved-program-before.json").write_text(json.dumps(saved, indent=4) + "\n")
    protected = digest(binary)
    home = Path(os.environ.get("FORGE_CACHE_DIR", work / "cache")) / "ghidra-packaged-user"
    home.mkdir(parents=True, exist_ok=True)
    temporary = Path(os.environ.get("TMPDIR", work / "temporary"))
    temporary.mkdir(parents=True, exist_ok=True)
    java_options = shlex.join(["-Duser.home=" + str(home), "-Djava.io.tmpdir=" + str(temporary),
                              "-Djna.tmpdir=" + str(temporary)])
    env = {**os.environ, "JAVA_TOOL_OPTIONS": java_options}

    def run(label, command, *, headless=False):
        command = list(map(str, command))
        (work / (label + ".command.json")).write_text(json.dumps(command, indent=4) + "\n")
        with (work / (label + ".stdout")).open("wb") as out, (work / (label + ".stderr")).open("wb") as err:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                                    timeout=600 if headless else 120)
        stdout = (work / (label + ".stdout")).read_text()
        stderr = (work / (label + ".stderr")).read_text()
        # Headless can report script errors yet return zero. Keep those errors
        # fatal and expose a bounded transcript in CI instead of only a label.
        diagnostic = (f"{label}: exit={result.returncode}\n"
                      f"stdout (last 12000 characters):\n{stdout[-12000:]}\n"
                      f"stderr (last 8000 characters):\n{stderr[-8000:]}")
        assert result.returncode == 0, diagnostic
        assert "Traceback" not in stdout + stderr and "ERROR " not in stdout + stderr, diagnostic
        if not headless:
            assert not stderr, diagnostic
        return stdout + stderr

    reports, sessions, failures = [], [], []
    for variant, shift in (("original", 0), ("rebased", 0x400000)):
        output = work / variant
        # Headless local -process opens a writable project container even with
        # -readOnly. Run the script once without an import in a small host
        # project; the script opens the analyzed fixture as a read-only view.
        host = work / (variant + "-host")
        host.mkdir()
        try:
            transcript = run(variant + "-headless", [ghidra / "support/analyzeHeadless", host, "Harness",
                "-noanalysis", "-max-cpu", "2",
                "-scriptPath", SCRIPTS / "ghidra_scripts", "-postScript", "CheckCallSitePackagedExport.java",
                binary, output, hex(shift), module, project], headless=True)
            assert "packaged-call-site-export=PASS functions=13" in transcript, transcript[-20000:]
            assert transcript.count("GhidraDwarfForge symbol export PASS") == 2, transcript[-20000:]
        finally:
            assert digest(binary) == protected, "packaged exporter changed original input"
            capture["require_program_preserved"](project, saved, work / (variant + "-program-preservation.json"))
        result = json.loads((output / "export.json").read_text())
        assert result["status"] == "PASS_PACKAGED_CALL_SITE_EXPORT"
        assert result["readOnlyProject"] is True
        assert Path(result["classOrigin"]).resolve() == (module / "lib/GhidraDwarfForge.jar").resolve()
        assert result["jarSha256"] == expected["lib/GhidraDwarfForge.jar"]
        assert result["scriptSha256"] == expected["ghidra_scripts/GhidraDwarfForge.java"]
        assert result["consumerSha256"] in expected.values() and result["producerSha256"] in expected.values()
        assert result["inputSha256"] == protected
        assert set(result["analystNamedThunks"]) == {"cs_forward", "cs_indirect"}
        assert result["correctedDriverBody"] == (compiler["target"] == "x86_64")
        probe = json.loads((args.capture / args.probe_report / (variant + ".json")).read_text())
        assert result["rebaseDelta"] == probe["rebaseDelta"]
        projection = lambda rows: {f["name"]: (f["entry"], f["body"]) for f in rows}
        assert projection(result["functions"]) == projection(probe["functions"]), "packaged fixture changed known body ranges"
        for function in result["functions"]:
            if function["name"] != "cs_checkpoint":
                assert function["signatureSource"] == "USER_DEFINED"
            if function["name"] in result["analystNamedThunks"]:
                assert function["nameSource"] == "USER_DEFINED"
        sidecar = output / "input.dbg"
        assert digest(sidecar) == result["sidecarSha256"]
        assert digest(Path(str(sidecar) + ".c")) == result["sourceSha256"]
        run(variant + "-gnu", ["readelf", "-h", "-S", "-n", "--debug-dump=info,abbrev,aranges,decodedline", sidecar])
        run(variant + "-llvm", ["llvm-dwarfdump", "--verify", sidecar])
        run(variant + "-strict", ["python3", "-B", SCRIPTS / "check-dwarfdump.py", sidecar,
            work / (variant + "-strict.txt"), "--tool", args.dwarfdump.resolve(), "--original", binary])
        for scenario in range(8):
            observation = reference["debugger"](compiler["target"], binary, scenario,
                work / f"{variant}-runtime-{scenario}", sidecar)
            issue = None
            try:
                recovered["check"](observation, scenario)
            except AssertionError as error:
                issue = str(error)
                failures.append({"view": variant, "scenario": scenario, "reason": issue})
            sessions.append({"view": variant, "scenario": scenario, "status": "FAIL" if issue else "PASS",
                             "observation": observation})
        reports.append(result)
        assert digest(sidecar) == result["sidecarSha256"] and digest(binary) == protected
    assert reports[1]["rebaseDelta"] - reports[0]["rebaseDelta"] == 0x400000
    assert capture["program_hashes"](project) == saved
    assert digest(archive) == package_hash and installed_package(archive, module) == expected
    report = {"status": "FAIL_PACKAGED_CALL_SITES" if failures else "PASS_PACKAGED_CALL_SITES",
              "target": compiler["target"], "role": compiler["role"], "packageSha256": package_hash,
              "installedInventory": expected, "inputSha256": protected, "savedProgramSha256": saved,
              "exports": reports, "sessions": sessions, "failures": failures}
    (work / "result.json").write_text(json.dumps(report, indent=4) + "\n")
    print(f"packaged-call-sites={report['status']} target={compiler['target']} role={compiler['role']} sessions={len(sessions)} failures={len(failures)}")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
