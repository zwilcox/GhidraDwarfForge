#!/usr/bin/env python3
"""Linux headless rejection of real same-width, same-endian forced imports.

Requires an installed production extension and the source-built reference ELF
from the selected CI target lane. Native paths deliberately do not exist: the
target disagreement must be diagnosed before any native production attempt.
Normal five-profile exporter/validator/GDB coverage remains in the shared matrix.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


PROFILES = {
    "x86_64": (62, 64, "x86", "AARCH64", "AARCH64:LE:64:v8A"),
    "mips32le": (8, 32, "MIPS", "ARM", "ARM:LE:32:v8"),
}


def identity(path):
    status = path.stat()
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mtime_ns": status.st_mtime_ns, "size": status.st_size}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ghidra", type=Path)
    parser.add_argument("target", choices=PROFILES)
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parents[3]
    launcher = arguments.ghidra.resolve() / "support/analyzeHeadless"
    fixture = repository / "build/fixtures" / arguments.target / "semantic.exec.reference"
    require(launcher.is_file() and fixture.is_file(), "Ghidra or source-built fixture missing")
    root = repository / "build/test-results/target-language-agreement"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run.", dir=root))
    print("target-language-agreement-results=" + str(work), flush=True)
    machine, bits, expected, actual, language = PROFILES[arguments.target]
    fixture_before = identity(fixture)
    for prior_pair in (False, True):
        case = work / ("existing-pair" if prior_pair else "absent-pair")
        output_directory = case / "output with spaces"
        output_directory.mkdir(parents=True)
        source = case / "original.elf"
        shutil.copy2(fixture, source)
        output = output_directory / "original.dbg"
        companion = output_directory / "original.dbg.c"
        if prior_pair:
            output.write_bytes(b"previous complete sidecar\n")
            companion.write_bytes(b"previous complete synthetic source\n")
        originals = {str(path): identity(path) for path in (source, output, companion)
                     if path.exists()}
        expected_files = sorted(path.name for path in output_directory.iterdir())
        missing_consumer = case / "native-must-not-load/libdwarf.so"
        missing_producer = case / "native-must-not-load/libdwarfp.so"
        command = [str(launcher), str(case), "WrongTarget", "-deleteProject",
                   "-import", str(source), "-loader", "ElfLoader", "-processor", language,
                   "-cspec", "default", "-noanalysis", "-postScript", "GhidraDwarfForge.java",
                   "--libdwarf=" + str(missing_consumer),
                   "--libdwarfp=" + str(missing_producer), "--output=" + str(output)]
        (case / "command.json").write_text(json.dumps(command, indent=2) + "\n")
        with (case / "headless.txt").open("w") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180)
        text = (case / "headless.txt").read_text()
        # Pinned Ghidra reports a post-script exception in the log, while the
        # completed analyzer process exits zero. A crashed analyzer is not proof.
        require(result.returncode == 0, "headless process failed or crashed")
        for crash in ["SIGSEGV", "EXCEPTION_ACCESS_VIOLATION", "OutOfMemoryError",
                      "A fatal error has been detected by the Java Runtime Environment"]:
            require(crash not in text, "headless process reported " + crash)
        reports = []
        for line in text.splitlines():
            if "GhidraDwarfForge report: " in line:
                reports.append(json.JSONDecoder().raw_decode(line[line.index("{"):])[0])
        require(len(reports) == 1, "expected one structured exporter report")
        report = reports[0]
        require(report["status"] == "FATAL", "wrong processor was not rejected")
        diagnostic = report["failure"]["message"]
        for fragment in ["ELF/Ghidra target mismatch", "machine=" + str(machine),
                         "class=ELF" + str(bits), "expected-processor=" + expected,
                         "Ghidra processor=" + actual, "pointer-bits=" + str(bits),
                         "byte-order=little", "language=" + language, "compiler=default",
                         "before extraction and native production"]:
            require(fragment in diagnostic, "missing identity: " + fragment)
        require(report["native"]["libdwarfVersion"] is None, "native production was reached")
        require("GhidraDwarfForge symbol export PASS" not in text, "unexpected successful export")
        require(not missing_consumer.exists() and not missing_producer.exists(),
                "native-negative control unexpectedly exists")
        require(originals == {name: identity(Path(name)) for name in originals},
                "original or previous pair was changed")
        require(expected_files == sorted(path.name for path in output_directory.iterdir()),
                "failed export left output/staging files")
        require(fixture_before == identity(fixture), "supplied fixture was changed")
        (case / "result.json").write_text(json.dumps({
            "status": "PASS", "headless_exit": result.returncode, "report": report,
            "unchanged": originals, "output_files": expected_files,
        }, indent=2) + "\n")
        print(case.name + "=PASS", flush=True)
    (work / "result.txt").write_text("target-language-agreement=PASS\n")
    print("target-language-agreement=PASS")


if __name__ == "__main__":
    main()
