#!/usr/bin/env python3
"""Compile bounded, explicit mutants outside the checkout and require behavioral failures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


REPO = Path(__file__).resolve().parents[3]
REPAIR = "ghidradwarfforge/dwarf/Dwarf32InfoRepair.java"
RELOCATE = "ghidradwarfforge/dwarf/SyntheticSourceRelocation.java"
PUBLISH = "ghidradwarfforge/output/CompanionArtifactPublisher.java"
REPAIR_TEST = "ghidradwarfforge.dwarf.Dwarf32InfoRepairBoundarySmoke"
RELOCATE_TEST = "ghidradwarfforge.dwarf.SyntheticSourceRelocationBoundarySmoke"
PUBLISH_TEST = "ghidradwarfforge.output.CompanionPublicationFailureSmoke"

# Each edit names a specific safety/semantic guarantee. This is not a blanket
# mutation score: surviving, uncompilable or timed-out mutants fail this harness.
MUTANTS = [
    ("repair-offset-truncation", REPAIR, REPAIR_TEST,
     "if ((buffer.getLong(cursor.offset) & 0xffffffff00000000L) != 0)", "if (false)"),
    ("repair-reference-not-adjusted", REPAIR, REPAIR_TEST,
     "long adjusted = adjust(reference.target(), deletions);", "long adjusted = reference.target();"),
    ("repair-wrong-byte-order", REPAIR, REPAIR_TEST,
     "order == ByteOrder.LITTLE_ENDIAN", "order == ByteOrder.BIG_ENDIAN"),
    ("relocation-wrong-directory-reference", RELOCATE, RELOCATE_TEST,
     "putInt(directoryReference, strings.length)", "putInt(directoryReference, 0)"),
    ("relocation-ignores-cancellation", RELOCATE, RELOCATE_TEST,
     "if (cancelled.getAsBoolean()) throw", "if (cancelled.getAsBoolean() && false) throw"),
    ("relocation-accepts-duplicate-file", RELOCATE, RELOCATE_TEST,
     "require(uniqueFiles.add(file.value()),", "require(uniqueFiles.add(file.value()) || true,"),
    ("publication-loses-primary-cleanup-diagnostic", PUBLISH, PUBLISH_TEST,
     "failure.addSuppressed(cleanupFailure);", "failure.getMessage();"),
    ("publication-loses-previous-generation", PUBLISH, PUBLISH_TEST,
     "move(backups[index], targets.get(index));", "Files.deleteIfExists(backups[index]);"),
    ("publication-ignores-final-cancellation", PUBLISH,
     "ghidradwarfforge.output.CompanionArtifactPublisherSmoke",
     "hook.afterInstall(index);\n            }\n            check.check();",
     "hook.afterInstall(index);\n            }\n            // Mutant drops the final cancellation check."),
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(argv):
    start = time.monotonic()
    result = subprocess.run(list(map(str, argv)), text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=40, check=False)
    if len(result.stdout.encode()) > 32768:
        raise RuntimeError("unexpectedly large mutation diagnostic")
    return result, round(time.monotonic() - start, 3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--classes", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    classes, tests, output = args.classes.resolve(), args.tests.resolve(), args.output.resolve()
    if not classes.is_dir() or not tests.is_dir():
        raise ValueError("compiled production and test directories are required")
    output.mkdir(parents=True, exist_ok=False)
    java, javac = args.java_home.resolve() / "bin/java", args.java_home.resolve() / "bin/javac"
    sources = {name: REPO / "src/main/java" / name for name in (REPAIR, RELOCATE, PUBLISH)}
    original = {name: path.read_text() for name, path in sources.items()}
    hashes = {name: digest(path) for name, path in sources.items()}
    results = []
    peak = 0
    started = time.monotonic()

    def check(label, name, test, source, mutant):
        nonlocal peak
        with tempfile.TemporaryDirectory(prefix="classes-", dir=output) as temporary:
            root = Path(temporary)
            path = root / name
            path.parent.mkdir(parents=True)
            path.write_text(source)
            # The production publisher's private exception is never serialized;
            # its existing missing serialVersionUID is unrelated to these mutants.
            compiled, compile_seconds = execute([javac, "-Xlint:all,-serial", "-Werror", "-cp", classes,
                                                 "-d", root, path])
            if compiled.returncode:
                raise AssertionError(f"{label}: compilation failed, not a detected mutant\n{compiled.stdout}")
            classpath = os.pathsep.join(map(str, (root, classes, tests)))
            run, run_seconds = execute([java, "-Djava.io.tmpdir=" + str(root), "-cp", classpath, test])
            (output / (label + ".log")).write_text(run.stdout)
            if mutant:
                if run.returncode == 0 or "java.lang.AssertionError:" not in run.stdout:
                    raise AssertionError(f"{label}: no behavioral assertion detected mutation\n{run.stdout}")
                if any(word in run.stdout for word in ("ClassNotFoundException", "NoClassDefFoundError", "LinkageError")):
                    raise AssertionError(f"{label}: class-loading failure is not a behavioral detection")
            elif run.returncode != 0 or "=PASS" not in run.stdout:
                raise AssertionError(f"{label}: unchanged-source baseline failed\n{run.stdout}")
            peak = max(peak, sum(p.stat().st_size for p in root.rglob("*") if p.is_file()))
            results.append({"label": label, "source": name, "test": test,
                            "status": "DETECTED" if mutant else "BASELINE_PASS",
                            "exitCode": run.returncode, "compileSeconds": compile_seconds,
                            "testSeconds": run_seconds})

    for index, (name, test) in enumerate(dict.fromkeys((row[1], row[2]) for row in MUTANTS)):
        check(f"baseline-{index}", name, test, original[name], False)
    for label, name, test, before, after in MUTANTS:
        if original[name].count(before) != 1:
            raise AssertionError(f"{label}: mutation anchor is not unique; review source change")
        check(label, name, test, original[name].replace(before, after), True)
    if hashes != {name: digest(path) for name, path in sources.items()}:
        raise AssertionError("mutation run changed checkout sources")
    report = {"status": "PASS", "mutantsDetected": len(MUTANTS), "sourceSha256": hashes,
              "elapsedSeconds": round(time.monotonic() - started, 3),
              "peakDisposableClassBytes": peak, "results": results,
              "scope": "Nine selected faults; not a repository-wide mutation score"}
    (output / "result.json").write_text(json.dumps(report, indent=4) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "mutantsDetected", "elapsedSeconds", "peakDisposableClassBytes")}))


if __name__ == "__main__":
    main()
