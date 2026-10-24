#!/usr/bin/env python3
"""Measure separate import and repeated export processes; retain all evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import statistics
import subprocess
import tempfile
import time


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def run(command, output, timeout=1800, measured=False, cwd=None):
    command = [str(item) for item in command]
    output.with_suffix(".command.json").write_text(json.dumps(command, indent=4) + "\n")
    metrics_path = output.with_suffix(".metrics.json")
    if measured:
        command = ["/usr/bin/time", "-o", str(metrics_path), "-f",
                   '{"elapsedSeconds":%e,"userSeconds":%U,"systemSeconds":%S,'
                   '"maximumResidentKiB":%M}', *command]
    with output.open("w") as stdout, output.with_suffix(".stderr").open("w") as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                   start_new_session=True, cwd=cwd,
                                   env={**os.environ, "LC_ALL": "C"})
        try:
            status = process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            # Stop the measured wrapper/JVM/debugger family, not just GNU time.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            # The leader can exit before children that ignore SIGTERM.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        if status != 0:
            raise subprocess.CalledProcessError(status, command)
    return json.loads(metrics_path.read_text()) if measured else None


def require_clean(output):
    stderr = output.with_suffix(".stderr").read_text()
    if stderr.strip() or re.search(r"(?im)\b(?:warning|error):", output.read_text()):
        raise RuntimeError(f"Unexpected validator/debugger diagnostic: {output}")


def make_fixture(directory, count):
    source = directory / "benchmark.c"
    lines = ["/* Deterministic synthetic scaling fixture, not representative firmware. */",
             "volatile unsigned int benchmark_sink = 0;",
             "typedef unsigned int (*operation)(unsigned int);"]
    for index in range(count):
        lines.extend([
            f"__attribute__((noinline)) unsigned int bench_{index}(unsigned int value) {{",
            f"    unsigned int adjusted = value + {index + 1}U;",
            "    benchmark_sink += adjusted;",
            "    return adjusted;",
            "}",
        ])
    lines.append("operation operations[] = {")
    lines.extend(f"    bench_{index}," for index in range(count))
    lines.extend(["};", "int main(void) {",
                  f"    for (unsigned int i = 0; i < {count}U; ++i) {{",
                  "        operations[i](i);", "    }", "    return 0;", "}"])
    source.write_text("\n".join(lines) + "\n")
    binary = directory / "benchmark"
    run(["gcc", "-O1", "-g0", "-fno-pie", "-no-pie", "-fno-omit-frame-pointer",
         "-Wl,--build-id=sha1", source, "-o", binary], directory / "compile.log")
    return binary


def validate(binary, sidecar, directory, count):
    directory.mkdir()
    for name, command in [
            ("elf-header", ["readelf", "-h", sidecar]),
            ("elf-sections", ["readelf", "-SW", sidecar]),
            ("elf-notes", ["readelf", "-n", sidecar]),
            ("llvm", ["llvm-dwarfdump", "--verify", sidecar]),
            ("libdwarf", ["dwarfdump", "-ka", "-ks", sidecar]),
            *[(f"dwarf-{kind}", ["readelf", f"--debug-dump={kind}", sidecar])
              for kind in ("info", "abbrev", "aranges", "decodedline", "Ranges", "loc")]]:
        output = directory / f"{name}.log"
        run(command, output)
        require_clean(output)
    script = directory / "behavior.gdb"
    run(["nm", "-n", binary], directory / "original-symbols.log")
    addresses = {}
    for line in (directory / "original-symbols.log").read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and re.fullmatch(r"bench_[0-9]+", fields[2]):
            addresses[fields[2]] = int(fields[0], 16)
    if set(addresses) != {f"bench_{index}" for index in range(count)}:
        raise RuntimeError("Compiler fixture lost a required function")
    script.write_text("\n".join([
        "set pagination off", "set confirm off", "set debuginfod enabled off",
        "set auto-solib-add off", "set disable-randomization off",
        "set startup-with-shell off", f"file {json.dumps(str(binary))}",
        f"symbol-file {json.dumps(str(sidecar))}", "python",
        f"expected_addresses = {addresses!r}",
        "for name, address in expected_addresses.items():",
        "    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)",
        "    assert symbol is not None and symbol.is_function, name",
        "    assert symbol.type.code == gdb.TYPE_CODE_FUNC, name",
        "    assert symbol.symtab is not None and symbol.symtab.filename.endswith('.dbg.c'), name",
        "    assert int(gdb.parse_and_eval('&' + name)) == address, name",
        "end", "ptype bench_0", "list bench_0",
        "break *bench_0", "run",
        "python assert gdb.selected_frame().name() == 'bench_0'",
        "python assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&bench_0'))",
        "python assert int(gdb.parse_and_eval('*(unsigned int*)&benchmark_sink')) == 0",
        "python assert gdb.selected_frame().find_sal().symtab.filename.endswith('.dbg.c')",
        "next", "list", "disable breakpoints", "continue",
        "python assert int(gdb.parse_and_eval('$_exitcode')) == 0",
        "echo benchmark-gdb=PASS\\n", "",
    ]))
    output = directory / "gdb.log"
    run(["gdb-multiarch", "-q", "-nx", "-batch", "-x", script], output, cwd=directory)
    require_clean(output)
    if "benchmark-gdb=PASS" not in output.read_text():
        raise RuntimeError("GDB behavior marker missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ghidra", type=Path, help="Ghidra with a native-inclusive Forge installation")
    parser.add_argument("--counts", type=int, nargs="+", default=[100, 1000])
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("this initial benchmark requires Linux x86-64")
    if args.repeats < 2 or any(count < 1 or count > 10000 for count in args.counts):
        parser.error("use at least two repeats and counts between 1 and 10000")
    for tool in ("gcc", "nm", "readelf", "llvm-dwarfdump", "dwarfdump", "gdb-multiarch"):
        if not shutil.which(tool):
            parser.error(f"required tool unavailable: {tool}")
    if not Path("/usr/bin/time").is_file():
        parser.error("GNU /usr/bin/time is required")
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / "Ghidra/Extensions/GhidraDwarfForge"
    wrapper = module / "support/ghidra-dwarf-forge-headless"
    if not wrapper.is_file():
        parser.error(f"installed wrapper not found: {wrapper}")
    repository = Path(__file__).resolve().parents[3]
    result_root = repository / "build/test-results/export-benchmark"
    result_root.mkdir(parents=True, exist_ok=True)
    results = Path(tempfile.mkdtemp(prefix="run.", dir=result_root))
    print(f"benchmark results: {results}", flush=True)
    metadata = {
        "startedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": platform.platform(), "cpuCount": os.cpu_count(),
        "loadAverageAtStart": os.getloadavg(), "ghidra": str(ghidra),
        "counts": args.counts, "repeats": args.repeats,
        "installedFiles": {str(path.relative_to(module)): digest(path)
                           for path in sorted(module.rglob("*"))
                           if path.is_file() and ("os" in path.relative_to(module).parts or
                                                 path.suffix in (".jar", ".java", ".properties"))},
        "measurementBoundary": "whole new process per sample, including JVM startup; "
                               "maximum RSS is GNU time's process-family high water, not total concurrent RSS",
    }
    (results / "environment.json").write_text(json.dumps(metadata, indent=4) + "\n")
    for tool in ("gcc", "readelf", "llvm-dwarfdump", "dwarfdump", "gdb-multiarch", "java"):
        run([tool, "--version"], results / f"version-{tool}.log")
    summaries = []
    for case, count in enumerate(args.counts):
        directory = results / f"case-{case}-{count}-functions"
        directory.mkdir()
        binary = make_fixture(directory, count)
        original_hash = digest(binary)
        project = directory / "project"
        project.mkdir()
        imported = run([ghidra / "support/analyzeHeadless", project, "Benchmark",
                        "-import", binary, "-loader", "ElfLoader",
                        "-analysisTimeoutPerFile", "1200"], directory / "import.log", measured=True)
        if "REPORT: Analysis succeeded" not in (directory / "import.log").read_text():
            raise RuntimeError("Import did not report completed analysis")
        sidecar = directory / "benchmark.dbg"
        samples = []
        hashes = None
        for iteration in range(args.repeats):
            print(f"benchmark: {count} functions, export {iteration + 1}/{args.repeats}", flush=True)
            output = directory / f"export-{iteration}.log"
            sample = run([wrapper, f"--ghidra-dir={ghidra}", f"--project-dir={project}",
                          "--project-name=Benchmark", "--program=benchmark", f"--input={binary}",
                          f"--output={sidecar}"], output, measured=True)
            reports = [line.split("GhidraDwarfForge report: ", 1)[1]
                       for line in output.read_text().splitlines() if "GhidraDwarfForge report: " in line]
            if len(reports) != 1:
                raise RuntimeError(f"Expected one report in {output}")
            report, end = json.JSONDecoder().raw_decode(reports[0])
            if reports[0][end:].strip() not in ("", "(GhidraScript)"):
                raise RuntimeError(f"Unexpected report log suffix: {output}")
            if (report["failure"] is not None or report["counts"]["functionsFailed"] != 0 or
                    report["counts"]["functionsDecompiled"] < count):
                raise RuntimeError(f"Incomplete scaling fixture export: {output}")
            current_hashes = [digest(sidecar), digest(Path(str(sidecar) + ".c"))]
            if hashes is not None and hashes != current_hashes:
                raise RuntimeError("Repeated artifacts differ")
            hashes = current_hashes
            if digest(binary) != original_hash:
                raise RuntimeError("Original fixture changed")
            sample["counts"] = report["counts"]
            sample["status"] = report["status"]
            samples.append(sample)
        validate(binary, sidecar, directory / "validation", count)
        summary = {"requestedFunctions": count, "inputBytes": binary.stat().st_size,
                   "sidecarBytes": sidecar.stat().st_size,
                   "sourceBytes": Path(str(sidecar) + ".c").stat().st_size,
                   "inputSha256": original_hash, "artifactSha256": hashes,
                   "import": imported, "exports": samples,
                   "exportMedianSeconds": statistics.median(sample["elapsedSeconds"] for sample in samples),
                   "exportMaximumResidentKiB": max(sample["maximumResidentKiB"] for sample in samples),
                   "structuralValidation": "PASS", "gdbBehavior": "PASS", "determinism": "PASS"}
        summaries.append(summary)
        (results / "summary.json").write_text(json.dumps(summaries, indent=4) + "\n")
    print("export-benchmark=PASS", flush=True)


if __name__ == "__main__":
    main()
