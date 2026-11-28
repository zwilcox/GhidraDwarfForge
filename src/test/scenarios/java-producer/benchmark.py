#!/usr/bin/env python3
"""Compare export of a real ELF's defined dynamic text symbols in separate JVMs."""
import argparse
import json
import platform
import statistics
from pathlib import Path

from compare import TEST, digest, prepare, run


def inventory(path):
    symbols = {}
    for row in run(["nm", "-DS", "-n", "--defined-only", path]).splitlines():
        fields = row.split()
        if len(fields) != 4:
            continue
        address, size, kind, name = fields
        if kind == "T" and int(size, 16) > 0:
            symbols.setdefault(address, (size, name))
    if len(symbols) < 100:
        raise ValueError("benchmark requires at least 100 distinct exported function addresses")
    return [f"{address}\t{size}\t{name}" for address, (size, name) in symbols.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--extension", required=True, type=Path)
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = args.input.resolve(strict=True)
    libraries, java = prepare(args.extension, args.ghidra, output)
    symbols = inventory(source)
    listing = output / "symbols.tsv"
    listing.write_text("\n".join(symbols) + "\n")
    report = {"input": source.name, "inputSha256": digest(source), "symbols": len(symbols),
              "jarSha256": digest(libraries / "GhidraDwarfForge.jar"), "host": platform.platform(),
              "cpu": next(row.split(":", 1)[1].strip() for row in Path("/proc/cpuinfo").read_text().splitlines()
                          if row.startswith("model name")), "jvm": run(["java", "-version"]).splitlines()[0],
              "flags": ["-Xms128m", "-Xmx512m"], "backends": {}}
    observations = {}
    for series, order in enumerate([("java", "libdwarf"), ("libdwarf", "java")]):
        for backend in order:
            dest = output / backend
            dest.mkdir(exist_ok=True)
            side = dest / "symbols.dbg"
            rss = dest / f"rss-{series}.txt"
            raw = run(["/usr/bin/time", "-f", "%M", "-o", rss, *java, *report["flags"],
                       "evaluation.SymbolBenchmark", backend, source, side, libraries, listing, "7"],
                      log=dest / f"export-{series}.log")
            ms = [int(row.split("=")[1]) / 1e6 for row in raw.splitlines() if row.startswith("export-ns=")]
            assert len(ms) == 7
            values = report["backends"].setdefault(backend, {"series": []})
            values["series"].append({"warmupMs": ms[:2], "sampleMs": ms[2:], "peakRssKiB": int(rss.read_text())})
            current = digest(side)
            assert values.setdefault("sidecarSha256", current) == current
            values["bytes"] = side.stat().st_size
            assert "No errors." in run(["llvm-dwarfdump", "--verify", side], log=dest / "llvm.log")
            run(["python3", TEST / "integration/check-dwarfdump.py", side, dest / "strict.log",
                 "--original", source], log=dest / "strict-result.log")
            rows = run(["readelf", "--debug-dump=info", "--wide", side], log=dest / "readelf.log")
            observations[backend] = decoded_functions(rows)
            assert digest(source) == report["inputSha256"]
    expected = {name: (int(a, 16), int(s, 16)) for a, s, name in (line.split("\t") for line in symbols)}
    assert observations["java"] == observations["libdwarf"] == expected
    for values in report["backends"].values():
        values["medianMs"] = statistics.median(t for s in values["series"] for t in s["sampleMs"])
    (output / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def decoded_functions(text):
    result = {}
    current = None
    for row in text.splitlines():
        if "Abbrev Number:" in row:
            if current is not None:
                name, address, size = current
                if name in result:
                    raise ValueError(f"duplicate decoded function {name}")
                result[name] = (address, size)
            current = [None, None, None] if "(DW_TAG_subprogram)" in row else None
        elif current is not None:
            if " DW_AT_name " in row:
                current[0] = row.rsplit(" ", 1)[-1]
            elif " DW_AT_low_pc " in row:
                current[1] = int(row.split()[-1], 0)
            elif " DW_AT_high_pc " in row:
                current[2] = int(row.split()[-1], 0)
    return result


if __name__ == "__main__":
    main()
