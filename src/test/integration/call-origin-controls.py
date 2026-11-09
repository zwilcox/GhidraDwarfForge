#!/usr/bin/env python3
"""Metamorphic controls for exact entry aliases; mutates disposable artifact copies only."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import runpy


SCRIPTS = Path(__file__).resolve().parent
reference = runpy.run_path(str(SCRIPTS / "call-site-reference.py"))
recovered = runpy.run_path(str(SCRIPTS / "call-site-recovered.py"))
run, digest = reference["run"], reference["digest"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path)
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--dwarfdump", required=True, type=Path)
    args = parser.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    compiler = json.loads((args.reference / "result.json").read_text())
    assert compiler["target"] == "x86_64", "this fixture exercises x86 discontiguous recursion"
    report = json.loads((args.artifacts / "result.json").read_text())
    assert report["status"] == "PASS_RECOVERED_PLAN_STRUCTURAL"
    original = (args.reference / "input").resolve()
    protected = {str(original): digest(original)}
    binary = work / "stripped-input"
    run(["objcopy", "--strip-all", original, binary], work / "strip-input")
    before, allocated, headers = reference["image"](original)
    after, new_allocated, new_headers = reference["image"](binary)
    assert allocated == new_allocated and headers == new_headers
    assert not any(s["name"] in (".symtab", ".debug_info") for s in after["sections"])
    binary_hash = digest(binary)
    rows = []
    for view in report["reports"]:
        variant = view["variant"]
        sidecar = (args.artifacts / (variant + ".json.dbg")).resolve()
        protected[str(sidecar)] = digest(sidecar)
        assert protected[str(sidecar)] == view["artifact"]["sidecarSha256"]
        inventory = json.loads(sidecar.with_suffix("").read_text())
        function = next(f for f in inventory["functions"] if f["name"] == "cs_recursive")
        entry = int(function["entry"], 16) - inventory["rebaseDelta"]
        text = run(["readelf", "--wide", "--symbols", sidecar], work / (variant + "-symbols"))
        symbols = re.findall(r"(?m)^\s*\d+:\s+([0-9a-f]+)\s+\d+\s+FUNC\s+\S+\s+\S+\s+\S+\s+(\S+)\s*$", text)
        anchor, = [name for value, name in symbols if name.startswith("forge_call_entry_") and int(value, 16) == entry]
        # Keep the harness boundary (main) and data observation symbol cs_sink;
        # every fixture routine participating in call recovery loses its old symbol.
        old_names = sorted({name for _, name in symbols if name.startswith("cs_")})
        assert "cs_recursive" in old_names
        stripped = work / (variant + "-stripped.dbg")
        run(["llvm-objcopy", *("--strip-symbol=" + name for name in old_names), sidecar, stripped], work / (variant + "-strip-symbols"))
        remaining = run(["readelf", "--wide", "--symbols", stripped], work / (variant + "-remaining-symbols"))
        assert not re.search(r"\bFUNC\b.*\bcs_recursive\s*$", remaining, re.MULTILINE)
        renamed = work / (variant + "-renamed.dbg")
        data = bytearray(stripped.read_bytes())
        info, _, _ = reference["image"](stripped)
        strings, = [s for s in info["sections"] if s["name"] == ".debug_str"]
        start, size = strings["offset"], strings["size"]
        text = data[start:start + size]
        assert text.count(b"cs_recursive\0") == 1
        data[start:start + size] = text.replace(b"cs_recursive\0", b"cs_recursivX\0")
        renamed.write_bytes(data)
        for mode, candidate in (("stripped", stripped), ("renamed", renamed)):
            prefix = work / (variant + "-" + mode)
            run(["llvm-dwarfdump", "--verify", candidate], Path(str(prefix) + "-llvm"))
            run(["python3", "-B", SCRIPTS / "check-dwarfdump.py", candidate,
                 Path(str(prefix) + "-strict.txt"), "--tool", args.dwarfdump.resolve(), "--original", binary],
                Path(str(prefix) + "-strict"))
            original_name = os.environ.get("FORGE_CALL_SITE_RECURSIVE_NAME")
            try:
                os.environ["FORGE_CALL_SITE_RECURSIVE_NAME"] = "cs_recursivX" if mode == "renamed" else "cs_recursive"
                for scenario in range(8):
                    observed = reference["debugger"]("x86_64", binary, scenario,
                        work / f"{variant}-{mode}-runtime-{scenario}", candidate)
                    normalized = copy.deepcopy(observed)
                    for frame in normalized["frames"]:
                        assert not frame["name"].startswith("forge_call_entry_"), "private lookup name leaked into frames"
                        if mode == "renamed":
                            assert frame["name"] != "cs_recursive", "debugger recovered a removed original name"
                            if frame["name"] == "cs_recursivX": frame["name"] = "cs_recursive"
                    recovered["check"](normalized, scenario)
                    rows.append({"view": variant, "mode": mode, "scenario": scenario, "status": "PASS",
                                 "observation": observed})
            finally:
                if original_name is None: os.environ.pop("FORGE_CALL_SITE_RECURSIVE_NAME", None)
                else: os.environ["FORGE_CALL_SITE_RECURSIVE_NAME"] = original_name
        missing = work / (variant + "-missing-alias.dbg")
        run(["llvm-objcopy", "--strip-symbol=" + anchor, stripped, missing], work / (variant + "-remove-alias"))
        negative = reference["debugger"]("x86_64", binary, 4, work / (variant + "-missing-runtime"), missing)
        recursive = [f for f in negative["frames"] if f["name"] == "cs_recursive"]
        assert len(recursive) == 3 and all(not f["tail"] for f in recursive), "missing alias still invented the virtual frame"
        rows.append({"view": variant, "mode": "missing-alias", "scenario": 4, "status": "PASS_NEGATIVE",
                     "observation": negative})
    assert digest(binary) == binary_hash
    assert all(digest(Path(path)) == value for path, value in protected.items())
    result = {"status": "PASS_CALL_ORIGIN_CONTROLS", "role": compiler["role"], "protectedSha256": protected,
              "strippedInputSha256": binary_hash, "sessions": rows,
              "scope": "Disposable-copy symbol removal and DWARF-name mutation; real exporter baseline, no new Ghidra extraction claim"}
    (work / "result.json").write_text(json.dumps(result, indent=4) + "\n")
    print(f"call-origin-controls=PASS role={compiler['role']} sessions={len(rows)}")


if __name__ == "__main__":
    main()
