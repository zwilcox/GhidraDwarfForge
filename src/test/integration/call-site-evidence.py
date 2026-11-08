#!/usr/bin/env python3
"""Compare current Ghidra transfer capture with compiler reference instruction PCs."""
import argparse
import hashlib
import json
import os
import runpy
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
    indirect = next(call for call in reference["calls"] if call["caller"] == "cs_indirect")
    assert omissions["cs_leaf"] == "entry has an unproved incoming non-call transfer at " + instructions[int(indirect["pc"], 16)]["address"]
    if reference["target"] == "x86_64":
        assert "incomplete instruction inventory" in omissions["cs_driver"]
        assert "unproved incoming non-call transfer" in omissions["cs_driver.cold"]
    return captured["tails"]


def program_hashes(project):
    data = project / "Calls.rep/idata"
    result = {str(path.relative_to(data)): digest(path) for path in sorted(data.rglob("*")) if path.is_file()}
    assert result, "missing saved program database"
    return result


def compare_arguments(reference, captured):
    evaluate = runpy.run_path(str(ROOT / "src/test/integration/check-call-values.py"))["evaluate"]
    expressions = {int(row["pc"], 16): row for row in captured["arguments"]}
    observations = []
    first, second = (5, 4) if reference["target"] == "x86_64" else (0, 1)
    addends = {"cs_normal": 1, "cs_tail_first": 1, "cs_tail_middle": 2, "cs_left": 3, "cs_right": 4}
    checks = 0
    for call in reference["calls"]:
        if call["caller"] in ("cs_indirect", "cs_leaf"):
            continue
        row = expressions[int(call["pc"], 16)]
        values = row["integerArgumentExpressions"]
        assert row["caller"] == call["caller"] and values[0] is not None, (call, row)
        for value, depth in ((0, 0), (20, 3), (0xffffffff, 1), (0x7fffffff, 1), (0x80000000, 0), (17, 0xffffffff)):
            # P-code arithmetic is modular. Overflow samples test machine values;
            # they do not assert defined signed-overflow behavior for the C source.
            registers = {number: 0xdead00000000 + number for number in range(33)}
            registers[first], registers[second] = value, depth
            expected = value + addends.get(call["caller"], 0)
            if call["caller"] == "cs_diamond":
                expected = value + (1 if call["callee"] == "cs_left" else 2)
            elif call["caller"] == "cs_recursive" and call["callee"] == "cs_recursive":
                expected = value + 1
                assert values[1] is not None
                assert evaluate(bytes.fromhex(values[1]), 8, "little", registers) == (depth - 1) & 0xffffffff
                checks += 1
            elif call["caller"] == "cs_tail_recursive":
                expected = value + depth
            assert evaluate(bytes.fromhex(values[0]), 8, "little", registers) == expected & 0xffffffff, (call, row, value, depth)
            checks += 1
        observations.append(row)
    assert "cs_indirect" in captured["argumentOmissions"]
    assert "cs_leaf" in captured["argumentOmissions"] and not any(row["caller"] == "cs_leaf" for row in expressions.values())
    if reference["target"] == "x86_64":
        assert "cs_driver.cold" in captured["argumentOmissions"] and "cs_driver" in captured["argumentOmissions"]
    return {"checks": checks, "transfers": observations}


def compare_bindings(reference, captured):
    evaluate = runpy.run_path(str(ROOT / "src/test/integration/check-call-values.py"))["evaluate"]
    rows = {int(row["pc"], 16): row for row in captured["bindings"]}
    first, second = (5, 4) if reference["target"] == "x86_64" else (0, 1)
    addends = {"cs_normal": 1, "cs_tail_first": 1, "cs_tail_middle": 2, "cs_left": 3, "cs_right": 4}
    checks, observations = 0, []
    for call in reference["calls"]:
        if call["callee"] is None:
            assert int(call["pc"], 16) not in rows, "indirect target acquired a formal binding"
            continue
        row = rows[int(call["pc"], 16)]
        assert row["caller"] == call["caller"] and row["callee"] == call["callee"]
        args = row["arguments"]
        if call["callee"] == "cs_checkpoint":
            assert not args
            continue
        two = call["callee"] == "cs_recursive"
        assert [a["ordinal"] for a in args] == ([0, 1] if two else [0]), row
        assert [a["name"] for a in args] == (["value", "depth"] if two else ["value"]), row
        assert [a["register"] for a in args] == ([first, second] if two else [first]), row
        assert all(a["bytes"] == 8 and a["typeKey"] for a in args) and not row["omissions"], row
        for value, depth in ((0, 0), (20, 3), (0xffffffff, 1), (0x7fffffff, 1), (0x80000000, 0), (17, 0xffffffff),
                             (0xabcdef0000000014, 0x1234560000000003)):
            registers = {first: value, second: depth}
            expected = value + addends.get(call["caller"], 0)
            if call["caller"] == "cs_diamond":
                expected = value + (1 if call["callee"] == "cs_left" else 2)
            elif call["caller"] == "cs_recursive" and call["callee"] == "cs_recursive":
                expected = value + 1
                assert evaluate(bytes.fromhex(args[1]["expression"]), 8, "little", registers) == (depth - 1) & 0xffffffff
                checks += 1
            elif call["caller"] == "cs_tail_recursive":
                expected = value + depth
            if not (call["caller"] == "cs_forward" or call["caller"] == "cs_recursive" and call["callee"] == "cs_leaf"):
                expected &= 0xffffffff
            assert evaluate(bytes.fromhex(args[0]["expression"]), 8, "little", registers) == expected, (call, row, value, depth)
            checks += 1
        # Temporary fixture type IDs are not persistent analyst type identities;
        # compare semantic bindings and expressions across rolled-back processes.
        observations.append({**row, "arguments": [{k: v for k, v in arg.items() if k != "typeKey"} for arg in args]})
    driver = []
    for row in rows.values():
        if row["caller"] == "cs_driver" and reference["target"] == "aarch64":
            expected = {"cs_tail_first": [20], "cs_tail_recursive": [50, 3], "cs_normal": [10],
                        "cs_forward": [70], "cs_recursive": [40, 3], "cs_indirect": [60], "cs_diamond": [30]}[row["callee"]]
            assert [a["name"] for a in row["arguments"]] == (["value", "depth"] if len(expected) == 2 else ["value"])
            assert [a["register"] for a in row["arguments"]] == list(range(len(expected))) and not row["omissions"]
            assert [evaluate(bytes.fromhex(a["expression"]), 8, "little", {}) for a in row["arguments"]] == expected
            checks += len(expected)
            driver.append(row["callee"])
            observations.append({**row, "arguments": [{k: v for k, v in arg.items() if k != "typeKey"} for arg in row["arguments"]]})
        elif row["caller"] in ("cs_driver", "cs_driver.cold", "cs_indirect"):
            assert not row["arguments"], "unproved caller gained parameter values"
    if reference["target"] == "aarch64":
        assert sorted(driver) == sorted(["cs_tail_first", "cs_tail_recursive", "cs_normal", "cs_forward",
                                         "cs_recursive", "cs_indirect", "cs_diamond", "cs_diamond"])
    return {"checks": checks, "transfers": observations}


def compare_plan(reference, captured):
    functions = {int(f["entry"], 16) - captured["rebaseDelta"]: f["name"] for f in captured["functions"]}
    entries = {name: address for address, name in functions.items()}
    plans = {functions[int(f["caller"], 16)]: f for f in captured["plan"]}
    assert set(plans) == set(entries), (set(plans), set(entries))
    partial = {"cs_indirect", "cs_leaf"}
    if reference["target"] == "x86_64":
        partial.update(("cs_driver", "cs_driver.cold"))
    for name, plan in plans.items():
        assert plan["completeness"] == ("PARTIAL" if name in partial else "ALL_CALLS"), (name, plan)
    sites = {int(site["pc"], 16): (name, site) for name, plan in plans.items() for site in plan["sites"]}
    assert len(sites) == sum(len(plan["sites"]) for plan in plans.values()), "ambiguous plan ownership"
    bindings = {int(b["pc"], 16): b for b in captured["bindings"]}
    checks = 0
    for call in reference["calls"]:
        pc = int(call["pc"], 16)
        if call["callee"] is None:
            assert pc not in sites, "unresolved indirect tail became a proved tail"
            continue
        name, site = sites[pc]
        assert name == call["caller"] and site["tail"] == call["tail"]
        assert int(site["returnPc"], 16) == int(call["returnPc"], 16), (call, site)
        assert int(site["callee"], 16) == entries[call["callee"]]
        assert site["arguments"] == bindings[pc]["arguments"], (call, site)
        checks += 1
    # Check every emitted site's binding, including driver calls outside the
    # selected compiler oracle rows. Unknown/decompiler-only values stay absent.
    for pc, (name, site) in sites.items():
        assert site["arguments"] == bindings[pc]["arguments"], (name, site)
    assert not plans["cs_indirect"]["sites"]
    semantic = [{**plan, "sites": [{**site, "arguments": [
        {k: v for k, v in arg.items() if k != "typeKey"} for arg in site["arguments"]]}
        for site in plan["sites"]]} for plan in captured["plan"]]
    return {"compilerComparisons": checks, "sites": len(sites), "functions": semantic}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path, help="completed call-site-reference.py output")
    parser.add_argument("output", type=Path)
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--reuse-project", action="store_true", help="read an existing capture project; write fresh tail-state reports")
    parser.add_argument("--report-name", default="tail-state", choices=("tail-state", "argument-state", "parameter-binding", "entry-contract", "composed-plan", "forge-plan", "entry-locations"),
                        help="fresh report directory when reusing a saved project")
    parser.add_argument("--bind-parameters", action="store_true", help="temporarily curate fixture integer signatures and validate actual entry binding")
    parser.add_argument("--consumer", type=Path, help="emit and validate native sidecars from recovered plans")
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--dwarfdump", type=Path)
    args = parser.parse_args()
    if any((args.consumer, args.producer, args.dwarfdump)):
        assert all((args.consumer, args.producer, args.dwarfdump, args.bind_parameters)), "emission requires both libraries, validator and binding"
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
    reports_root = work / args.report_name if args.reuse_project else work
    if args.reuse_project:
        reports_root.mkdir(exist_ok=False)
    # Read-only reopen through the current source runtime; do not overwrite a
    # user's installed extension or build another Ghidra installation.
    reports = []
    for variant, shift in (("original", 0), ("rebased", 0x400000)):
        output = reports_root / (variant + ".json")
        text = run([ROOT / "gradlew", "--no-daemon", "callSiteEvidenceProbe",
                    "-PcallSiteProject=" + str(project), "-PcallSiteInput=" + str(original),
                    "-PcallSiteReport=" + str(output), "-PcallSiteRebase=" + str(shift),
                    *(["-PcallSiteBindings=true"] if args.bind_parameters else []),
                    *(["-PcallSiteConsumer=" + str(args.consumer.resolve()), "-PcallSiteProducer=" + str(args.producer.resolve())]
                      if args.consumer else [])], reports_root / (variant + "-capture"), env)
        assert "call-site-evidence-probe=PASS" in text
        captured = json.loads(output.read_text())
        assert "/build/classes/java/main/" in captured["classOrigin"], captured["classOrigin"]
        reports.append({"variant": variant, "delta": captured["rebaseDelta"], "calls": compare(compiler, captured),
                        "tails": compare_tails(compiler, captured), "tailOmissions": captured["tailOmissions"],
                        "arguments": compare_arguments(compiler, captured), "argumentOmissions": captured["argumentOmissions"],
                        "omissions": {f["name"]: f["omissions"] for f in captured["functions"] if f["omissions"]}})
        if args.bind_parameters:
            reports[-1]["bindings"] = compare_bindings(compiler, captured)
            reports[-1]["plan"] = compare_plan(compiler, captured)
        if args.consumer:
            sidecar = Path(captured["sidecar"])
            run(["readelf", "-h", "-S", "-n", "--debug-dump=info,abbrev,aranges,decodedline", sidecar], reports_root / (variant + "-gnu"), env)
            run(["llvm-dwarfdump", "--verify", sidecar], reports_root / (variant + "-llvm"), env)
            run(["python3", "-B", ROOT / "src/test/integration/check-dwarfdump.py", sidecar,
                 reports_root / (variant + "-strict.txt"), "--tool", args.dwarfdump.resolve(), "--original", original],
                reports_root / (variant + "-strict"), env)
            reports[-1]["artifact"] = {"sidecarSha256": digest(sidecar), "sourceSha256": digest(Path(str(sidecar) + ".c"))}
    assert reports[0]["calls"] == reports[1]["calls"], "rebase changed transfer identities or original bytes"
    assert reports[0]["tails"] == reports[1]["tails"], "rebase changed proved tail identities or original bytes"
    assert reports[0]["arguments"] == reports[1]["arguments"], "rebase changed integer actual-value expressions"
    if args.bind_parameters:
        assert reports[0]["bindings"] == reports[1]["bindings"], "rebase changed formal storage or argument values"
        assert reports[0]["plan"] == reports[1]["plan"], "rebase changed call-site plan"
    assert reports[1]["delta"] - reports[0]["delta"] == 0x400000
    assert digest(original) == protected, "capture changed the original executable"
    assert program_hashes(project) == saved, "capture changed the saved program database"
    (reports_root / "result.json").write_text(json.dumps({
        "status": "PASS_RECOVERED_PLAN_STRUCTURAL" if args.consumer else
            "PASS_CURATED_PARAMETER_BINDING" if args.bind_parameters else "PASS_CAPTURE_TAIL_ARGUMENT_REFERENCE",
        "target": compiler["target"], "role": compiler["role"],
        "scope": "Captured transfers, tails, integer bindings and composed plans; optional emission validates structure/determinism. Full debugger behavior and normal-script execution remain separate acceptance gates.",
        "inputSha256": protected, "savedProgramSha256": saved, "reports": reports,
    }, indent=4) + "\n")
    print(f"call-site-evidence-reference=PASS target={compiler['target']} role={compiler['role']}")


if __name__ == "__main__":
    main()
