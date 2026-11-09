#!/usr/bin/env python3
"""Linux producer admission/form probe, not Forge runtime call-site acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


MODES = {
    "control": ("DW_AT_low_pc", "DW_FORM_addr"),
    "call-pc": ("DW_AT_call_pc", "DW_FORM_addr"),
    "return-pc": ("DW_AT_call_return_pc", "DW_FORM_addr"),
    "origin": ("DW_AT_call_origin", "DW_FORM_ref4"),
    "parameter": ("DW_AT_call_parameter", "DW_FORM_ref4"),
    "value": ("DW_AT_call_value", "DW_FORM_exprloc"),
    "target": ("DW_AT_call_target", "DW_FORM_exprloc"),
    "target-clobbered": ("DW_AT_call_target_clobbered", "DW_FORM_exprloc"),
    "data-location": ("DW_AT_call_data_location", "DW_FORM_exprloc"),
    "data-value": ("DW_AT_call_data_value", "DW_FORM_exprloc"),
}
for name in ("value", "target", "target-clobbered", "data-location", "data-value"):
    MODES["block-" + name] = MODES[name]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prefix = args.prefix.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output must be empty; retain/review earlier results before reuse")
    commands = []

    def run(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        commands.append({"command": command, "returncode": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
        (output / "commands.json").write_text(json.dumps(commands, indent=4) + "\n")
        if result.returncode:
            raise RuntimeError(f"Command failed: {command}\n{result.stdout}\n{result.stderr}")
        return result

    probe = output / "probe"
    source = Path(__file__).with_name("call-site-producer-probe.c").resolve()
    run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-I" + str(prefix / "include/libdwarf-2"), str(source),
         "-L" + str(prefix / "lib"), "-Wl,-rpath," + str(prefix / "lib"),
         "-ldwarfp", "-ldwarf", "-o", str(probe)])
    envelope_source = output / "envelope.c"
    envelope_source.write_text("int producer_probe_envelope;\n")
    envelope = output / "envelope.o"
    run(["cc", "-c", "-g0", str(envelope_source), "-o", str(envelope)])
    results = []
    for mode, (attribute, form) in MODES.items():
        directory = output / mode
        directory.mkdir()
        run([str(probe), mode, str(directory)])
        object_path = directory / "probe.o"
        command = ["objcopy"]
        for section in sorted(directory.glob(".debug_*")):
            command.extend(["--add-section", section.name + "=" + str(section)])
        command.extend([str(envelope), str(object_path)])
        run(command)
        abbreviations = run(["readelf", "--debug-dump=abbrev", str(object_path)])
        if abbreviations.stderr or not re.search(
                rf"\b{attribute}\s+{form}\b", abbreviations.stdout):
            raise RuntimeError(f"Missing expected {attribute}/{form}: {abbreviations}")
        info = run(["readelf", "--debug-dump=info", str(object_path)])
        if info.stderr:
            raise RuntimeError(f"readelf diagnostic: {info.stderr}")
        if mode.startswith("block-"):
            llvm_info = run(["llvm-dwarfdump", "--debug-info", str(object_path)])
            if "DW_OP_entry_value" not in llvm_info.stdout:
                raise RuntimeError("LLVM did not decode the nested entry-value expression")
        run(["llvm-dwarfdump", "--verify", str(object_path)])
        results.append({"mode": mode, "attribute": attribute, "form": form,
                        "readelf": "PASS", "llvmVerify": "PASS"})
        print(f"{mode}: admission, {form}, readelf and LLVM verification PASS", flush=True)
    report = {"scope": "Producer attribute admission/forms only; no Forge/GDB runtime claim",
              "results": results, "nativeSha256": {}}
    with source.open("rb") as stream:
        report["probeSourceSha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
    with Path(__file__).open("rb") as stream:
        report["harnessSha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
    for name in ("libdwarf.so.2.3.2", "libdwarfp.so.2.3.2"):
        with (prefix / "lib" / name).open("rb") as stream:
            report["nativeSha256"][name] = hashlib.file_digest(stream, "sha256").hexdigest()
    report["versions"] = {tool: run([tool, "--version"]).stdout.splitlines()[0]
                          for tool in ("cc", "readelf", "llvm-dwarfdump")}
    (output / "summary.json").write_text(json.dumps(report, indent=4) + "\n")


if __name__ == "__main__":
    main()
