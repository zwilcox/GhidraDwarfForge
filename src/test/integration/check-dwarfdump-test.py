#!/usr/bin/env python3
"""Controls for complete checker output, including the observed exit-zero failure."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import struct


def main():
    repository = Path(__file__).resolve().parents[3]
    root = repository / "build/test-results/check-dwarfdump"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run.", dir=root))
    print("strict-dwarfdump-test-results=" + str(work), flush=True)
    helper = repository / "src/test/integration/check-dwarfdump.py"
    fixtures = repository / "src/test/fixtures/dwarfdump"
    clean = (fixtures / "clean-2.3.2.txt").read_text()
    historical = (fixtures / "exit-zero-errors-20210528.txt").read_text()
    artifact = work / "input with spaces.dbg"
    artifact.write_bytes(b"private parser control\n")
    fake = work / "replay checker"
    fake.write_text("#!/usr/bin/env python3\n" +
        "import os, pathlib, sys\n" +
        "assert sys.argv[1:5] == ['--no-follow-debuglink', '-ka', '-ki', '-kd']\n" +
        "replay = os.environ.get('CHECK_ORIGINAL_REPLAY') if sys.argv[-1] == " +
        "os.environ.get('CHECK_ORIGINAL_PATH') else os.environ['CHECK_REPLAY']\n" +
        "sys.stderr.write(os.environ.get('CHECK_STDERR', ''))\n" +
        "sys.stderr.flush()\n" +
        "sys.stdout.buffer.write(pathlib.Path(replay).read_bytes())\n" +
        "sys.stdout.flush()\n" +
        "sys.exit(int(os.environ.get('CHECK_EXIT', '0')))\n")
    fake.chmod(0o755)

    def run_case(name, text, expected, exit_status=0, stderr=""):
        replay = work / (name + ".replay")
        replay.write_text(text)
        log = work / (name + ".txt")
        environment = dict(os.environ, CHECK_REPLAY=str(replay),
            CHECK_EXIT=str(exit_status), CHECK_STDERR=stderr)
        result = subprocess.run([sys.executable, str(helper), str(artifact), str(log),
            "--tool", str(fake)], env=environment, text=True, capture_output=True)
        (work / (name + ".runner.txt")).write_text(result.stdout + result.stderr)
        metadata = json.loads(log.with_name(log.name + ".check.json").read_text())
        assert (result.returncode == 0) == expected, (name, result.stderr)
        assert (metadata["status"] == "PASS") == expected, (name, metadata)
        assert metadata["exit_status"] == exit_status, (name, metadata)
        assert log.read_bytes() == text.encode(), name
        assert log.with_name(log.name + ".stderr").read_bytes() == stderr.encode(), name
        print(name + "=PASS", flush=True)

    run_case("clean", clean, True)
    # Real retained Ubuntu 20210528 output: its tool returned zero despite
    # line_table=13, harmless_errors=3 and total errors=16.
    run_case("historical-exit-zero-errors", historical, False)
    run_case("nonzero-compiler", clean.replace("errors =     0,", "errors =     1,", 1), False)
    run_case("nonzero-category", re.sub(r"(line_table\s+\d+\s+)0", r"\g<1>4", clean, count=1), False)
    run_case("nonzero-total", re.sub(r"(\*\* Summarize \*\*\s+\d+\s+)0", r"\g<1>1", clean, count=1), False)
    run_case("malformed-counter", re.sub(r"(line_table\s+)\d+", r"\g<1>unknown", clean, count=1), False)
    # Removing a zero-valued category preserves the arithmetic, so completion
    # must require its presence in both the compiler and total tables.
    zero_categories = set(re.findall(r"^([a-z_]+)\s+0\s+0$", clean, re.MULTILINE))
    assert {"locations", "frames", "fde_table", "type_offset"} <= zero_categories
    for category in sorted(zero_categories):
        matches = list(re.finditer(r"^" + category + r"\s+0\s+0\n", clean, re.MULTILINE))
        assert len(matches) == 2, category
        for table, match in enumerate(matches):
            incomplete = clean[:match.start()] + clean[match.end():]
            run_case("missing-zero-" + category + "-table-" + str(table), incomplete, False)
    run_case("unknown-zero-category", clean.replace("locations", "unknown_category", 1), False)
    run_case("empty", "", False)
    run_case("truncated-table", clean.split("** Summarize **", 1)[0], False)
    run_case("truncated-final-record", clean[:clean.rfind("[    3]")], False)
    run_case("nonzero-exit", clean, False, exit_status=7)
    run_case("stderr-warning", clean, False, stderr="warning: unclassified checker problem\n")
    run_case("stderr-before-clean-output", clean, False, stderr="unexpected checker diagnostic\n")
    assert artifact.read_bytes() == b"private parser control\n"

    for destination in ("raw", "stderr", "metadata", "original", "original-stderr"):
        for kind in ("direct", "symlink", "hardlink"):
            case = work / ("alias-" + destination + "-" + kind)
            case.mkdir()
            log = case / "checker.txt"
            suffix = {"raw": "", "stderr": ".stderr", "metadata": ".check.json",
                "original": ".original.txt", "original-stderr": ".original.txt.stderr"}[destination]
            colliding = log.with_name(log.name + suffix)
            original = colliding if kind == "direct" else case / "original.elf"
            original.write_bytes(b"preserve original ELF control\n")
            if kind == "symlink":
                colliding.symlink_to(original)
            elif kind == "hardlink":
                os.link(original, colliding)
            result = subprocess.run([sys.executable, str(helper), str(artifact), str(log),
                "--tool", str(fake), "--original", str(original)], text=True, capture_output=True)
            assert result.returncode != 0 and "aliases an ELF input" in result.stderr, result.stderr
            assert original.read_bytes() == b"preserve original ELF control\n"
            assert artifact.read_bytes() == b"private parser control\n"
    print("all-log-original-aliases=PASS", flush=True)

    # An actual source-built DWARF5 object also exercises the selected checker,
    # independently of the replay controls. No frame data is needed here.
    source = work / "clean.c"
    source.write_text("int clean_value(int input) { return input + 1; }\n")
    original = work / "clean.o"
    subprocess.run(["gcc", "-g", "-gdwarf-5", "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables", "-c", str(source), "-o", str(original)], check=True)
    subprocess.run([sys.executable, str(helper), str(original), str(work / "real-clean.txt")],
        check=True)

    # A separate compiler-built x86 ELF pair has identical inherited frame
    # bytes. This is the only eligible diagnostic family; counts alone cannot
    # establish inheritance. The selected pinned checker reports these records.
    source.write_text("int main(void) { return 0; }\n")
    artifact = work / "compiler.dbg"
    original = work / "compiler.stripped"
    subprocess.run(["gcc", "-g", "-gdwarf-5", "-O0", "-fno-pie", "-no-pie",
        str(source), "-o", str(artifact)], check=True)
    subprocess.run(["objcopy", "--strip-debug", str(artifact), str(original)], check=True)
    without_original = subprocess.run([sys.executable, str(helper), str(artifact),
        str(work / "without-original.txt")], text=True, capture_output=True)
    assert without_original.returncode != 0 and "uncorroborated inherited" in without_original.stderr
    proof = work / "corroborated.txt"
    subprocess.run([sys.executable, str(helper), str(artifact), str(proof),
        "--original", str(original)], check=True)
    evidence = json.loads(proof.with_name(proof.name + ".check.json").read_text())
    assert evidence["inherited_frame_evidence"]["diagnostics"]
    assert evidence["reported_errors"] > 0 and evidence["uncorroborated_errors"] == 0

    # Mutate private copies, preserving the exact original/compiler baselines.
    baseline = original.read_bytes()
    section_offset = struct.unpack_from("<Q", baseline, 40)[0]
    entry_size, section_count, names_index = struct.unpack_from("<HHH", baseline, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", baseline, section_offset + index * entry_size)
        for index in range(section_count)]
    names = sections[names_index]
    strings = baseline[names[4]:names[4] + names[5]]
    frame_index = next(index for index, section in enumerate(sections)
        if strings[section[0]:].split(b"\0", 1)[0] == b".eh_frame")
    sectionless = work / "sectionless.elf"
    erased = bytearray(baseline)
    struct.pack_into("<Q", erased, 40, 0)
    struct.pack_into("<HH", erased, 60, 0, 0)
    sectionless.write_bytes(erased)
    subprocess.run([sys.executable, str(helper), str(artifact), str(work / "bound-frame-reference.txt"),
        "--original", str(sectionless), "--frame-reference", str(original)], check=True)
    truncated = work / "sectionless-trailing-table-removed.elf"
    shortened = erased[:section_offset]
    struct.pack_into("<H", shortened, 58, 0)
    truncated.write_bytes(shortened)
    subprocess.run([sys.executable, str(helper), str(artifact), str(work / "trailing-table-reference.txt"),
        "--original", str(truncated), "--frame-reference", str(original)], check=True)
    for label, data in (
            ("missing-frame-tail", shortened[:sections[frame_index][4] + sections[frame_index][5] - 1]),
            ("changed-retained-byte", shortened[:])):
        if label == "changed-retained-byte":
            data[0x100] ^= 1
        candidate = work / (label + ".elf")
        candidate.write_bytes(data)
        result = subprocess.run([sys.executable, str(helper), str(artifact), str(work / (label + ".txt")),
            "--original", str(candidate), "--frame-reference", str(original)], text=True, capture_output=True)
        assert result.returncode != 0 and ("frame reference" in result.stderr or
            "frame bytes differ" in result.stderr), result.stderr
    for label, offset in (("body", 0x100), ("header", 18), ("frame", sections[frame_index][4])):
        candidate = work / ("reference-mismatch-" + label)
        changed = bytearray(baseline)
        changed[offset] ^= 1
        candidate.write_bytes(changed)
        result = subprocess.run([sys.executable, str(helper), str(artifact),
            str(work / ("reference-mismatch-" + label + ".txt")), "--original", str(sectionless),
            "--frame-reference", str(candidate)], text=True, capture_output=True)
        assert result.returncode != 0 and "frame reference" in result.stderr
    assert sections[frame_index][5] > 4 and baseline[
        sections[frame_index][4] + sections[frame_index][5] - 4:
        sections[frame_index][4] + sections[frame_index][5]] == bytes(4)
    # A table-proven extent can stop before the original zero terminator.
    trimmed = work / "trimmed-frame.dbg"
    data = bytearray(artifact.read_bytes())
    table = struct.unpack_from("<Q", data, 40)[0]
    width, count, names_index_ = struct.unpack_from("<HHH", data, 58)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, table + i * width) for i in range(count)]
    strings_ = headers[names_index_]
    names_ = data[strings_[4]:strings_[4] + strings_[5]]
    index = next(i for i, h in enumerate(headers) if names_[h[0]:].split(b"\0", 1)[0] == b".eh_frame")
    struct.pack_into("<Q", data, table + index * width + 32, headers[index][5] - 4)
    trimmed.write_bytes(data)
    subprocess.run([sys.executable, str(helper), str(trimmed), str(work / "trimmed-bound-reference.txt"),
        "--original", str(sectionless), "--frame-reference", str(original)], check=True)
    for kind in ("direct", "symlink", "hardlink"):
        collision = work / ("reference-log-alias-" + kind)
        if kind == "direct":
            collision = original
        elif kind == "symlink":
            collision.symlink_to(original)
        else:
            os.link(original, collision)
        result = subprocess.run([sys.executable, str(helper), str(artifact), str(collision),
            "--original", str(sectionless), "--frame-reference", str(original)], text=True, capture_output=True)
        assert result.returncode != 0 and "aliases an ELF input" in result.stderr
        assert original.read_bytes() == baseline
    print("sectionless-frame-reference-byte-binding-and-controls=PASS", flush=True)
    for name, offset in (("frame-byte", sections[frame_index][4]), ("machine", 18),
            ("frame-address", section_offset + frame_index * entry_size + 16)):
        changed = bytearray(baseline)
        changed[offset] ^= 1
        candidate = work / (name + ".elf")
        candidate.write_bytes(changed)
        result = subprocess.run([sys.executable, str(helper), str(artifact),
            str(work / (name + ".txt")), "--original", str(candidate)], text=True, capture_output=True)
        assert result.returncode != 0 and "identities or bytes differ" in result.stderr, result.stderr
    assert original.read_bytes() == baseline

    raw = proof.read_text()
    original_raw = proof.with_name(proof.name + ".original.txt").read_text()
    frame_lines = re.findall(r"^\*\*\* DWARF CHECK: DW_DLE_DEBUG_FRAME_LENGTH_NOT_MULTIPLE.*$",
        raw, re.MULTILINE)
    assert len(set(frame_lines)) >= 2, "multiplicity control needs distinct frame records"
    replay = work / "inherited-replay.txt"
    reference_replay = work / "original-replay.txt"
    for name, side_text, original_text in (
            ("different-diagnostic-offset", raw,
                re.sub(r"offset 0x[0-9a-f]+\.", "offset 0xdeadbeef.", original_raw, count=1)),
            ("duplicate-diagnostic-same-count", raw.replace(frame_lines[1], frame_lines[0], 1),
                original_raw),
            ("extra-emitted-line-error", re.sub(r"(line_table\s+\d+\s+)0", r"\g<1>1", raw, count=1),
                original_raw)):
        replay.write_text(side_text)
        reference_replay.write_text(original_text)
        environment = dict(os.environ, CHECK_REPLAY=str(replay), CHECK_EXIT="0",
            CHECK_ORIGINAL_PATH=str(original), CHECK_ORIGINAL_REPLAY=str(reference_replay))
        result = subprocess.run([sys.executable, str(helper), str(artifact),
            str(work / (name + ".txt")), "--original", str(original), "--tool", str(fake)],
            env=environment, text=True, capture_output=True)
        assert result.returncode != 0, name
    print("inherited-frame-exact-evidence-and-corruption-controls=PASS", flush=True)
    (work / "result.txt").write_text("strict-dwarfdump-controls=PASS\n")
    print("strict-dwarfdump-controls=PASS")


if __name__ == "__main__":
    main()
