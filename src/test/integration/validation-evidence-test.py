#!/usr/bin/env python3
"""Focused evidence reader/capture controls; no Ghidra, GDB or inferior execution."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("evidence", HERE / "validation-evidence.py")
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=4) + "\n", encoding="utf-8")


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class Controls:
    def __init__(self, arguments):
        self.arguments = arguments
        self.work = Path(tempfile.mkdtemp(prefix="run.", dir=arguments.output.resolve()))
        self.passed = []
        self.inputs = {}
        self.baseline = self.work / "baseline"
        self.baseline.mkdir()
        (self.baseline / "cases").mkdir()

    def check(self, label, condition):
        if not condition:
            raise AssertionError(label)
        self.passed.append(label)

    def reject(self, label, action, exception=None, message=None):
        try:
            action()
        except BaseException as failure:
            allowed = exception or (EVIDENCE.EvidenceError, OSError, UnicodeError,
                                    json.JSONDecodeError)
            if not isinstance(failure, allowed):
                raise AssertionError(label + ": unexpected exception") from failure
            if message is not None and message not in str(failure):
                raise AssertionError(label + ": wrong failure phase: " + str(failure)) from failure
            self.passed.append(label)
            return failure
        raise AssertionError(label + ": unexpectedly accepted")

    def clone(self, label):
        destination = self.work / label
        shutil.copytree(self.baseline, destination)
        return destination

    def refresh(self, root, role=None, tools=False):
        """Rebind unsigned hashes so semantic controls reach the actual reader."""
        index = load(root / "index.json")
        if tools:
            path = root / "tools/toolset.json"
            record = load(path)
            record["files"] = [EVIDENCE.file_record(path.parent, path.parent / item["path"],
                                                   EVIDENCE.TOOL_FILE) for item in record["files"]]
            write_json(path, record)
            index["toolset"] = EVIDENCE.file_record(root, path, EVIDENCE.SMALL_JSON)
        for current in EVIDENCE.ROLES:
            path = root / "cases" / current / "receipt.json"
            record = load(path)
            if current == role:
                record["outputs"] = [EVIDENCE.file_record(path.parent, path.parent / item["path"],
                                                         EVIDENCE.LARGE_FILE) for item in record["outputs"]]
            if tools:
                record["toolsetSha256"] = index["toolset"]["sha256"]
            write_json(path, record)
            index["captures"][current] = EVIDENCE.file_record(root, path, EVIDENCE.SMALL_JSON)
        write_json(root / "index.json", index)

    def read(self, root):
        return EVIDENCE.read_capture_index(root / "index.json", "test")

    def initialize(self):
        toolset = EVIDENCE.create_tools(self.arguments.bundle, self.arguments.llvm,
                                        self.arguments.llvm_notices, self.baseline / "tools")
        fixtures = self.work / "inputs"
        fixtures.mkdir()
        receipts = {}
        for index, role in enumerate(EVIDENCE.ROLES):
            source = fixtures / (role + ".c")
            source.write_text("int value(int x) { return x + " + str(index + 1) +
                              "; }\nint main(void) { return value(19); }\n", encoding="ascii")
            original, sidecar = fixtures / role, fixtures / (role + ".dbg")
            command = [self.arguments.cc, "-g", "-gdwarf-5", "-O0", str(source), "-o", str(original)]
            command.extend(["-fPIE", "-pie"] if role == "pie" else ["-fno-pie", "-no-pie"])
            if role == "exec.no-build-id":
                command.append("-Wl,--build-id=none")
            with (fixtures / (role + ".compiler.stdout")).open("xb") as output, \
                    (fixtures / (role + ".compiler.stderr")).open("xb") as errors:
                result = subprocess.run(command, stdout=output, stderr=errors, check=False)
            self.check(role + " compiler completed quietly", result.returncode == 0 and
                       not (fixtures / (role + ".compiler.stderr")).read_bytes())
            shutil.copyfile(original, sidecar)
            self.inputs[role] = (original, sidecar)
            receipts[role] = EVIDENCE.capture(original, sidecar, toolset,
                                               self.baseline / "cases" / role)
        EVIDENCE.create_index("test", receipts, self.baseline / "index.json")
        result = self.read(self.baseline)
        self.check("three full real compiler captures", set(result["captures"]) == set(EVIDENCE.ROLES))
        self.before = {str(path): EVIDENCE.snapshot(path) for paths in self.inputs.values() for path in paths}
        for role, paths in self.inputs.items():
            result = EVIDENCE.verify_selection(self.baseline / "index.json", "test", role, *paths)
            self.check(role + " selected bytes verified", result["status"] == "MATCHING_CAPTURED_EVIDENCE")
        copies = self.work / "renamed"
        copies.mkdir()
        for original, name in zip(self.inputs["exec"], ("other-original", "other-sidecar")):
            shutil.copyfile(original, copies / name)
        self.check("different selected spellings retain byte association",
                   EVIDENCE.verify_selection(self.baseline / "index.json", "test", "exec",
                       copies / "other-original", copies / "other-sidecar")["strict"]["compilers"] > 0)

    def schema_controls(self):
        path = self.work / "json-control"
        cases = {
            "duplicate decoded key": b'{"a":1,"\\u0061":2}',
            "UTF8 BOM": b'\xef\xbb\xbf{}', "invalid UTF8": b'"\xff"',
            "unpaired surrogate": b'"\\ud800"', "decimal": b'1.0',
            "nonfinite": b'NaN', "unsigned overflow": b'18446744073709551616',
            "signed underflow": b'-9223372036854775809', "depth": b'[' * 9 + b'0' + b']' * 9,
            "long string": b'"' + b'a' * 65537 + b'"',
            "too many values": b'[' + b'0,' * 262144 + b'0]',
            "raw control": b'"a\x01b"', "invalid escape": b'"\\x00"',
            "trailing token": b'{}{}', "truncated": b'{"x":',
        }
        for label, raw in cases.items():
            path.write_bytes(raw)
            self.reject("JSON " + label, lambda: EVIDENCE.read_json(path))
        path.write_bytes(b'{"x":18446744073709551615,"y":-9223372036854775808}')
        self.check("unsigned address lexical boundary", EVIDENCE.read_json(path)["x"] == (1 << 64) - 1)
        for label, mutate in (
                ("boolean schema", lambda v: v.update(schemaVersion=True)),
                ("unknown key", lambda v: v.update(other=1)),
                ("missing key", lambda v: v.pop("target")),
                ("wrong target", lambda v: v.update(target="other")),
                ("missing role", lambda v: v["captures"].pop("pie")),
                ("path traversal", lambda v: v["captures"]["exec"].update(path="../outside")),
                ("role swap", lambda v: v["captures"].update(exec=v["captures"]["pie"])),
                ("boolean length", lambda v: v["toolset"].update(bytes=True))):
            root = self.clone("schema-" + label.replace(" ", "-"))
            value = load(root / "index.json")
            mutate(value)
            write_json(root / "index.json", value)
            self.reject(label, lambda: self.read(root))

    def output_controls(self):
        # trusted_parser loads a fresh class each time; its precise module/name is
        # checked below rather than treating every arbitrary exception as rejection.
        def rejected(label, root):
            try:
                self.read(root)
            except Exception as failure:
                self.check(label, isinstance(failure, (EVIDENCE.EvidenceError, OSError, UnicodeError)) or
                           (type(failure).__name__ == "ValidationFailure" and
                            type(failure).__module__ == "forge_strict_validator"))
                return
            raise AssertionError(label + ": unexpectedly accepted")

        for label, name, change in (
                ("LLVM empty", "llvm.stdout", lambda text: ""),
                ("LLVM truncated", "llvm.stdout", lambda text: text.replace("No errors.", "")),
                ("LLVM selected filename", "llvm.stdout", lambda text: text.replace("Verifying ", "Verifying wrong", 1)),
                ("LLVM diagnostic", "llvm.stdout", lambda text: text + "warning: controlled\n"),
                ("LLVM stderr", "llvm.stderr", lambda text: "controlled stderr\n"),
                ("strict empty", "dwarfdump.txt", lambda text: ""),
                ("strict category missing", "dwarfdump.txt", lambda text: "\n".join(
                    line for line in text.splitlines() if not line.strip().startswith("locations "))),
                ("strict tail missing", "dwarfdump.txt", lambda text: text.rsplit("Number of TAG records", 1)[0]),
                ("strict diagnostic", "dwarfdump.txt", lambda text: text + "error: controlled\n"),
                ("strict stderr", "dwarfdump.txt.stderr", lambda text: "controlled\n"),
                ("runner stderr", "strict-runner.stderr", lambda text: "controlled\n"),
                ("runner completion", "strict-runner.stdout", lambda text: text + "extra\n")):
            root = self.clone("output-" + label.replace(" ", "-"))
            path = root / "cases/exec" / name
            path.write_text(change(path.read_text()), encoding="utf-8")
            self.refresh(root, role="exec")
            rejected(label, root)
        for label, mutate in (
                ("signal exit", lambda v: v["invocations"]["llvm"].update(exitStatus=-9)),
                ("boolean exit", lambda v: v["invocations"]["strict"].update(exitStatus=True)),
                ("pair changed input", lambda v: v["inputs"]["original"]["after"].update(mtime_ns=0)),
                ("strict unknown summary", lambda v: v["strictSummary"].update(extra=0)),
                ("wrong checker invocation", lambda v: v["invocations"]["strict"]["argv"].__setitem__(6, "--other")),
                ("false LLVM boolean", lambda v: v["llvmSummary"].update(complete=1))):
            root = self.clone("receipt-" + label.replace(" ", "-"))
            path = root / "cases/exec/receipt.json"
            value = load(path)
            mutate(value)
            write_json(path, value)
            self.refresh(root)
            rejected(label, root)
        for label, name, change in (
                ("LLVM version marker", "llvmVersion.stdout", "unrecognized version\n"),
                ("GNU version marker", "dwarfdumpVersion.stdout", "wrong version\n"),
                ("version stderr", "llvmVersion.stderr", "warning\n"),
                ("parser policy changed", "sources/check-dwarfdump.py", "# not current source\n"),
                ("capture policy changed", "sources/validation-evidence.py", "# not current source\n")):
            root = self.clone("tool-" + label.replace(" ", "-"))
            (root / "tools" / name).write_text(change, encoding="utf-8")
            self.refresh(root, tools=True)
            rejected(label, root)
        root = self.clone("tool-launcher-spelling")
        path = root / "tools/toolset.json"
        value = load(path)
        value["invocations"]["dwarfdumpVersion"]["argv"][0] = "/unrelated/dwarfdump"
        write_json(path, value)
        self.refresh(root, tools=True)
        rejected("recorded launcher confinement", root)

    def inherited_controls(self):
        parser = EVIDENCE.trusted_parser()
        base_metadata = load(self.baseline / "cases/exec/dwarfdump.txt.check.json")
        self.check("real inherited frame diagnostics present", base_metadata["reported_errors"] >= 2 and
                   base_metadata["inherited_frame_evidence"]["diagnostics"])
        root = self.clone("frame-same-count-different-message")
        path = root / "cases/exec/dwarfdump.txt.original.txt"
        raw = path.read_text()
        altered = re.sub(r"offset 0x[0-9a-f]+\.", "offset 0xdeadbeef.", raw, count=1)
        self.check("frame offset control changes actual message", altered != raw)
        path.write_text(altered)
        self.refresh(root, role="exec")
        try:
            self.read(root)
        except Exception as failure:
            self.check("same count different inherited offset rejected", type(failure).__name__ ==
                       "ValidationFailure" and "uncorroborated inherited" in str(failure))
        else:
            raise AssertionError("different original diagnostic accepted")

        # Controlled unsigned receipt: do not claim these changed files were run
        # through validators. Exercise the reader's full uint64 address domain and
        # its independent frame-byte check after every claimed SHA is rewritten.
        root = self.clone("frame-high-address")
        copied = self.work / "frame-high-inputs"
        copied.mkdir()
        paths = []
        frame_payload_offset = None
        for index, source in enumerate(self.inputs["exec"]):
            raw = bytearray(source.read_bytes())
            self.check("frame control compiler ELF64 little endian", raw[4:6] == b"\x02\x01")
            offset = struct.unpack_from("<Q", raw, 40)[0]
            width, count, names_index = struct.unpack_from("<HHH", raw, 58)
            rows = [struct.unpack_from("<IIQQQQIIQQ", raw, offset + i * width) for i in range(count)]
            names = raw[rows[names_index][4]:rows[names_index][4] + rows[names_index][5]]
            frame = next(i for i, row in enumerate(rows) if names[row[0]:].split(b"\0", 1)[0] == b".eh_frame")
            struct.pack_into("<Q", raw, offset + frame * width + 16, (1 << 63) + 0x1234)
            frame_payload_offset = rows[frame][4]
            path = copied / str(index)
            path.write_bytes(raw)
            paths.append(path)
        metadata_path = root / "cases/exec/dwarfdump.txt.check.json"
        metadata = load(metadata_path)
        metadata["inherited_frame_evidence"]["identity"]["section_address"] = (1 << 63) + 0x1234
        write_json(metadata_path, metadata)
        receipt_path = root / "cases/exec/receipt.json"
        receipt = load(receipt_path)
        for kind, path in zip(("original", "sidecar"), paths):
            receipt["inputs"][kind]["before"] = EVIDENCE.snapshot(path)
            receipt["inputs"][kind]["after"] = EVIDENCE.snapshot(path)
        write_json(receipt_path, receipt)
        self.refresh(root, role="exec")
        self.check("high-bit frame address accepted as uint64", EVIDENCE.verify_selection(
            root / "index.json", "test", "exec", *paths)["strict"]["reported_errors"] >= 2)
        raw = bytearray(paths[0].read_bytes())
        raw[frame_payload_offset] ^= 1
        paths[0].write_bytes(raw)
        receipt = load(receipt_path)
        receipt["inputs"]["original"]["before"] = EVIDENCE.snapshot(paths[0])
        receipt["inputs"]["original"]["after"] = EVIDENCE.snapshot(paths[0])
        write_json(receipt_path, receipt)
        self.refresh(root)
        self.check("index alone does not assert actual frame bytes", self.read(root)["captures"]["exec"]["frameIdentity"] is not None)
        self.reject("rewritten SHA cannot replace actual frame proof", lambda: EVIDENCE.verify_selection(
            root / "index.json", "test", "exec", *paths), message="frame identity/bytes differ")

    def capacity_control(self):
        parser = EVIDENCE.trusted_parser()
        root = self.clone("capacity-65536")
        case = root / "cases/exec"
        metadata_path = case / "dwarfdump.txt.check.json"
        metadata = load(metadata_path)
        message = metadata["inherited_frame_evidence"]["diagnostics"][0]
        messages = [message] * 65536
        categories = sorted(parser.COMMON_CHECK_CATEGORIES | {"function_coverage"})
        rows = [name + " " + str(65536 if name == "harmless_errors" else 1) + " " +
                str(65536 if name == "harmless_errors" else 0) for name in categories]
        table = ("DWARF CHECK RESULT\n<item> <checks> <errors>\n" + "\n".join(rows) +
                 "\n** Summarize ** " + str(65536 + len(categories) - 1) + " 65536\n")
        raw = ("\n".join(messages) + "\nHARMLESS ERROR COUNT: 65536\n1 Compilers detected:\n" +
               "1 Compilers verified:\n*** ERRORS PER COMPILER ***\n1: errors = 65536, controlled\n" +
               table + "*** TOTAL ERRORS FOR ALL COMPILERS ***\n" + table +
               "Number of TAG records 1\nNumber of distinct TAGs in object 1\n" +
               "[ 1] 0x11 DW_TAG_compile_unit 1 100.0\n")
        summary = parser.validate_output(raw, messages)
        for suffix in ("dwarfdump.txt", "dwarfdump.txt.original.txt"):
            (case / suffix).write_text(raw)
        metadata.update(summary)
        metadata["inherited_frame_evidence"]["diagnostics"] = messages
        write_json(metadata_path, metadata)
        receipt_path = case / "receipt.json"
        receipt = load(receipt_path)
        receipt["strictSummary"] = summary
        write_json(receipt_path, receipt)
        old_log = receipt["invocations"]["strict"]["argv"][3]
        (case / "strict-runner.stdout").write_text("strict-dwarfdump=PASS reported-errors=65536 " +
            "corroborated-frame-errors=65536 log=" + old_log + "\n")
        self.refresh(root, role="exec")
        self.check("65536 complete retained messages fit all reader limits",
                   self.read(root)["captures"]["exec"]["strict"]["reported_errors"] == 65536)
        if self.arguments.capacity_replay is not None:
            raw_path = self.arguments.capacity_replay
            paths = [raw_path, Path(str(raw_path) + ".original.txt"), Path(str(raw_path) + ".check.json")]
            before = {str(path): EVIDENCE.snapshot(path) for path in paths}
            value = EVIDENCE.read_json(paths[2], EVIDENCE.LARGE_FILE)
            inherited = value["inherited_frame_evidence"]["diagnostics"]
            for path, original in ((paths[0], False), (paths[1], True)):
                summary = parser.validate_output(EVIDENCE.read_text(path, EVIDENCE.LARGE_FILE),
                                                 inherited, original=original)
                self.check("actual retained capacity complete " + str(original), summary["reported_errors"] == 65536)
            self.check("actual capacity corpus unchanged", before == {str(path): EVIDENCE.snapshot(path) for path in paths})
            write_json(self.work / "retained-capacity.json", before)

    def capture_failure_controls(self):
        baseline_case = self.baseline / "cases/exec"
        baseline_receipt = load(baseline_case / "receipt.json")
        baseline_old_log = baseline_receipt["invocations"]["strict"]["argv"][3]

        def replay(command, stdout, stderr, environment):
            command = list(map(str, command))
            case = Path(stdout).parent
            if command[1] == "--verify":
                text = (baseline_case / "llvm.stdout").read_text().replace(
                    str(self.inputs["exec"][1]), command[2])
                Path(stdout).write_text(text)
                Path(stderr).write_bytes(b"")
            else:
                replacements = {baseline_old_log: str(case / "dwarfdump.txt"),
                    str(self.inputs["exec"][1]): command[2], str(self.inputs["exec"][0]): command[7]}
                for source in baseline_case.iterdir():
                    if not source.name.startswith("dwarfdump.txt"):
                        continue
                    text = source.read_text()
                    for old, new in replacements.items():
                        text = text.replace(old, new)
                    (case / source.name).write_text(text)
                text = (baseline_case / "strict-runner.stdout").read_text().replace(
                    baseline_old_log, str(case / "dwarfdump.txt"))
                Path(stdout).write_text(text)
                Path(stderr).write_bytes(b"")
            return {"argv": command, "cwd": str(Path.cwd()), "environment": environment, "exitStatus": 0}

        for phase in ("between", "after"):
            parent = self.work / ("changed-" + phase)
            parent.mkdir()
            paths = [parent / name for name in ("original", "sidecar")]
            for source, destination in zip(self.inputs["exec"], paths):
                shutil.copyfile(source, destination)
            calls = []
            def changed(command, stdout, stderr, environment):
                record = replay(command, stdout, stderr, environment)
                calls.append(command)
                if len(calls) == (1 if phase == "between" else 2):
                    with paths[0].open("ab") as output:
                        output.write(b"controlled change")
                return record
            with patch.object(EVIDENCE, "run_recorded", changed):
                self.reject("input change " + phase + " validator pair", lambda: EVIDENCE.capture(
                    *paths, self.baseline / "tools/toolset.json", parent / "case"), message="input changed")
            self.check("changed " + phase + " never publishes receipt", len(calls) == 2 and
                       not (parent / "case/receipt.json").exists() and (parent / "case/failure.json").is_file())

        marker = RuntimeError("controlled parse failure")
        cleanup = OSError("controlled unlink failure")
        original_unlink = Path.unlink
        def failed_unlink(path, *args, **kwargs):
            if path.name == "checking.json":
                raise cleanup
            return original_unlink(path, *args, **kwargs)
        destination = self.work / "parse-cleanup-failure"
        with patch.object(EVIDENCE, "run_recorded", replay), \
                patch.object(EVIDENCE, "parse_capture", side_effect=marker), patch.object(Path, "unlink", failed_unlink):
            failure = self.reject("parse primary survives cleanup", lambda: EVIDENCE.capture(
                *self.inputs["exec"], self.baseline / "tools/toolset.json", destination), RuntimeError)
        self.check("cleanup failure retained on exact primary", failure is marker and
                   any("controlled unlink failure" in note for note in failure.__notes__) and
                   not (destination / "receipt.json").exists() and (destination / "checking.json").exists())
        destination = self.work / "capture-no-runtime-replay"
        with patch.object(EVIDENCE, "run_recorded", replay):
            self.check("replay success control reaches publication", EVIDENCE.capture(*self.inputs["exec"],
                self.baseline / "tools/toolset.json", destination).is_file())

    def filesystem_controls(self):
        for label, relative in (("cross-role hardlink", "cases/pie/llvm.stderr"),
                                ("case-tool hardlink", "tools/llvmVersion.stderr")):
            root = self.clone(label.replace(" ", "-"))
            path = root / relative
            path.unlink()
            os.link(root / "cases/exec/llvm.stderr", path)
            self.reject(label, lambda: self.read(root), message="alias")
        root = self.clone("retained-symlink")
        path = root / "cases/exec/llvm.stderr"
        path.unlink()
        path.symlink_to(self.baseline / "cases/exec/llvm.stderr")
        self.reject("retained leaf symlink", lambda: self.read(root))
        directory = self.work / "tree"
        directory.mkdir()
        (directory / "link").symlink_to(self.baseline / "tools", target_is_directory=True)
        self.reject("tree symlink directory", lambda: EVIDENCE.tree_files(directory))
        (directory / "link").unlink()
        for index in range(65):
            (directory / str(index)).write_bytes(b"")
        self.reject("tree file bound", lambda: EVIDENCE.tree_files(directory))
        fifo = self.work / "fifo"
        os.mkfifo(fifo)
        self.reject("FIFO rejected without opening", lambda: EVIDENCE.read_json(fifo))
        temporary = self.work / "publish.json.tmp"
        temporary.write_bytes(b"owned by someone else")
        before = EVIDENCE.snapshot(temporary)
        self.reject("preexisting temporary rejected", lambda: EVIDENCE.publish(
            self.work / "publish.json", {}), FileExistsError)
        self.check("preexisting temporary preserved", EVIDENCE.snapshot(temporary) == before)
        before = EVIDENCE.snapshot(self.baseline / "cases/exec/receipt.json")
        with patch.object(EVIDENCE, "run_recorded", side_effect=AssertionError("must not invoke")):
            self.reject("capture destination reuse", lambda: EVIDENCE.capture(*self.inputs["exec"],
                self.baseline / "tools/toolset.json", self.baseline / "cases/exec"), FileExistsError)
            self.reject("original sidecar inode alias", lambda: EVIDENCE.capture(
                self.inputs["exec"][0], self.inputs["exec"][0], self.baseline / "tools/toolset.json",
                self.work / "alias-output"))
        self.check("capture reuse leaves receipt exact",
                   EVIDENCE.snapshot(self.baseline / "cases/exec/receipt.json") == before)
        self.check("alias creates no output", not (self.work / "alias-output").exists())
        self.reject("different selected role bytes", lambda: EVIDENCE.verify_selection(
            self.baseline / "index.json", "test", "exec", *self.inputs["pie"]))
        mutated = self.work / "changed-sidecar"
        shutil.copyfile(self.inputs["exec"][1], mutated)
        with mutated.open("ab") as stream:
            stream.write(b"changed")
        self.reject("changed selected bytes", lambda: EVIDENCE.verify_selection(
            self.baseline / "index.json", "test", "exec", self.inputs["exec"][0], mutated))

    def bounded_io_controls(self):
        path = self.work / "bounded"
        path.write_bytes(b"small")
        original_open = Path.open
        class Tracked(io.BytesIO):
            closed_flag = False
            def close(stream):
                stream.closed_flag = True
                super().close()
        stream = Tracked(b"a" * 10)
        def opening(selected, *args, **kwargs):
            return stream if selected == path and args == ("rb",) else original_open(selected, *args, **kwargs)
        with patch.object(Path, "open", opening):
            self.reject("growth bounded on actual reread", lambda: EVIDENCE.read_bytes(path, 5))
        self.check("growing reread closed", stream.closed_flag)
        stream = Tracked(b"a" * 10)
        destination = self.work / "bounded-copy"
        with patch.object(Path, "open", opening):
            self.reject("copy growth bounded", lambda: EVIDENCE.copy_exact(path, destination, 5))
        self.check("growing copy closed and no excess written", stream.closed_flag and destination.stat().st_size <= 5)
        state = EVIDENCE.snapshot(path)
        path.write_bytes(b"larger")
        self.reject("final rehash retains observed bound", lambda: EVIDENCE.unchanged({str(path): state}),
                    message="exceeds evidence limit")
        manifest = self.work / "oversized-manifest"
        manifest.mkdir()
        (manifest / "SHA256SUMS").write_text("".join("0" * 64 + "  ./" + str(i) + "\n" for i in range(64)))
        calls = []
        def fake_snapshot(selected, *args, **kwargs):
            calls.append(str(selected))
            return {"sha256": "0" * 64, "bytes": 0, "mtime_ns": 0}
        for i in range(64):
            (manifest / str(i)).write_bytes(b"")
        with patch.object(EVIDENCE, "snapshot", fake_snapshot):
            self.reject("manifest count before next hash", lambda: EVIDENCE.manifest_files(manifest))
        self.check("manifest did not hash forbidden 64th entry", len(calls) == 63)
        total = self.work / "oversized-total"
        total.mkdir()
        (total / "SHA256SUMS").write_text("".join("0" * 64 + "  ./" + name + "\n" for name in ("one", "two", "three")))
        for name in ("one", "two", "three"):
            with (total / name).open("wb") as output:
                output.truncate(EVIDENCE.TOOL_FILE)
        calls.clear()
        with patch.object(EVIDENCE, "snapshot", fake_snapshot):
            self.reject("manifest total before excess hash", lambda: EVIDENCE.manifest_files(total))
        self.check("aggregate does not hash third over-limit file", len(calls) == 2)
        write_json(total / "recipe.json", {"status": "PASS", "construction": "three owned sparse zero files",
            "file_sizes": {name: (total / name).stat().st_size for name in ("one", "two", "three")},
            "mock_hash_calls": calls, "expected_hash_calls": 2,
            "scope": "Individually allowed sizes; running total rejects the third before hashing. No payload claim."})
        for name in ("one", "two", "three"):
            (total / name).unlink()
        self.check("size-only sparse fixtures cleaned", all(not (total / name).exists() for name in ("one", "two", "three")))

    def finish(self):
        self.check("all compiled inputs preserved", self.before == {
            str(path): EVIDENCE.snapshot(path) for paths in self.inputs.values() for path in paths})
        write_json(self.work / "result.json", {"status": "PASS", "controls": len(self.passed),
            "passed": self.passed, "source": EVIDENCE.snapshot(HERE / "validation-evidence.py"),
            "test": EVIDENCE.snapshot(Path(__file__)), "inputs": self.before,
            "scope": "Focused captures/readers; no Ghidra/GDB/inferior execution or product validation attestation."})
        print("validation-evidence-controls=PASS count=" + str(len(self.passed)) + " result=" + str(self.work))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--llvm", type=Path, required=True)
    parser.add_argument("--llvm-notices", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capacity-replay", type=Path,
                        help="optional retained native 65536-message stdout; reader replay only")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    controls = Controls(args)
    try:
        controls.initialize()
        controls.schema_controls()
        controls.output_controls()
        controls.inherited_controls()
        controls.capacity_control()
        controls.filesystem_controls()
        controls.bounded_io_controls()
        controls.capture_failure_controls()
        controls.finish()
    except BaseException as failure:
        write_json(controls.work / "failure.json", {"status": "FAILED", "exception": type(failure).__name__,
            "message": str(failure), "passed": controls.passed})
        print("validation-evidence-controls=FAILED result=" + str(controls.work), flush=True)
        raise


if __name__ == "__main__":
    main()
