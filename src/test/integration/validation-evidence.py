#!/usr/bin/env python3
"""Capture existing CI validator calls and bind their retained evidence to selections.

This is an unsigned test-harness observation, not a product supervisor, immutable
snapshot, authenticated receipt, source proof or attachment approval. No command
is executed by either public verification function. Report NOT_RUN stays intact.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROLES = ("exec", "pie", "exec.no-build-id")
SMALL_JSON = 2 * 1024 * 1024
LARGE_FILE = 64 * 1024 * 1024
CASE_TOTAL = 512 * 1024 * 1024
TOOL_FILE = 128 * 1024 * 1024
TOOL_TOTAL = 256 * 1024 * 1024
PINS = {
    "sourceCommit": "af7b278c6aa2ae9daad94fb7f8bffdc0e9980993",
    "sourceArchiveSha256": "7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd",
    "checkerPatchSha256": "69340f63ee78c06309731a40bb1e0e9e193b5d2f659e5f050ef413138649f696",
    "readerPatchSha256": "8468426396e6a28f755077681eec78d326744a535c7aade9d17d9a1acef73b46",
    "diagnosticPatchSha256": "e9f7eb0e613b4a4e859377ad12563ad514d24f7ee81b04378a30b8e99e403139",
    "callingConventionPatchSha256": "a1b5cc6d63795aeda62b5945bf8991360882c7334003e9912e274638ec073581",
    "configurationSha256": "842bba9230de82059dfcef1485114cf3c33eae8be2973c649d176f4ad18972ef",
}
PIN_FILES = {
    "source/libdwarf-2.3.2.tar.xz": "sourceArchiveSha256",
    "source/support/validation/0001-check-line-sequences.patch": "checkerPatchSha256",
    "source/support/validation/0002-accept-bounded-extended-program-count.patch": "readerPatchSha256",
    "source/support/validation/0003-preserve-bounded-harmless-diagnostics.patch": "diagnosticPatchSha256",
    "source/support/validation/0004-recognize-subroutine-calling-convention.patch": "callingConventionPatchSha256",
    "share/dwarfdump/dwarfdump.conf": "configurationSha256",
}
PROFILE = "libdwarf-2.3.2-four-corrections-and-llvm-verify"


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def exact(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), label + " fields differ")


def integer(value, label, signed=False):
    require(type(value) is int and (-(1 << 63) if signed else 0) <= value < (1 << 63),
            "invalid integer: " + label)
    return value


def text(value, label, empty=False):
    require(isinstance(value, str) and (empty or bool(value)) and "\0" not in value and
            len(value.encode("utf-16-le", errors="strict")) // 2 <= 65536, "invalid text: " + label)
    return value


def path_text(value):
    text(value, "path")
    require(len(value.encode("utf-16-le")) // 2 <= 16384, "path exceeds bound")
    return value


def regular(path, retained=False):
    path = Path(path)
    mode = path.lstat().st_mode if retained else path.stat().st_mode
    require(stat.S_ISREG(mode), "not a regular file: " + str(path))
    return path


def snapshot(path, limit=None, retained=False):
    path = regular(path, retained)
    before = path.stat()
    if limit is not None:
        require(before.st_size <= limit, "file exceeds evidence limit: " + str(path))
    digest, count = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while block := stream.read(65536):
            count += len(block)
            require(limit is None or count <= limit, "file exceeds evidence limit: " + str(path))
            digest.update(block)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns) and
            count == after.st_size, "file changed while hashing: " + str(path))
    return {"sha256": digest.hexdigest(), "bytes": count, "mtime_ns": after.st_mtime_ns}


def read_bytes(path, limit):
    regular(path, retained=True)
    require(Path(path).stat().st_size <= limit, "read exceeds evidence limit: " + str(path))
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "growing file exceeds evidence limit: " + str(path))
    return data


def read_text(path, limit):
    return read_bytes(path, limit).decode("utf-8", errors="strict")


def copy_exact(source, destination, expected):
    count = 0
    with Path(destination).open("xb") as output, Path(source).open("rb") as stream:
        while data := stream.read(min(65536, expected - count + 1)):
            count += len(data)
            require(count <= expected, "source grew during bounded retention")
            output.write(data)
    require(count == expected, "source shrank during bounded retention")


def file_record(root, path, limit):
    value = snapshot(path, limit, retained=True)
    return {"path": str(Path(path).relative_to(root)), "sha256": value["sha256"], "bytes": value["bytes"]}


def fingerprint(value, time=False):
    exact(value, ("sha256", "bytes", "mtime_ns") if time else ("sha256", "bytes"), "fingerprint")
    require(isinstance(value["sha256"], str) and re.fullmatch("[0-9a-f]{64}", value["sha256"]), "invalid SHA256")
    integer(value["bytes"], "bytes")
    if time:
        integer(value["mtime_ns"], "mtime_ns", signed=True)


def same_bytes(left, right):
    return all(left[key] == right[key] for key in ("sha256", "bytes"))


def confined(root, spelling):
    path_text(spelling)
    part = Path(spelling)
    require(not part.is_absolute() and part.parts and all(p not in (".", "..") for p in part.parts)
            and str(part) == spelling, "noncanonical relative evidence path")
    root = Path(root).resolve(strict=True)
    result = root / part
    current = root
    for component in part.parts:
        current /= component
        require(not current.is_symlink(), "symlink in retained evidence: " + str(current))
    require(result.resolve(strict=True).is_relative_to(root), "evidence escapes root")
    return regular(result, retained=True)


def json_depth(data):
    """Bound depth, token count and decoded string units before JSON materialization."""
    position, depth, tokens = 0, 0, 0
    while position < len(data):
        character = data[position]
        position += 1
        if character in " \t\r\n,:]}" :
            if character in "]}":
                depth -= 1
                require(depth >= 0, "invalid JSON nesting")
            continue
        tokens += 1
        require(tokens <= 262144, "JSON value count exceeds bound")
        if character in "[{":
            depth += 1
            require(depth <= 8, "JSON nesting exceeds bound")
        elif character == '"':
            units = 0
            while True:
                require(position < len(data), "unterminated JSON string")
                character = data[position]
                position += 1
                if character == '"':
                    break
                require(ord(character) >= 32, "raw JSON string control")
                if character == "\\":
                    require(position < len(data), "incomplete JSON escape")
                    escape = data[position]
                    position += 1
                    if escape == "u":
                        require(position + 4 <= len(data) and
                                re.fullmatch("[0-9a-fA-F]{4}", data[position:position + 4]),
                                "invalid JSON Unicode escape")
                        position += 4
                    else:
                        require(escape in '\"\\/bfnrt', "invalid JSON escape")
                    units += 1
                else:
                    units += 2 if ord(character) > 65535 else 1
                require(units <= 65536, "JSON string exceeds bound")
        else:
            while position < len(data) and data[position] not in " \t\r\n,:{}[]\"":
                position += 1
    require(depth == 0, "incomplete JSON framing")


def read_json(path, limit=SMALL_JSON):
    regular(path, retained=True)
    require(Path(path).stat().st_size <= limit, "JSON exceeds byte limit")
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit and not raw.startswith(b"\xef\xbb\xbf"), "oversized/BOM JSON")
    decoded = raw.decode("utf-8", errors="strict")
    json_depth(decoded)

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def number(value):
        require(re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value) and len(value) <= 20, "invalid integer lexeme")
        parsed = int(value)
        require(-(1 << 63) <= parsed < (1 << 64), "JSON integer exceeds 64-bit range")
        return parsed

    def forbidden(value):
        raise EvidenceError("noninteger JSON number: " + value)

    value = json.loads(decoded, object_pairs_hook=pairs, parse_int=number,
                       parse_float=forbidden, parse_constant=forbidden)
    todo, count = [value], 0
    while todo:
        item = todo.pop()
        count += 1
        require(count <= 262144, "JSON value count exceeds bound")
        if isinstance(item, dict):
            todo.extend(element for pair in item.items() for element in pair)
        elif isinstance(item, list):
            todo.extend(item)
        elif isinstance(item, str):
            # UTF-16 encoding also rejects unpaired decoded surrogates.
            require(len(item.encode("utf-16-le", errors="strict")) // 2 <= 65536, "JSON string exceeds bound")
    return value


def publish(path, value):
    path = Path(path)
    require(not path.exists() and not path.is_symlink(), "evidence destination already exists: " + str(path))
    temporary = path.with_name(path.name + ".tmp")
    owned = False
    try:
        stream = temporary.open("xb")
        owned = True
        with stream:
            stream.write((json.dumps(value, ensure_ascii=True, indent=4) + "\n").encode("utf-8"))
        # The containing directory is freshly owned; no concurrent-writer promise.
        require(not path.exists() and not path.is_symlink(), "evidence destination appeared")
        temporary.rename(path)
    except BaseException as failure:
        if owned:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as cleanup:
                failure.add_note("evidence temporary cleanup failed: " + repr(cleanup))
        raise


def new_directory(path):
    path = Path(path).absolute()
    require(path.name not in ("", ".", ".."), "invalid evidence directory leaf")
    parent = path.parent.resolve(strict=True)
    require(parent.is_dir(), "evidence parent is not a directory")
    path = parent / path.name
    path.mkdir(mode=0o700)
    return path


def trusted_parser():
    path = HERE / "check-dwarfdump.py"
    spec = importlib.util.spec_from_file_location("forge_strict_validator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tree_files(root):
    """Bound traversal itself, rejecting links/special entries before following any."""
    root = Path(root)
    pending, found, identities, entries = [root], set(), set(), 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as children:
            for entry in children:
                entries += 1
                require(entries <= 128, "retained tree entry count exceeds bound")
                info = entry.stat(follow_symlinks=False)
                path = Path(entry.path)
                require(not stat.S_ISLNK(info.st_mode), "symlink in retained tree")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                else:
                    require(stat.S_ISREG(info.st_mode), "special file in retained tree")
                    identity = (info.st_dev, info.st_ino)
                    require(identity not in identities, "retained tree files alias")
                    identities.add(identity)
                    found.add(str(path.relative_to(root)))
                    require(len(found) <= 64, "retained tree file count exceeds bound")
    return found


def manifest_files(bundle):
    manifest = regular(bundle / "SHA256SUMS", retained=True)
    require(manifest.stat().st_size <= SMALL_JSON, "bundle manifest exceeds limit")
    expected, declared_total = {}, 0
    for line in read_text(manifest, SMALL_JSON).splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", line)
        require(match is not None and match[2] not in expected, "malformed/duplicate bundle manifest")
        require(len(expected) < 63, "bundle inventory exceeds bound")
        path = confined(bundle, match[2])
        declared_total += path.stat().st_size
        require(declared_total <= TOOL_TOTAL, "bundle total exceeds bound")
        observed = snapshot(path, TOOL_FILE, retained=True)
        require(observed["sha256"] == match[1], "bundle manifest hash differs")
        expected[match[2]] = observed
    require(0 < len(expected) <= 63, "bundle inventory exceeds bound")
    actual = tree_files(bundle)
    require(actual == set(expected) | {"SHA256SUMS"}, "bundle inventory differs from manifest")
    for name, key in PIN_FILES.items():
        require(name in expected and expected[name]["sha256"] == PINS[key], "bundle source/configuration pin differs")
    metadata = read_text(bundle / "BUILD-METADATA.txt", SMALL_JSON)
    require("source-commit=" + PINS["sourceCommit"] in metadata and "producer-patch=not-applied" in metadata,
            "bundle is not the pinned validation-only consumer")
    expected["SHA256SUMS"] = snapshot(manifest, SMALL_JSON, retained=True)
    require(sum(value["bytes"] for value in expected.values()) <= TOOL_TOTAL, "bundle total exceeds bound")
    return expected


def version_output(path, label):
    snapshot(path, 65536, retained=True)
    value = read_text(path, 65536)
    pattern = (r"(?m)^(?:Ubuntu )?LLVM version [0-9][^\n]*$" if label == "llvmVersion"
               else r"\(libdwarf 2\.3\.2 dwarfdump 2\.3\.2\)")
    require(re.search(pattern, value) is not None and
            re.search(r"(?i)\b(?:warning|error|fatal):", value) is None, "unexpected tool version output")


def run_recorded(command, stdout, stderr, environment):
    with Path(stdout).open("xb") as output, Path(stderr).open("xb") as errors:
        result = subprocess.run(list(map(str, command)), stdout=output, stderr=errors,
                                env={**os.environ, **environment}, check=False)
    return {"argv": list(map(str, command)), "cwd": str(Path.cwd()),
            "environment": environment, "exitStatus": result.returncode}


def create_tools(bundle, llvm, notices, output):
    bundle = Path(bundle).resolve(strict=True)
    inventory = manifest_files(bundle)
    llvm_argument = Path(llvm).absolute()
    llvm = regular(llvm_argument.resolve(strict=True))
    notices = regular(Path(notices).resolve(strict=True))
    selected = [*map(lambda name: bundle / name, inventory), llvm, notices,
                HERE / "check-dwarfdump.py", Path(__file__).resolve()]
    require(sum(regular(path).stat().st_size for path in selected) <= TOOL_TOTAL, "toolset total exceeds bound")
    before = {str(path): snapshot(path, TOOL_FILE) for path in selected}
    require(not Path(output).absolute().resolve(strict=False).is_relative_to(bundle),
            "toolset output cannot modify the source bundle")
    destination = new_directory(output)
    try:
        for name in inventory:
            target = destination / "dwarfdump" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            copy_exact(bundle / name, target, before[str(bundle / name)]["bytes"])
        for source, name in ((llvm, "llvm/llvm-dwarfdump"), (notices, "llvm/NOTICE"),
                (HERE / "check-dwarfdump.py", "sources/check-dwarfdump.py"),
                (Path(__file__).resolve(), "sources/validation-evidence.py")):
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            copy_exact(source, target, before[str(source)]["bytes"])
        for name in inventory:
            require(same_bytes(snapshot(destination / "dwarfdump" / name, TOOL_FILE), before[str(bundle / name)]),
                    "retained bundle copy differs")
        for source, name in ((llvm, "llvm/llvm-dwarfdump"), (notices, "llvm/NOTICE"),
                (HERE / "check-dwarfdump.py", "sources/check-dwarfdump.py"),
                (Path(__file__).resolve(), "sources/validation-evidence.py")):
            require(same_bytes(snapshot(destination / name, TOOL_FILE), before[str(source)]),
                    "retained tool/source copy differs")
        launcher = destination / "dwarfdump/bin/dwarfdump"
        launcher.chmod(0o755)
        (destination / "dwarfdump/libexec/dwarfdump").chmod(0o755)
        invocations = {}
        for label, command in (("llvmVersion", [llvm, "--version"]), ("dwarfdumpVersion", [launcher, "--version"])):
            invocation = run_recorded(command, destination / (label + ".stdout"),
                                      destination / (label + ".stderr"), {"LC_ALL": "C"})
            require(invocation["exitStatus"] == 0 and not read_bytes(destination / (label + ".stderr"), 0),
                    "tool version invocation failed")
            version_output(destination / (label + ".stdout"), label)
            invocations[label] = invocation
        require({str(path): snapshot(path, TOOL_FILE) for path in selected} == before,
                "tool sources changed during retention")
        files = [file_record(destination, destination / name, TOOL_FILE) for name in sorted(tree_files(destination))]
        require(len(files) <= 64 and sum(value["bytes"] for value in files) <= TOOL_TOTAL, "toolset exceeds limit")
        value = {"schemaVersion": 1, "kind": "FORGE_TEST_VALIDATION_TOOLSET", "profile": PROFILE,
            "retainedRoot": str(destination), "configured": {"llvm": str(llvm_argument), "llvmResolved": str(llvm), "llvmNotices": str(notices),
                           "bundle": str(bundle)}, "files": files, "invocations": invocations, "pins": PINS,
            "parserSha256": before[str(HERE / "check-dwarfdump.py")]["sha256"],
            "captureSha256": before[str(Path(__file__).resolve())]["sha256"]}
        publish(destination / "toolset.json", value)
        return destination / "toolset.json"
    except BaseException as failure:
        record_failure(destination, failure)
        raise


def record_failure(destination, failure):
    try:
        publish(Path(destination) / "failure.json", {"completion": "FAILED", "exception": type(failure).__name__,
            "diagnostic": str(failure), "scope": "No complete capture; retained files are failure evidence only."})
    except BaseException as recording:
        failure.add_note("failure evidence could not be written: " + repr(recording))


def verify_file_inventory(root, records, limit, total_limit, files):
    require(isinstance(records, list) and 0 < len(records) <= 64, "file inventory bound")
    found, identities, total = {}, set(), 0
    for record in records:
        exact(record, ("path", "sha256", "bytes"), "file record")
        fingerprint({key: record[key] for key in ("sha256", "bytes")})
        path = confined(root, record["path"])
        require(record["path"] not in found, "duplicate retained path")
        identity = (path.stat().st_dev, path.stat().st_ino)
        require(identity not in identities, "distinct retained files alias")
        identities.add(identity)
        require(total + path.stat().st_size <= total_limit, "evidence aggregate exceeds limit")
        observed = snapshot(path, limit, retained=True)
        require(same_bytes(observed, record), "retained file hash/length differs: " + str(path))
        total += observed["bytes"]
        require(total <= total_limit, "evidence aggregate exceeds limit")
        files[str(path)] = observed
        found[record["path"]] = path
    return found


def invocation(value):
    exact(value, ("argv", "cwd", "environment", "exitStatus"), "invocation")
    require(isinstance(value["argv"], list) and 0 < len(value["argv"]) <= 16, "argv bound")
    for argument in value["argv"]:
        path_text(argument)
    require(Path(path_text(value["cwd"])).is_absolute(), "invocation cwd is not absolute")
    require(value["environment"] == {"LC_ALL": "C"}, "unexpected explicit invocation environment")
    require(type(value["exitStatus"]) is int and value["exitStatus"] == 0, "invocation did not exit normally")


def verify_toolset(path, files):
    path = regular(Path(path), retained=True)
    value = read_json(path)
    exact(value, ("schemaVersion", "kind", "profile", "retainedRoot", "configured", "files", "invocations", "pins",
                  "parserSha256", "captureSha256"), "toolset")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and
            value["kind"] == "FORGE_TEST_VALIDATION_TOOLSET" and value["profile"] == PROFILE,
            "unsupported toolset schema/profile")
    require(value["pins"] == PINS, "validation source pins differ")
    old_root = Path(path_text(value["retainedRoot"]))
    require(old_root.is_absolute() and old_root.name == "tools", "invalid recorded retained tool root")
    exact(value["configured"], ("llvm", "llvmResolved", "llvmNotices", "bundle"), "configured tools")
    for spelling in value["configured"].values():
        require(Path(path_text(spelling)).is_absolute(), "configured tool path is not absolute")
    inventory = verify_file_inventory(path.parent, value["files"], TOOL_FILE, TOOL_TOTAL, files)
    expected = {"dwarfdump/" + name for name in manifest_files(path.parent / "dwarfdump")}
    expected |= {"llvm/llvm-dwarfdump", "llvm/NOTICE", "sources/check-dwarfdump.py", "sources/validation-evidence.py",
                 "llvmVersion.stdout", "llvmVersion.stderr", "dwarfdumpVersion.stdout", "dwarfdumpVersion.stderr"}
    require(set(inventory) == expected and tree_files(path.parent) == expected | {path.name},
            "unexpected toolset files")
    for field, source in (("parserSha256", "check-dwarfdump.py"), ("captureSha256", "validation-evidence.py")):
        source_state = snapshot(HERE / source, TOOL_FILE)
        files[str(HERE / source)] = source_state
        actual = source_state["sha256"]
        require(value[field] == actual == files[str(inventory["sources/" + source])]["sha256"],
                "retained parser/capture differs from trusted current source")
    exact(value["invocations"], ("llvmVersion", "dwarfdumpVersion"), "tool versions")
    for label, record in value["invocations"].items():
        invocation(record)
        require(not read_bytes(inventory[label + ".stderr"], 0), "tool version wrote stderr")
        require(record["argv"][-1] == "--version" and len(record["argv"]) == 2, "unexpected version arguments")
        version_output(inventory[label + ".stdout"], label)
    require(value["invocations"]["llvmVersion"]["argv"][0] == value["configured"]["llvmResolved"],
            "LLVM invoked spelling differs")
    require(value["invocations"]["dwarfdumpVersion"]["argv"][0] ==
            str(old_root / "dwarfdump/bin/dwarfdump"), "retained GNU launcher spelling differs")
    files[str(path)] = snapshot(path, SMALL_JSON, retained=True)
    return value


def input_observation(value):
    exact(value, ("path", "resolvedPath", "before", "after"), "input observation")
    for key in ("path", "resolvedPath"):
        require(Path(path_text(value[key])).is_absolute(), "selected input spelling is not absolute")
    fingerprint(value["before"], time=True)
    fingerprint(value["after"], time=True)
    require(value["before"] == value["after"], "input changed across the validation pair")


def llvm_output(raw, sidecar):
    lines = raw.decode("utf-8", errors="strict").splitlines()
    require(lines and lines[0].startswith("Verifying " + sidecar + ":") and
            "file format " in lines[0], "LLVM output is not associated with the selected sidecar")
    require(lines[-1] == "No errors." and lines.count("No errors.") == 1 and
            "Verifying .debug_info Unit Header Chain..." in lines and
            "Verifying .debug_abbrev..." in lines and "Verifying non-dwo Units..." in lines and
            "Verifying dwo Units..." in lines, "LLVM verification output is incomplete")
    require(not re.search(r"\b(?:warning|error|fatal):|Errors detected|malformed|corrupt", "\n".join(lines),
                          re.IGNORECASE), "LLVM reported a diagnostic")
    return {"exitStatus": 0, "complete": True, "diagnostics": 0}


def parse_capture(path, tools, toolset_state, files):
    path = regular(path, retained=True)
    value = read_json(path)
    exact(value, ("schemaVersion", "kind", "completion", "toolsetSha256", "inputs", "invocations",
                  "outputs", "strictSummary", "llvmSummary"), "capture")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and
            value["kind"] == "FORGE_TEST_VALIDATION_CAPTURE" and value["completion"] == "COMPLETE",
            "unsupported/incomplete validation capture")
    require(value["toolsetSha256"] == toolset_state["sha256"], "capture toolset differs")
    exact(value["inputs"], ("original", "sidecar"), "selected inputs")
    for item in value["inputs"].values():
        input_observation(item)
    require(value["inputs"]["original"]["resolvedPath"] != value["inputs"]["sidecar"]["resolvedPath"],
            "captured input roles alias")
    exact(value["invocations"], ("llvm", "strict"), "capture invocations")
    for item in value["invocations"].values():
        invocation(item)
    outputs = verify_file_inventory(path.parent, value["outputs"], LARGE_FILE, CASE_TOTAL, files)
    required = {"llvm.stdout", "llvm.stderr", "strict-runner.stdout", "strict-runner.stderr",
                "dwarfdump.txt", "dwarfdump.txt.stderr", "dwarfdump.txt.check.json"}
    require(required <= set(outputs), "capture output inventory incomplete")
    original, sidecar = value["inputs"]["original"], value["inputs"]["sidecar"]
    llvm = value["invocations"]["llvm"]
    require(llvm["argv"] == [tools["configured"]["llvmResolved"], "--verify", sidecar["path"]],
            "LLVM invocation differs from selected role")
    require(not read_bytes(outputs["llvm.stderr"], 0), "LLVM stderr is not empty")
    llvm_summary = llvm_output(read_bytes(outputs["llvm.stdout"], LARGE_FILE), sidecar["path"])
    require(value["llvmSummary"] == llvm_summary and all(type(value["llvmSummary"][k]) is type(v)
            for k, v in llvm_summary.items()), "LLVM summary differs")
    parser = trusted_parser()
    metadata = read_json(outputs["dwarfdump.txt.check.json"], LARGE_FILE)
    inherited = parser.frame_diagnostics(read_text(outputs["dwarfdump.txt"], LARGE_FILE))
    require(len(inherited) <= 65536, "inherited diagnostic capacity exceeded")
    base_keys = {"command", "cwd", "status", "exit_status", "stderr_log", "compilers", "check_tables",
                 "reported_errors", "uncorroborated_errors"}
    exact(metadata, base_keys | ({"original_check", "inherited_frame_evidence"} if inherited else set()),
          "strict metadata")
    strict = value["invocations"]["strict"]
    launcher = tools["invocations"]["dwarfdumpVersion"]["argv"][0]
    old_tool_root = Path(launcher).parents[2]
    require(len(strict["argv"]) == 8 and Path(strict["argv"][0]).is_absolute(), "unexpected strict runner")
    old_log = Path(strict["argv"][3])
    require(old_log.is_absolute() and old_log.name == "dwarfdump.txt", "unexpected strict output path")
    require(strict["argv"][1:] == [str(old_tool_root / "sources/check-dwarfdump.py"), sidecar["path"],
            str(old_log), "--tool", launcher, "--original", original["path"]], "strict runner arguments differ")
    require(metadata["command"] == [launcher, "--no-follow-debuglink", "-ka", "-ki", "-kd", sidecar["resolvedPath"]]
            and metadata["cwd"] == strict["cwd"] and metadata["status"] == "PASS" and
            type(metadata["exit_status"]) is int and metadata["exit_status"] == 0 and
            metadata["stderr_log"] == str(old_log) + ".stderr", "strict command/outcome differs")
    require(not read_bytes(outputs["strict-runner.stderr"], 0) and not read_bytes(outputs["dwarfdump.txt.stderr"], 0),
            "strict checker/runner stderr is not empty")
    if inherited:
        required |= {"dwarfdump.txt.original.txt", "dwarfdump.txt.original.txt.stderr"}
        require(required <= set(outputs), "original corroboration output missing")
        check = metadata["original_check"]
        exact(check, ("command", "log", "stderr_log", "exit_status"), "original invocation")
        require(check["command"] == [launcher, "--no-follow-debuglink", "-ka", "-ki", "-kd", original["resolvedPath"]]
                and check["log"] == str(old_log) + ".original.txt" and
                check["stderr_log"] == str(old_log) + ".original.txt.stderr" and
                type(check["exit_status"]) is int and check["exit_status"] == 0, "original command/outcome differs")
        require(not read_bytes(outputs["dwarfdump.txt.original.txt.stderr"], 0), "original checker stderr is not empty")
        proof = metadata["inherited_frame_evidence"]
        exact(proof, ("original", "identity", "diagnostics"), "inherited frame proof")
        require(proof["original"] == original["resolvedPath"] and proof["diagnostics"] == inherited,
                "inherited diagnostic messages differ")
        exact(proof["identity"], ("class", "byte_order", "os_abi", "abi_version", "machine", "flags",
              "section_address", "section_size", "section_sha256"), "frame identity")
        for key, item in proof["identity"].items():
            if key == "section_sha256":
                require(isinstance(item, str) and re.fullmatch("[0-9a-f]{64}", item), "invalid frame SHA")
            elif key == "section_address":
                require(type(item) is int and 0 <= item < (1 << 64), "invalid unsigned frame address")
            else:
                integer(item, "frame " + key)
        parser.validate_output(read_text(outputs["dwarfdump.txt.original.txt"], LARGE_FILE),
                               inherited, original=True)
    require(set(outputs) == required and tree_files(path.parent) == required | {path.name},
            "unexpected capture output")
    summary = parser.validate_output(read_text(outputs["dwarfdump.txt"], LARGE_FILE), inherited)
    for key, expected in summary.items():
        require(type(metadata[key]) is int and metadata[key] == expected, "strict summary differs")
    require(value["strictSummary"] == summary and all(type(value["strictSummary"][key]) is int for key in summary),
            "capture strict summary differs")
    expected_runner = ("strict-dwarfdump=PASS reported-errors=" + str(summary["reported_errors"]) +
        " corroborated-frame-errors=" + str(summary["reported_errors"]) + " log=" + str(old_log) + "\n")
    require(read_text(outputs["strict-runner.stdout"], LARGE_FILE) == expected_runner,
            "strict runner completion differs")
    files[str(path)] = snapshot(path, SMALL_JSON, retained=True)
    return {"inputs": value["inputs"], "strict": summary, "llvm": llvm_summary,
            "frameIdentity": metadata["inherited_frame_evidence"]["identity"] if inherited else None,
            "capture": {"path": str(path), "sha256": files[str(path)]["sha256"]}}


def _verify_index(index_path, target):
    index_path = regular(Path(index_path).resolve(strict=True), retained=True)
    files = {str(index_path): snapshot(index_path, SMALL_JSON, retained=True)}
    value = read_json(index_path)
    exact(value, ("schemaVersion", "kind", "target", "toolset", "captures"), "capture index")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and
            value["kind"] == "FORGE_TEST_VALIDATION_INDEX" and value["target"] == target and
            isinstance(target, str) and re.fullmatch(r"[a-z0-9_]{1,64}", target), "unsupported index/target")
    exact(value["captures"], ROLES, "capture roles")
    root = index_path.parent
    indexed = verify_file_inventory(root, [value["toolset"], *value["captures"].values()], SMALL_JSON,
                                    4 * SMALL_JSON, files)
    tool_path = root / value["toolset"]["path"]
    require(value["toolset"]["path"] == "tools/toolset.json", "unexpected shared toolset location")
    tools = verify_toolset(tool_path, files)
    captures = {}
    for role in ROLES:
        record = value["captures"][role]
        require(record["path"] == "cases/" + role + "/receipt.json", "capture role path differs")
        captures[role] = parse_capture(indexed[record["path"]], tools, files[str(tool_path)], files)
    distinct_entries(files)
    return {"index": {"path": str(index_path), "sha256": files[str(index_path)]["sha256"]},
            "target": target, "captures": captures, "files": files}


def distinct_entries(files):
    identities = {}
    for retained in files:
        identity = (Path(retained).stat().st_dev, Path(retained).stat().st_ino)
        require(identity not in identities or identities[identity] == retained,
                "distinct evidence entries alias across captures/toolset")
        identities[identity] = retained


def unchanged(files):
    require(all(snapshot(Path(path), state["bytes"], retained=True) == state for path, state in files.items()),
            "evidence changed during verification")


def read_capture_index(index_path, target):
    """Verify retained outputs/tool bytes; frame-byte claims need verify_selection.

    Recorded invocation paths/mtimes are not opened or treated as current identity.
    Only confined retained evidence is read, using the trusted current parser.
    """
    result = _verify_index(index_path, target)
    unchanged(result["files"])
    return result


def verify_selection(index_path, target, role, original, sidecar):
    """Bind explicit selected bytes and actual frame evidence to the closed capture."""
    require(role in ROLES, "unknown selected role")
    original, sidecar = regular(Path(original)), regular(Path(sidecar))
    require(not os.path.samefile(original, sidecar), "selected original and sidecar alias")
    selected = {"original": snapshot(original), "sidecar": snapshot(sidecar)}
    result = _verify_index(index_path, target)
    capture = result["captures"][role]
    for kind, observed in selected.items():
        require(same_bytes(capture["inputs"][kind]["before"], observed), "selected " + kind + " differs from capture")
    if capture["frameIdentity"] is not None:
        parser = trusted_parser()
        original_identity, original_bytes = parser.elf_frame_identity(original)
        sidecar_identity, sidecar_bytes = parser.elf_frame_identity(sidecar)
        require(original_identity == sidecar_identity == capture["frameIdentity"] and original_bytes == sidecar_bytes,
                "selected inherited frame identity/bytes differ")
    require(selected == {"original": snapshot(original), "sidecar": snapshot(sidecar)},
            "selected files changed during verification")
    unchanged(result["files"])
    return {"status": "MATCHING_CAPTURED_EVIDENCE", "role": role, "index": result["index"],
            "capture": capture["capture"], "strict": capture["strict"], "llvm": capture["llvm"],
            "files": result["files"]}


def capture(original, sidecar, toolset, output):
    original, sidecar = regular(Path(original).absolute()), regular(Path(sidecar).absolute())
    require(not os.path.samefile(original, sidecar), "original and sidecar alias")
    toolset = regular(Path(toolset).resolve(strict=True), retained=True)
    require(toolset.name == "toolset.json" and toolset.parent.name == "tools", "unexpected toolset path")
    files = {}
    tools = verify_toolset(toolset, files)
    llvm = regular(Path(tools["configured"]["llvmResolved"]))
    llvm_state = snapshot(llvm, TOOL_FILE)
    require(same_bytes(llvm_state, files[str(toolset.parent / "llvm/llvm-dwarfdump")]),
            "invoked LLVM differs from retained executable")
    require(not Path(output).absolute().resolve(strict=False).is_relative_to(toolset.parent),
            "capture cannot write within retained toolset")
    for selected in (original, sidecar):
        require(not any(os.path.samefile(selected, path) for path in [*files, str(llvm)]), "input aliases tool evidence")
    inputs = {kind: {"path": str(path), "resolvedPath": str(path.resolve(strict=True)),
                    "before": snapshot(path)} for kind, path in (("original", original), ("sidecar", sidecar))}
    destination = new_directory(output)
    try:
        invocations = {}
        invocations["llvm"] = run_recorded([llvm, "--verify", sidecar], destination / "llvm.stdout",
                                           destination / "llvm.stderr", {"LC_ALL": "C"})
        invocation(invocations["llvm"])
        require(snapshot(destination / "llvm.stderr", LARGE_FILE)["bytes"] == 0, "LLVM wrote stderr")
        snapshot(destination / "llvm.stdout", LARGE_FILE)
        llvm_summary = llvm_output(read_bytes(destination / "llvm.stdout", LARGE_FILE), str(sidecar))
        launcher = toolset.parent / "dwarfdump/bin/dwarfdump"
        command = [sys.executable, toolset.parent / "sources/check-dwarfdump.py", sidecar,
                   destination / "dwarfdump.txt", "--tool", launcher, "--original", original]
        invocations["strict"] = run_recorded(command, destination / "strict-runner.stdout",
                                             destination / "strict-runner.stderr", {"LC_ALL": "C"})
        invocation(invocations["strict"])
        metadata = read_json(destination / "dwarfdump.txt.check.json", LARGE_FILE)
        require(metadata.get("status") == "PASS", "strict checker did not complete")
        for kind, path in (("original", original), ("sidecar", sidecar)):
            inputs[kind]["after"] = snapshot(path)
            require(inputs[kind]["after"] == inputs[kind]["before"], "input changed across validation pair")
        require(snapshot(llvm, TOOL_FILE) == llvm_state, "LLVM changed across validation pair")
        unchanged(files)
        outputs = [file_record(destination, path, LARGE_FILE) for path in sorted(destination.iterdir())]
        require(sum(record["bytes"] for record in outputs) <= CASE_TOTAL, "capture output exceeds aggregate bound")
        value = {"schemaVersion": 1, "kind": "FORGE_TEST_VALIDATION_CAPTURE", "completion": "COMPLETE",
            "toolsetSha256": files[str(toolset)]["sha256"], "inputs": inputs, "invocations": invocations,
            "outputs": outputs, "strictSummary": {key: metadata[key] for key in
                ("compilers", "check_tables", "reported_errors", "uncorroborated_errors")}, "llvmSummary": llvm_summary}
        # Parse before publishing a successful receipt, using exactly the retained
        # bytes. Temporary record is not an externally consumable complete receipt.
        probe = destination / "checking.json"
        publish(probe, value)
        try:
            parse_capture(probe, tools, files[str(toolset)], {})
        except BaseException as failure:
            try:
                probe.unlink()
            except OSError as cleanup:
                failure.add_note("capture validation temporary cleanup failed: " + repr(cleanup))
            raise
        else:
            probe.unlink()
        publish(destination / "receipt.json", value)
        return destination / "receipt.json"
    except BaseException as failure:
        record_failure(destination, failure)
        raise


def create_index(target, captures, output):
    require(re.fullmatch(r"[a-z0-9_]{1,64}", target) is not None, "invalid target label")
    require(set(captures) == set(ROLES), "exactly three named captures required")
    output = Path(output).absolute()
    root = output.parent.resolve(strict=True)
    require(output.name == "index.json", "capture index must be named index.json")
    require(not output.exists() and not output.is_symlink(), "index destination exists")
    toolset = root / "tools/toolset.json"
    files = {}
    tools = verify_toolset(toolset, files)
    records = {}
    for role in ROLES:
        path = Path(captures[role]).resolve(strict=True)
        require(path == root / "cases" / role / "receipt.json", "capture is outside its explicit role directory")
        parse_capture(path, tools, files[str(toolset)], files)
        records[role] = file_record(root, path, SMALL_JSON)
    distinct_entries(files)
    unchanged(files)
    value = {"schemaVersion": 1, "kind": "FORGE_TEST_VALIDATION_INDEX", "target": target,
             "toolset": file_record(root, toolset, SMALL_JSON), "captures": records}
    publish(output, value)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    tools = modes.add_parser("tools")
    for option in ("bundle", "llvm", "llvm-notices", "output"):
        tools.add_argument("--" + option, type=Path, required=True)
    run = modes.add_parser("capture")
    for option in ("original", "sidecar", "toolset", "output"):
        run.add_argument("--" + option, type=Path, required=True)
    index = modes.add_parser("index")
    index.add_argument("--target", required=True)
    index.add_argument("--capture", action="append", required=True)
    index.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "tools":
        result = create_tools(args.bundle, args.llvm, args.llvm_notices, args.output)
    elif args.mode == "capture":
        result = capture(args.original, args.sidecar, args.toolset, args.output)
    else:
        selected = {}
        for item in args.capture:
            role, separator, path = item.partition("=")
            require(separator and role not in selected and path, "invalid/duplicate --capture")
            selected[role] = Path(path)
        result = create_index(args.target, selected, args.output)
    print("validation-evidence=" + str(result))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError) as failure:
        print("validation-evidence=FAILED: " + str(failure), file=sys.stderr)
        sys.exit(1)
