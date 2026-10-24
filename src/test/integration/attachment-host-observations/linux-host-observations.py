#!/usr/bin/env python3
"""Owned Linux feasibility fixtures; no attachment, replacement or preservation API."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tempfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=4, sort_keys=True)
        stream.write("\n")


def run(command, directory, label, expected=0):
    try:
        result = subprocess.run([str(item) for item in command], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                                env={**os.environ, "LC_ALL": "C"})
    except subprocess.TimeoutExpired as failure:
        # subprocess.run kills and waits for this direct owned child. This is not
        # a process-tree supervisor; these inspected probes do not spawn children.
        (directory / (label + ".stdout")).write_bytes(failure.stdout or b"")
        (directory / (label + ".stderr")).write_bytes(failure.stderr or b"")
        write_json(directory / (label + ".timeout.json"), {
            "argv": [str(item) for item in command], "seconds": 60,
            "scope": "Owned direct test child killed/reaped by subprocess.run"})
        raise
    (directory / (label + ".stdout")).write_bytes(result.stdout)
    (directory / (label + ".stderr")).write_bytes(result.stderr)
    record = {"argv": [str(item) for item in command], "exit": result.returncode,
              "stdoutSha256": sha(result.stdout), "stderrSha256": sha(result.stderr)}
    write_json(directory / (label + ".command.json"), record)
    if expected is not None:
        assert result.returncode == expected, (label, record, result.stderr.decode(errors="replace"))
    return result


def stat_fields(value):
    return {"dev": value.st_dev, "ino": value.st_ino, "nlink": value.st_nlink,
            "mode": value.st_mode, "uid": value.st_uid, "gid": value.st_gid,
            "size": value.st_size, "mtimeNanos": value.st_mtime_ns,
            "ctimeNanos": value.st_ctime_ns, "atimeNanos": value.st_atime_ns}


def native_xattrs(path, follow=False):
    names = os.listxattr(path, follow_symlinks=follow)
    assert len(names) <= 64, "Research xattr count bound"
    values = {}
    total = 0
    for name in sorted(names):
        value = os.getxattr(path, name, follow_symlinks=follow)
        total += len(value)
        assert len(value) <= 65536 and total <= 1048576
        values[name] = {"bytes": len(value), "sha256": sha(value),
                        "base64": base64.b64encode(value).decode("ascii")}
    return {"attributes": values, "namespaceVisibility": "UNKNOWN",
            "limitation": "Successful listxattr may omit names inaccessible to this process"}


def snapshot(paths):
    result = {}
    for label, path in paths.items():
        info = path.lstat()
        item = {"path": str(path), "lstat": stat_fields(info), "xattrs": native_xattrs(path)}
        if stat.S_ISREG(info.st_mode):
            assert info.st_size <= 16 * 1024 * 1024
            item["sha256"] = sha(path.read_bytes())
        if stat.S_ISLNK(info.st_mode):
            item["linkTarget"] = os.readlink(path)
        result[label] = item
    return result


def without_access_time(value):
    value = json.loads(json.dumps(value))
    for record in value.values():
        record["lstat"].pop("atimeNanos")
    return value


def native_observe(path, policy):
    # Python calls the host's stat/fstat/open/listxattr APIs; no Java/provider facts used.
    out = {"path": str(path), "lstat": stat_fields(path.lstat()),
           "xattrsNoFollow": native_xattrs(path), "channelIdentity": "OBSERVED_NATIVE_FSTAT"}
    flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path, flags)
    try:
        out["noFollowHandle"] = {"flags": ["O_PATH", "O_NOFOLLOW", "O_CLOEXEC"],
                                  "fstat": stat_fields(os.fstat(descriptor))}
    finally:
        os.close(descriptor)
    try:
        followed = path.stat()
        out["followStat"] = stat_fields(followed)
    except OSError as failure:
        out["followError"] = {"type": type(failure).__name__, "errno": failure.errno}
        return out
    if policy != "READ" or not stat.S_ISREG(followed.st_mode):
        out["reads"] = "NOT_REQUESTED_OR_NOT_REGULAR"
        return out
    first = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        second = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            opened = [stat_fields(os.fstat(fd)) for fd in (first, second)]
            out["openedHandles"] = opened
            out["sameOpenedIdentity"] = all(opened[0][key] == opened[1][key] for key in ("dev", "ino"))
            reads = []
            for fd in (first, second):
                digest = hashlib.sha256()
                count = 0
                while True:
                    data = os.read(fd, 65536)
                    if not data:
                        break
                    count += len(data)
                    assert count <= 16 * 1024 * 1024
                    digest.update(data)
                reads.append({"bytes": count, "sha256": digest.hexdigest()})
            out["reads"] = reads
        finally:
            os.close(second)
    finally:
        os.close(first)
    return out


def manifest(files, pairs):
    lines = ["FORGE_HOST_FACTS\t1"]
    lines.extend("FILE\t" + label + "\t" + base64.b64encode(os.fsencode(path)).decode("ascii")
                 + "\t" + policy for label, (path, policy) in files.items())
    lines.extend("PAIR\t" + left + "\t" + right for left, right in pairs)
    return ("\n".join(lines) + "\n").encode("ascii")


def observed(value):
    assert value["status"] == "OBSERVED", value
    return value["value"]


def verify_java(java, native, files):
    assert java["schemaVersion"] == 1 and java["scope"] == "INSPECTION_ONLY"
    assert java["host"]["javaVersion"].split(".")[0] == "21", java["host"]
    assert 0 < java["host"]["maxHeap"] <= 64 * 1024 * 1024
    assert set(java["files"]) == set(files)
    for label, (path, policy) in files.items():
        actual = java["files"][label]
        expected = native[label]
        assert actual["path"] == str(path) and actual["policy"] == policy
        nofollow = observed(actual["nofollow"])
        mode = expected["lstat"]["mode"]
        assert nofollow["regular"] == stat.S_ISREG(mode)
        assert nofollow["directory"] == stat.S_ISDIR(mode)
        assert nofollow["symbolicLink"] == stat.S_ISLNK(mode)
        assert nofollow["size"] == expected["lstat"]["size"]
        assert nofollow["modifiedNanos"] == expected["lstat"]["mtimeNanos"]
        unix = observed(actual["unixNoFollow"])
        assert unix == {key: expected["lstat"][key] for key in ("dev", "ino", "nlink", "uid", "gid", "mode")}
        if isinstance(expected.get("reads"), list):
            reads = observed(actual["reads"])
            assert [reads["first"], reads["second"]] == expected["reads"]
            assert reads["openedChannelIdentity"] == "UNKNOWN_PUBLIC_JAVA_API"
        elif policy == "METADATA":
            assert actual["reads"]["status"] == "NOT_REQUESTED"
        if stat.S_ISREG(mode) or stat.S_ISDIR(mode):
            attrs = observed(actual["userNoFollow"])
            assert attrs["completeNativeNamespaceEnumeration"] == "UNKNOWN"
            expected_user = {name.removeprefix("user."): {key: value[key] for key in ("bytes", "sha256")}
                             for name, value in expected["xattrsNoFollow"]["attributes"].items()
                             if name.startswith("user.")}
            assert attrs["attributes"] == expected_user
        else:
            for name in ("userNoFollow", "dosNoFollow", "aclNoFollow"):
                assert actual[name]["status"] == "UNAVAILABLE"
    expected_pairs = [("plain", "plain"), ("plain", "equal_copy"),
                      ("plain", "hardlink"), ("plain", "symlink")]
    assert len(java["pairs"]) == len(expected_pairs)
    assert sorted((item["left"], item["right"]) for item in java["pairs"]) == sorted(expected_pairs)
    pairs = {(item["left"], item["right"]): observed(item["isSameFile"]) for item in java["pairs"]}
    assert pairs == {("plain", "plain"): True, ("plain", "equal_copy"): False,
                     ("plain", "hardlink"): True, ("plain", "symlink"): True}
    assert java["files"]["symlink"]["nofollowReadOpen"]["status"] == "UNAVAILABLE"
    assert java["files"]["dangling"]["follow"]["status"] == "UNAVAILABLE"
    assert java["files"]["fifo"]["nofollow"]["value"]["other"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java", type=Path, required=True)
    parser.add_argument("--javac", type=Path, required=True)
    parser.add_argument("--output-parent", type=Path, required=True)
    args = parser.parse_args()
    assert sys.platform == "linux", "Linux-only native oracle"
    assert args.output_parent.is_dir()
    root = Path(tempfile.mkdtemp(prefix="linux.", dir=args.output_parent.resolve()))
    print(root, flush=True)
    source = Path(__file__).with_name("HostFacts.java").resolve()
    source_before = {str(path): sha(path.read_bytes()) for path in (source, Path(__file__).resolve())}
    executables = {name: {"path": str(path.resolve()), "sha256": sha(path.resolve().read_bytes())}
                   for name, path in {"java": args.java, "javac": args.javac,
                                      "python": Path(sys.executable)}.items()}
    classes = root / "classes"
    classes.mkdir()
    run([args.java, "-version"], root, "java-version")
    run([args.javac, "-version"], root, "javac-version")
    run([args.javac, "--release", "21", "-d", classes, source], root, "compile")
    tools = {}
    for name in ("getfacl", "setfacl"):
        executable = shutil.which(name)
        assert executable, name + " must be explicitly available; no silent omission"
        path = Path(executable).resolve()
        version = run([path, "--version"], root, name + "-version")
        tools[name] = {"path": str(path), "sha256": sha(path.read_bytes()),
                       "version": version.stdout.decode("utf-8").strip()}
    fixtures = root / "fixtures"
    fixtures.mkdir(mode=0o700)
    plain = fixtures / "plain"
    plain.write_bytes(b"Forge host observations only.\n\x00\xff")
    plain.chmod(0o640)
    os.setxattr(plain, "user.forge_probe", b"owned-xattr\x00\xff")
    equal = fixtures / "equal-copy"
    equal.write_bytes(plain.read_bytes())
    equal.chmod(0o600)
    hardlink = fixtures / "hardlink"
    os.link(plain, hardlink)
    symlink = fixtures / "symlink"
    symlink.symlink_to("plain")
    dangling = fixtures / "dangling"
    dangling.symlink_to("not-created")
    fifo = fixtures / "fifo"
    os.mkfifo(fifo, 0o600)
    acl_parent = fixtures / "acl-parent"
    acl_parent.mkdir(mode=0o700)
    os.setxattr(acl_parent, "user.forge_parent", b"not-inherited-as-user-xattr")
    named_uid = 60001 if os.getuid() != 60001 else 60002
    run([tools["setfacl"]["path"], "-m",
         f"d:u::rwx,d:u:{named_uid}:r--,d:g::---,d:m::r--,d:o::---", acl_parent], root, "set-default-acl")
    old_umask = os.umask(0o077)
    try:
        acl_child = acl_parent / "inherited"
        control_child = fixtures / "no-acl-child"
        for child in (acl_child, control_child):
            fd = os.open(child, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
            try:
                os.write(fd, b"same-creation-mode-and-umask\n")
            finally:
                os.close(fd)
    finally:
        os.umask(old_umask)
    acl_text = run([tools["getfacl"]["path"], "-n", "-p", acl_parent, acl_child, control_child],
                   root, "acl-native").stdout.decode("utf-8")
    assert f"user:{named_uid}:r--" in acl_text
    assert stat.S_IMODE(acl_child.stat().st_mode) == 0o640
    assert stat.S_IMODE(control_child.stat().st_mode) == 0o600
    assert "system.posix_acl_default" in os.listxattr(acl_parent)
    assert "system.posix_acl_access" in os.listxattr(acl_child)
    assert "user.forge_parent" not in os.listxattr(acl_child)
    files = {"plain": (plain, "READ"), "equal_copy": (equal, "READ"),
             "hardlink": (hardlink, "READ"), "symlink": (symlink, "READ"),
             "dangling": (dangling, "METADATA"), "fifo": (fifo, "METADATA"),
             "directory": (fixtures, "METADATA"), "acl_parent": (acl_parent, "METADATA"),
             "acl_child": (acl_child, "READ"), "control_child": (control_child, "READ")}
    pairs = [("plain", "plain"), ("plain", "equal_copy"), ("plain", "hardlink"), ("plain", "symlink")]
    manifest_path = root / "manifest.tsv"
    manifest_path.write_bytes(manifest(files, pairs))
    protected = {label: path for label, (path, _) in files.items()}
    before = snapshot(protected)
    write_json(root / "before.json", before)
    native = {label: native_observe(path, policy) for label, (path, policy) in files.items()}
    write_json(root / "native.json", native)
    assert native["plain"]["sameOpenedIdentity"]
    assert native["plain"]["lstat"]["nlink"] == 2
    assert native["plain"]["lstat"]["ino"] == native["hardlink"]["lstat"]["ino"]
    assert native["plain"]["lstat"]["ino"] != native["equal_copy"]["lstat"]["ino"]
    assert native["plain"]["reads"] == native["equal_copy"]["reads"]
    assert stat.S_ISLNK(native["symlink"]["noFollowHandle"]["fstat"]["mode"])
    command = [args.java, "-Xmx64m", "-cp", classes, "HostFacts", manifest_path]
    result = run(command, root, "java-facts")
    assert result.stderr == b""
    java = json.loads(result.stdout)
    assert java["manifestSHA256"] == sha(manifest_path.read_bytes())
    verify_java(java, native, files)
    controls = []
    invalid = {
        "version": b"FORGE_HOST_FACTS\t2\n",
        "empty": b"FORGE_HOST_FACTS\t1\n",
        "unknown-pair": manifest(files, [("plain", "missing")]),
        "duplicate-id": manifest_path.read_bytes() + manifest_path.read_bytes().splitlines(keepends=True)[1],
        "invalid-base64": b"FORGE_HOST_FACTS\t1\nFILE\tbad\t%%%\tREAD\n",
        "invalid-utf8": b"FORGE_HOST_FACTS\t1\nFILE\tbad\t/w==\tREAD\n",
        "invalid-policy": manifest_path.read_bytes().replace(b"\tREAD\n", b"\tWRITE\n", 1),
        "manifest-limit": b"x" * 65537,
    }
    for label, data in invalid.items():
        path = root / (label + ".tsv")
        path.write_bytes(data)
        result = run([*command[:-1], path], root, "negative-" + label, expected=None)
        assert result.returncode != 0 and result.stdout == b"" and result.stderr
        controls.append({"id": label, "exit": result.returncode, "manifestSHA256": sha(data)})
    after = snapshot(protected)
    write_json(root / "after.json", after)
    assert without_access_time(before) == without_access_time(after)
    retained = {}
    copies = root / "selected-bytes"
    copies.mkdir()
    for label, (path, policy) in files.items():
        if policy != "READ":
            continue
        data = path.read_bytes()
        assert len(data) <= 16 * 1024 * 1024
        expected = native[label]["reads"][0]
        assert len(data) == expected["bytes"] and sha(data) == expected["sha256"]
        copy = copies / (label + ".bytes")
        with copy.open("xb") as output:
            output.write(data)
        assert sha(copy.read_bytes()) == expected["sha256"]
        retained[label] = {"selectedPath": str(path), "retainedPath": str(copy), **expected}
    write_json(root / "retained-bytes.json", retained)
    source_copies = root / "source"
    source_copies.mkdir()
    for path in (source, Path(__file__).resolve(), source.with_name("README.md")):
        with (source_copies / path.name).open("xb") as output:
            output.write(path.read_bytes())
    final = snapshot(protected)
    write_json(root / "finally-after.json", final)
    assert without_access_time(before) == without_access_time(final)
    assert source_before == {path: sha(Path(path).read_bytes()) for path in source_before}
    for info in executables.values():
        assert info["sha256"] == sha(Path(info["path"]).read_bytes())
    result = {"status": "PASS", "scope": "INSPECTION_ONLY_OWNED_FIXTURES",
              "sourceSHA256": source_before, "host": {"platform": platform.platform(),
              "python": sys.version, "uid": os.getuid(), "gid": os.getgid()}, "tools": tools,
              "java": java["host"], "executables": executables,
              "files": len(files), "pairControls": len(pairs), "retainedByteCopies": retained,
              "manifestNegatives": controls, "protectedBytesAndObservedMetadataUnchanged": True,
              "accessTimes": {label: {"before": before[label]["lstat"]["atimeNanos"],
                  "afterProbe": after[label]["lstat"]["atimeNanos"],
                  "afterRetention": final[label]["lstat"]["atimeNanos"]} for label in before},
              "namespaceVisibility": "UNKNOWN", "javaOpenedChannelIdentity": "UNKNOWN",
              "aclInheritance": {"namedUid": named_uid, "childMode": "0640", "controlMode": "0600",
                  "nativeAclObserved": True, "javaUserViewIsNotAclInventory": True},
              "limitations": ["No attachment, metadata preservation, replacement, flush or durability test",
                  "Access times may change from read-only inspection", "Not an adversarial race or snapshot proof",
                  "Java and Python native namespace lists may omit inaccessible names",
                  "Windows native evidence remains separate"]}
    write_json(root / "result.json", result)
    print(json.dumps({"status": "PASS", "result": str(root / "result.json")}))


if __name__ == "__main__":
    main()
