#!/usr/bin/env python3
"""Retain bounded end-of-job primary-fixture diagnostics, including on failure."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


TARGETS = ("x86_64", "aarch64", "arm32", "mips32be", "mips32le")
MAX_BYTES = 16 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
STEMS = (
    "semantic.exec", "semantic.partial", "semantic.exec.no-build-id",
    "semantic.exec.no-sections", "semantic.pie", "libsemantic.so",
)
INPUTS = (
    "semantic.exec.reference", "semantic.exec.stripped",
    "semantic.exec.no-build-id.reference", "semantic.exec.no-build-id.stripped",
    "semantic.exec.no-sections.stripped", "semantic.partial.reference",
    "semantic.partial.stripped", "semantic.pie.reference", "semantic.pie.stripped",
    "libsemantic.so.reference", "libsemantic.so.stripped",
    "semantic.shared-driver.reference", "semantic.shared-driver.stripped",
)
SOURCES = ("semantic.c", "shared_semantic.c", "shared_driver.c")


def metadata(value):
    return {
        "device": value.st_dev, "inode": value.st_ino, "mode": value.st_mode,
        "bytes": value.st_size, "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def capture_file(source, destination):
    record = {"source": str(source), "retained": str(destination)}
    created = False
    try:
        before = source.lstat()
        record["before"] = metadata(before)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("selected path is not a regular file (symlinks excluded)")
        if before.st_size > MAX_BYTES:
            raise ValueError(f"selected file exceeds {MAX_BYTES}-byte capture limit")
        digest = hashlib.sha256()
        count = 0
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as original:
            if metadata(os.fstat(original.fileno())) != metadata(before):
                raise ValueError("selected file changed before opening")
            with destination.open("xb") as retained:
                created = True
                while chunk := original.read(CHUNK_BYTES):
                    count += len(chunk)
                    if count > MAX_BYTES:
                        raise ValueError("selected file grew beyond the capture limit")
                    digest.update(chunk)
                    retained.write(chunk)
            record["after"] = metadata(source.lstat())
            if (record["after"] != record["before"] or
                    metadata(os.fstat(original.fileno())) != record["before"] or
                    count != before.st_size):
                raise ValueError("selected file changed during capture")
        copied_digest = hashlib.sha256()
        copied_count = 0
        with destination.open("rb") as retained:
            while chunk := retained.read(CHUNK_BYTES):
                copied_count += len(chunk)
                if copied_count > count:
                    raise ValueError("retained copy grew beyond the observed input")
                copied_digest.update(chunk)
        if copied_count != count or copied_digest.digest() != digest.digest():
            raise ValueError("retained copy does not match the observed input")
        record.update(status="CAPTURED", bytes=count, sha256=digest.hexdigest(),
                      retained_sha256=copied_digest.hexdigest())
    except FileNotFoundError as error:
        record.update(status="ABSENT" if "before" not in record else "ERROR",
                      error_type=type(error).__name__, diagnostic=str(error))
    except (OSError, ValueError) as error:
        record.update(status="ERROR", error_type=type(error).__name__,
                      diagnostic=str(error))
    finally:
        if created and record.get("status") != "CAPTURED":
            try:
                destination.unlink()
            except OSError as error:
                record["cleanup_error"] = f"{type(error).__name__}: {error}"
    return record


def capture(repository, target):
    if target not in TARGETS:
        raise ValueError(f"unknown fixture target: {target}")
    output = repository / "build/test-results/primary-fixtures" / target
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()  # An earlier capture is evidence; never replace it.
    (output / "sources").mkdir()
    fixture = repository / "build/fixtures" / target
    names = list(INPUTS) + [f"{stem}.ghidra-forge.dbg{suffix}"
                           for stem in STEMS for suffix in ("", ".c")]
    records = [capture_file(fixture / name, output / name) for name in names]
    records.extend(capture_file(repository / "src/test/fixtures" / name,
                                output / "sources" / name) for name in SOURCES)
    receipt = {
        "schemaVersion": 1, "target": target, "max_file_bytes": MAX_BYTES,
        "scope": "End-of-job diagnostic snapshot of explicit primary fixtures. "
                 "Not proof of bytes at an earlier exporter or debugger invocation; "
                 "compare against its report or capture hashes where available. "
                 "Missing outputs do not imply that their tests ran or passed.",
        "files": records,
        "captured": sum(r["status"] == "CAPTURED" for r in records),
        "absent": sum(r["status"] == "ABSENT" for r in records),
        "errors": sum(r["status"] == "ERROR" for r in records),
    }
    with (output / "capture.json").open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=4)
        stream.write("\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    arguments = parser.parse_args()
    receipt = capture(Path(__file__).resolve().parents[3], arguments.target)
    print(json.dumps({key: receipt[key] for key in ("target", "captured", "absent", "errors")}))
    return 1 if receipt["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
