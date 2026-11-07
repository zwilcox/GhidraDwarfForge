#!/usr/bin/env python3
"""Check exact evidence retention for filenames rejected by artifact upload."""

import hashlib
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def main():
    helper = Path(__file__).resolve().parents[3] / "support/archive-target-diagnostics.py"
    with tempfile.TemporaryDirectory(prefix="forge-artifact-names-") as directory:
        base = Path(directory)
        root = base / "diagnostics"
        root.mkdir()
        names = ['request λ "literal".json', 'colon:angle<>pipe|star*question?.log',
            'carriage\rline\n.log', '.forge-build-id/v1/id/generations/one/source/source.c',
            'nested/.hidden/strict.log']
        expected = {}
        for index, name in enumerate(names):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bytes(range(256)) + str(index).encode())
            expected[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        (root / "linked-source").symlink_to(names[3])
        archive = base / "target-preflight.tar.gz"
        subprocess.run([sys.executable, str(helper), str(root), str(archive)], check=True)
        with tarfile.open(archive) as retained:
            files = {member.name.removeprefix("./"): member for member in retained}
            assert {name for name, member in files.items() if member.isfile()} == set(names)
            for name, digest in expected.items():
                assert hashlib.sha256(retained.extractfile(files[name]).read()).hexdigest() == digest
            assert files["linked-source"].issym()
            assert files["linked-source"].linkname == names[3]
        for name, digest in expected.items():
            assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
        refused = subprocess.run([sys.executable, str(helper), str(root),
            str(root / "recursive.tar.gz")], capture_output=True, text=True)
        assert refused.returncode != 0 and not (root / "recursive.tar.gz").exists()
        assert not list(base.glob("*.partial"))
    print("target-diagnostics-retention=PASS quoted/unicode/hidden/control-names/links/unchanged-input")


if __name__ == "__main__":
    main()
