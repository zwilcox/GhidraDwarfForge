"""Compare staged runtime bytes with the checksums recorded by the native build."""
import hashlib
import re
import sys
from pathlib import Path


def verify(platform, directory):
    metadata = (directory / "BUILD-METADATA.txt").read_text(encoding="utf-8").splitlines()
    if metadata.count("SHA-256:") != 1:
        raise ValueError("expected one native SHA-256 section")
    first = metadata.index("SHA-256:") + 1
    end = metadata.index("Dependencies:", first)
    recorded = {}
    for line in metadata[first:end]:
        match = re.fullmatch(r"\\?([a-f0-9]{64}) [ *](.+)", line)
        if not match:
            raise ValueError("invalid library checksum record")
        digest, original_path = match.groups()
        # Older jobs recorded paths relative to the build host. Never open them.
        name = re.split(r"[/\\]", original_path)[-1]
        if name in recorded:
            raise ValueError("duplicate library checksum for " + name)
        recorded[name] = digest

    pattern = "*.dll" if platform == "win_x86_64" else "*.so*"
    observed = {}
    for path in sorted(directory.glob(pattern)):
        with path.open("rb") as stream:
            checksum = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                checksum.update(chunk)
        observed[path.name] = checksum.hexdigest()
    if not recorded or recorded != observed:
        raise ValueError("build metadata differs from the shipped library set or bytes")
    manifest = directory / "NATIVE-RUNTIME-SHA256SUMS"
    if manifest.exists():
        lines = manifest.read_text(encoding="ascii").splitlines()
        if sorted(lines) != sorted(f"{digest}  {name}" for name, digest in observed.items()):
            raise ValueError("runtime checksum manifest differs from build metadata")


if __name__ == "__main__":
    try:
        verify(sys.argv[1], Path(sys.argv[2]))
    except (OSError, ValueError) as error:
        sys.exit(f"{sys.argv[1]} native runtime provenance mismatch: {error}")
