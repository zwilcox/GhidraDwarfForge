#!/usr/bin/env python3
"""Preserve Linux fixture filenames inside one portable upload filename."""

import argparse
import os
from pathlib import Path
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    output = args.output.absolute()
    if not root.is_dir() or output.resolve().is_relative_to(root):
        parser.error("root must be a directory and output must be outside it")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, suffix=".partial",
                delete=False) as stream:
            temporary = Path(stream.name)
            with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.PAX_FORMAT,
                    dereference=False) as archive:
                archive.add(root, arcname=".")
        os.replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(f"target diagnostics archived: {output}")


if __name__ == "__main__":
    main()
