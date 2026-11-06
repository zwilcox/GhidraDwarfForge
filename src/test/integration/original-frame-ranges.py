#!/usr/bin/env python3
"""Compare original CIE/FDE inventories against compiler, GNU and LLVM evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import sys
import struct
import zlib

ROOT = Path(__file__).resolve().parents[3]
HELPERS = runpy.run_path(str(ROOT / "src/test/integration/cfi-encoder.py"))
run, metadata = HELPERS["run"], HELPERS["metadata"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_variants(case, original, kind, prefix, classpath, args, expected, raw):
    variants = [("plain", original)]
    if kind == "debug_frame":
        for mode in ("zlib-gabi", "zlib-gnu"):
            path = case / mode
            run([prefix + "objcopy", "--compress-debug-sections=" + mode, original, path],
                case / (mode + "-compress.log"))
            variants.append((mode, path))
    else:
        info = metadata(original)
        assert any(int.from_bytes(original.read_bytes()[info["phoff"] + index * info["phsize"]:
            info["phoff"] + index * info["phsize"] + 4], "little") == 0x6474e550
            for index in range(info["phcount"])), "compiler fixture needs PT_GNU_EH_FRAME"
        for mode in ("sectionless", "unnamed"):
            path = case / mode
            data = bytearray(original.read_bytes())
            if mode == "sectionless":
                data[40:48] = bytes(8)
                data[58:64] = bytes(6)
            else:
                section, = [s for s in info["sections"] if s["name"] == ".eh_frame"]
                data[section["header"]:section["header"] + 4] = bytes(4)
            path.write_bytes(data)
            variants.append((mode, path))
    results = []
    for mode, path in variants:
        before = digest(path)
        text = run([args.java, "-cp", classpath, "ghidradwarfforge.elf.OriginalFrameSourcesSmoke", path],
                   case / (mode + "-sources.log"))
        frames, sources = [], []
        for line in text.splitlines():
            fields = line.split()
            if fields[0] == "source":
                _, name, offset, stored, decoded, address, headers, stored_sha, plain_sha = fields
                source = {"name": name, "offset": int(offset, 16), "stored": int(stored, 16),
                          "decoded": int(decoded, 16), "address": int(address, 16),
                          "programHeaders": headers == "true", "storedSha256": stored_sha, "decodedSha256": plain_sha}
                payload = path.read_bytes()[source["offset"]:source["offset"] + source["stored"]]
                assert hashlib.sha256(payload).hexdigest() == stored_sha
                if name == ".zdebug_frame":
                    assert payload[:4] == b"ZLIB"
                    plain = zlib.decompress(payload[12:])
                    assert len(plain) == int.from_bytes(payload[4:12], "big")
                elif mode == "zlib-gabi" and name == ".debug_frame":
                    compression, reserved, length, alignment = struct.unpack_from("<IIQQ", payload)
                    assert compression == 1 and reserved == 0 and alignment
                    plain = zlib.decompress(payload[24:])
                    assert len(plain) == length
                else:
                    plain = payload
                assert len(plain) == source["decoded"] and hashlib.sha256(plain).hexdigest() == plain_sha
                if source["decoded"] and (name.endswith("debug_frame") or name == ".eh_frame"):
                    original_bytes = raw.read_bytes()
                    assert original_bytes.startswith(plain) and not any(original_bytes[len(plain):])
                if kind == "eh_frame":
                    assert source["programHeaders"]
                sources.append(source)
            elif fields[0] == "frame":
                _, offset, cie, address, size, signal = fields
                assert signal == "false"
                frames.append((int(address, 16), int(size, 16)))
            else:
                raise AssertionError(line)
        assert sources and sorted(frames) == sorted(expected)
        assert digest(path) == before
        if mode.startswith("zlib"):
            gnu = run(["readelf", "--debug-dump=frames", path], case / (mode + "-gnu.log"))
            observed = [(int(a, 16), int(b, 16) - int(a, 16))
                        for a, b in re.findall(r"\bFDE\b[^\n]*\bpc=([0-9a-f]+)\.\.([0-9a-f]+)", gnu)]
            assert sorted(observed) == sorted(expected)
            run(["llvm-dwarfdump", "--verify", path], case / (mode + "-llvm.log"))
            run([sys.executable, ROOT / "src/test/integration/check-dwarfdump.py", path,
                 case / (mode + "-strict.log"), "--tool", args.dwarfdump, "--original", original],
                case / (mode + "-strict-driver.log"))
        results.append({"mode": mode, "sha256": before, "sources": sources, "ranges": frames})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("classes", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--java", default="java")
    parser.add_argument("--dwarfdump", required=True)
    parser.add_argument("--target", choices=("all", "x86_64", "aarch64"), default="all")
    args = parser.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    classpath = os.pathsep.join(str(args.classes.resolve() / part) for part in ("main", "test"))
    source = ROOT / "src/test/fixtures/synthetic-cfi.c"
    reports = []
    targets = ("x86_64", "aarch64") if args.target == "all" else (args.target,)
    for target in targets:
        prefix = "" if target == "x86_64" else "aarch64-linux-gnu-"
        start = source.with_name("synthetic-cfi-start-" + target + ".S")
        for role in ("exec", "pie", "shared"):
            for kind in ("debug_frame", "eh_frame"):
                case = work / (target + "-" + role + "-" + kind)
                case.mkdir()
                original = case / "original"
                flags = ["-O1", "-g", "-gdwarf-5", "-fomit-frame-pointer", "-fno-optimize-sibling-calls",
                         "-nostdlib", "-Wl,--build-id=none"]
                flags += (["-fno-asynchronous-unwind-tables", "-fno-unwind-tables"] if kind == "debug_frame"
                          else ["-fasynchronous-unwind-tables", "-funwind-tables", "-Wl,--eh-frame-hdr"])
                flags += {"exec": ["-fno-pie", "-no-pie", "-static"],
                          "pie": ["-fPIE", "-static-pie"], "shared": ["-fPIC", "-shared"]}[role]
                inputs = [source] if role == "shared" else [source, start]
                protected = {str(path): digest(path) for path in inputs}
                run([prefix + "gcc", *flags, *inputs, "-o", original], case / "compile.log")
                run([prefix + "gcc", *flags, *inputs, "-o", case / "repeat"], case / "repeat.log")
                assert original.read_bytes() == (case / "repeat").read_bytes()
                protected[str(original)] = digest(original)
                info = metadata(original)
                section, = [s for s in info["sections"] if s["name"] == "." + kind and s["size"]]
                assert section["flags"] & 0x800 == 0
                raw = case / "frames"
                data = original.read_bytes()[section["offset"]:section["offset"] + section["size"]]
                raw.write_bytes(data)
                inventory = run([args.java, "-cp", classpath, "ghidradwarfforge.unwind.OriginalFrameRangesSmoke",
                                 raw, "little", "8", kind.upper(), hex(section["address"])], case / "inventory.log")
                frames = []
                for line in inventory.splitlines()[1:]:
                    offset, cie, address, size, signal = line.split()
                    assert signal == "false"
                    frames.append(tuple(int(value, 16) for value in (offset, cie, address, size)))
                gnu = run(["readelf", "--debug-dump=frames", original], case / "gnu-frames.log")
                expected = [(int(a, 16), int(b, 16) - int(a, 16))
                            for a, b in re.findall(r"\bFDE\b[^\n]*\bpc=([0-9a-f]+)\.\.([0-9a-f]+)", gnu)]
                assert expected and sorted((f[2], f[3]) for f in frames) == sorted(expected)
                llvm = run(["llvm-dwarfdump", "--" + kind.replace("_", "-"), original], case / "llvm-frames.log")
                llvm_ranges = [(int(a, 16), int(b, 16) - int(a, 16))
                               for a, b in re.findall(r"\bFDE\b[^\n]*\bpc=([0-9a-f]+)\.\.\.?([0-9a-f]+)", llvm)]
                assert sorted(expected) == sorted(llvm_ranges), llvm
                run(["llvm-dwarfdump", "--verify", original], case / "llvm-verify.log")
                run([sys.executable, ROOT / "src/test/integration/check-dwarfdump.py", original,
                     case / "strict.log", "--tool", args.dwarfdump, "--original", case / "repeat"], case / "strict-driver.log")
                assert not any(word in gnu.lower() for word in ("warning", "error"))
                variants = source_variants(case, original, kind, prefix, classpath, args, expected, raw)
                assert protected == {path: digest(Path(path)) for path in protected}
                reports.append({"target": target, "role": role, "section": kind, "frames": frames,
                                "originalSha256": digest(original), "sectionSha256": digest(raw),
                                "inventorySha256": digest(case / "inventory.log"),
                                "strict": json.loads((case / "strict.log.check.json").read_text()), "sourceVariants": variants})
                print(target, role, kind, "original frame ranges PASS", flush=True)
    (work / "result.json").write_text(json.dumps({"status": "PASS", "cases": reports,
        "scope": "Original source/header/range inventory including compression and program headers, independently compared to GNU and LLVM; no relocation qualification, CFI semantics or synthesis claim"},
        indent=4) + "\n")


if __name__ == "__main__":
    main()
