"""Independent file-offset/address fixtures for the companion loader."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("forge_loader",
    ROOT / "src/main/resources/ghidradwarfforge/gdb/loader.py")
loader = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(loader)
Load = loader.LoadSegment
Map = loader.Mapping


class MappingTests(unittest.TestCase):
    def test_both_gdb_formats_and_space_paths(self):
        text = """process 123
Start Addr End Addr Size Offset Perms objfile
0x1000 0x2000 0x1000 0x0 r--p /tmp/my module.so
0x2000 0x3000 0x1000 0x1000 /tmp/my module.so
0x3000 0x4000 0x1000 0x0 rw-p
"""
        self.assertEqual(loader.parse_mappings(text), (
            Map(0x1000, 0x2000, 0, "/tmp/my module.so"),
            Map(0x2000, 0x3000, 0x1000, "/tmp/my module.so"),
            Map(0x3000, 0x4000, 0, "")))

    def test_invalid_or_unavailable_mapping_output(self):
        for text in ("Not supported on this target.",
                "0x1000 0x2000 0x500 0x0 /a",
                "0x2000 0x1000 0x1000 0x0 /a",
                "0x1000 0x2000 0x1000 ??? /a",
                "0x1000 0x2000 0x1000 0xffffffffffffffff /a"):
            with self.subTest(text=text), self.assertRaises(loader.LoaderError):
                loader.parse_mappings(text)

    def test_exec_offset_is_not_image_base(self):
        segments = [Load(0x1000, 0x401000, 0x180, 0x200)]
        maps = [Map(0x401000, 0x402000, 0x1000, "/a")]
        self.assertEqual(loader.select_bias(segments, maps, 64), 0)

    def test_nonzero_segment_offsets_and_multiple_aslr_biases(self):
        segments = [Load(0x2000, 0x6000, 0x300, 0x300),
            Load(0x3800, 0xb800, 0x1100, 0x2800)]
        for bias in (0x100000, 0x700000000000):
            maps = [Map(bias + 0x6000, bias + 0x7000, 0x2000, "/a"),
                Map(bias + 0xb000, bias + 0xc000, 0x3000, "/a"),
                Map(bias + 0xc000, bias + 0xd000, 0x4000, "/a")]
            self.assertEqual(loader.select_bias(segments, maps, 64), bias)

    def test_no_page_size_assumption(self):
        segment = Load(0x12345, 0x92345, 0x100, 0x100)
        maps = [Map(0x190000, 0x1a0000, 0x10000, "/a")]
        self.assertEqual(loader.select_bias([segment], maps, 32), 0x100000)

    def test_overlapping_file_pages_and_relro_splits(self):
        segments = [Load(0x2000, 0x2000, 0x820, 0x820),
            Load(0x2820, 0x3820, 0x1000, 0x2000)]
        maps = [Map(0x502000, 0x503000, 0x2000, "/a"),
            Map(0x503000, 0x504000, 0x2000, "/a"),
            Map(0x504000, 0x505000, 0x3000, "/a")]
        self.assertEqual(loader.select_bias(segments, maps, 32), 0x500000)
        with self.assertRaises(loader.LoaderError):
            loader.select_bias(segments, maps[:-1], 32)

    def test_duplicate_instances_require_selection(self):
        segments = [Load(0, 0, 0x1000, 0x1000)]
        maps = [Map(0x10000, 0x11000, 0, "/a"),
            Map(0x20000, 0x21000, 0, "/a")]
        self.assertEqual(loader.mapping_biases(segments, maps, 32), (0x10000, 0x20000))
        with self.assertRaisesRegex(loader.LoaderError, "ambiguous"):
            loader.select_bias(segments, maps, 32)
        self.assertEqual(loader.select_bias(segments, maps, 32, 0x20000), 0x20000)
        with self.assertRaisesRegex(loader.LoaderError, "contradicts"):
            loader.select_bias(segments, maps, 32, 0x30000)

    def test_coverage_gap_and_wrong_file_offset(self):
        segments = [Load(0, 0, 0x1000, 0x1000)]
        for maps in ([Map(0x10000, 0x10800, 0, "/a")],
                [Map(0x10000, 0x10800, 0, "/a"),
                    Map(0x10800, 0x11000, 0x900, "/a")], []):
            with self.subTest(maps=maps), self.assertRaises(loader.LoaderError):
                loader.select_bias(segments, maps, 32)

    def test_negative_bias_and_address_width(self):
        segments = [Load(0, 0x400000, 0x1000, 0x2000)]
        self.assertEqual(loader.select_bias(segments,
            [Map(0x200000, 0x201000, 0, "/a")], 32), -0x200000)
        # The mapped file bytes fit, but the relocated BSS would overflow ELF32.
        self.assertEqual(loader.mapping_biases(segments,
            [Map(0xfffff000, 0x100000000, 0, "/a")], 32), ())
        with self.assertRaises(loader.LoaderError):
            loader.select_bias(segments,
                [Map(0x100000000, 0x100001000, 0, "/a")], 32)

    def test_invalid_elf_ranges(self):
        for segments in ([], [Load(0, 0, 2, 1)], [Load(-1, 0, 1, 1)],
                [Load(0, 0, 0, 1)], [Load(0, 0xffffffff, 1, 2)]):
            with self.subTest(segments=segments), self.assertRaises(loader.LoaderError):
                loader.mapping_biases(segments, [], 32)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.code = bytes(range(256)) * 257
        self.manifest = {"schema": 1, "address_bits": 32,
            "segments": [[0, 0x1000, len(self.code), len(self.code) + 16]],
            "checks": [{"address": 0x1000, "size": len(self.code),
                "sha256": hashlib.sha256(self.code).hexdigest()}]}
        for role in ("target", "sidecar", "source"):
            path = self.root / (role + ' "with spaces"')
            path.write_bytes(role.encode() + self.code)
            self.manifest[role] = {"path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def test_bound_files_and_detached_manifest(self):
        detached = loader.validate_manifest(self.manifest)
        self.assertEqual(detached, self.manifest)
        loader.verify_files(detached)
        self.manifest["segments"][0][1] = 5
        self.assertEqual(detached["segments"][0][1], 0x1000)

    def test_changed_artifacts_are_rejected(self):
        for role in ("target", "sidecar", "source"):
            path = Path(self.manifest[role]["path"])
            old = path.read_bytes()
            path.write_bytes(old + b"changed")
            with self.assertRaisesRegex(loader.LoaderError, role + " SHA-256 mismatch"):
                loader.verify_files(self.manifest)
            path.write_bytes(old)

    def test_missing_nonregular_and_aliased_files(self):
        target = Path(self.manifest["target"]["path"])
        sidecar = Path(self.manifest["sidecar"]["path"])
        sidecar.unlink()
        with self.assertRaisesRegex(loader.LoaderError, "cannot verify sidecar"):
            loader.verify_files(self.manifest)
        sidecar.mkdir()
        with self.assertRaisesRegex(loader.LoaderError, "not a regular file"):
            loader.verify_files(self.manifest)
        sidecar.rmdir()
        os.link(target, sidecar)
        self.manifest["sidecar"]["sha256"] = self.manifest["target"]["sha256"]
        with self.assertRaisesRegex(loader.LoaderError, "alias"):
            loader.verify_files(self.manifest)

    def test_chunked_runtime_checks(self):
        reads = []
        def read(address, size):
            reads.append((address, size))
            return memoryview(self.code)[address - 0x201000:address - 0x201000 + size]
        loader.verify_memory(self.manifest, 0x200000, read)
        self.assertEqual(reads, [(0x201000, 65536), (0x211000, 256)])

    def test_runtime_mismatch_short_unreadable_and_overflow(self):
        def unreadable(address, size):
            raise RuntimeError("unmapped")
        for reader in (lambda address, size: b"\0" * size,
                lambda address, size: b"", unreadable):
            with self.assertRaises(loader.LoaderError):
                loader.verify_memory(self.manifest, 0, reader)
        with self.assertRaisesRegex(loader.LoaderError, "address width"):
            loader.verify_memory(self.manifest, 0xfffff000, lambda address, size: b"")

    def test_unsupported_or_unbound_manifest(self):
        mutations = [lambda m: m.update(schema=2), lambda m: m.update(extra=True),
            lambda m: m.update(checks=[]),
            lambda m: m["target"].update(path="relative"),
            lambda m: m["source"].update(path="/tmp/a\nquit"),
            lambda m: m["sidecar"].update(sha256="0"),
            lambda m: m["checks"][0].update(address=0),
            lambda m: m["checks"][0].update(size=-1),
            lambda m: m["segments"][0].append(5)]
        for mutate in mutations:
            changed = json.loads(json.dumps(self.manifest))
            mutate(changed)
            with self.assertRaises(loader.LoaderError):
                loader.validate_manifest(changed)

    def test_identifier_is_deterministic_and_binding_specific(self):
        first = loader.manifest_id(self.manifest)
        self.assertEqual(first, loader.manifest_id(dict(reversed(list(self.manifest.items())))))
        self.manifest["target"]["sha256"] = "0" * 64
        self.assertNotEqual(first, loader.manifest_id(self.manifest))


if __name__ == "__main__":
    unittest.main()
