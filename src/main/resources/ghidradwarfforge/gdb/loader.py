"""Forge companion runtime. No GDB commands execute when this module is imported.

Mapping arithmetic deliberately does not assume an architecture, page size or
section table. The GDB adapter and manifest generator supply selected identity
and PT_LOAD evidence; a mapping pathname alone is not an identity proof.
"""

import hashlib
import json
import os
import re
import stat
from typing import NamedTuple


class LoaderError(ValueError):
    """Missing, contradictory or unsupported loader evidence."""


class Mapping(NamedTuple):
    start: int
    end: int
    offset: int
    path: str


class LoadSegment(NamedTuple):
    offset: int
    address: int
    file_size: int
    memory_size: int


_HEX = r"0x[0-9a-fA-F]{1,16}"
_MAPPING = re.compile(
    r"^\s*(" + _HEX + r")\s+(" + _HEX + r")\s+(" + _HEX +
    r")\s+(" + _HEX + r")(?:\s+(.*))?$")
_PERMISSIONS = re.compile(r"^[r-][w-][x-][ps-](?:\s+|$)")
_MAX_ROWS = 4096
_MAX_SEGMENTS = 1024
_MAX_CANDIDATES = 256


def parse_mappings(text):
    """Parse GDB Linux `info proc mappings`, with or without permissions.

    Retain complete path spellings, including spaces. Path selection is exact
    and performed by the caller; basename matching would conflate modules.
    Unsupported layouts fail explicitly instead of implying no mappings.
    """
    if not isinstance(text, str) or len(text) > 8 * 1024 * 1024:
        raise LoaderError("mapping output exceeds the supported size")
    mappings = []
    for line in text.splitlines():
        if not line.lstrip().startswith("0x"):
            continue
        match = _MAPPING.fullmatch(line)
        if match is None:
            raise LoaderError("unsupported process mapping row")
        start, end, size, offset = (int(value, 16) for value in match.groups()[:4])
        if end <= start or size != end - start or offset + size > 1 << 64:
            raise LoaderError("inconsistent process mapping bounds")
        path = match.group(5) or ""
        permissions = _PERMISSIONS.match(path)
        if permissions:
            path = path[permissions.end():]
        if any(ord(character) < 32 or ord(character) == 127 for character in path):
            raise LoaderError("unsupported control character in mapping pathname")
        mappings.append(Mapping(start, end, offset, path))
        if len(mappings) > _MAX_ROWS:
            raise LoaderError("too many process mappings")
    if not mappings:
        raise LoaderError("process mappings are unavailable; supply an explicit load bias")
    return tuple(mappings)


def _check_segments(segments, address_bits):
    if address_bits not in (32, 64):
        raise LoaderError("unsupported target address width")
    if not segments or len(segments) > _MAX_SEGMENTS:
        raise LoaderError("missing or excessive ELF load segments")
    limit = 1 << address_bits
    for segment in segments:
        if any(type(value) is not int or value < 0 for value in segment):
            raise LoaderError("invalid ELF load segment")
        if (segment.file_size > segment.memory_size or
                segment.address >= limit or
                segment.address + segment.memory_size > limit or
                segment.offset + segment.file_size > 1 << 64):
            raise LoaderError("invalid ELF load segment bounds")
    if not any(segment.file_size for segment in segments):
        raise LoaderError("no file-backed ELF load segment")


def _covered(segment, mappings, bias):
    # Compare in file-offset coordinates. A mapping may split a segment, start
    # before it (page padding), or share file bytes with another LOAD segment.
    intervals = []
    for mapping in mappings:
        if mapping.start - mapping.offset != bias + segment.address - segment.offset:
            continue
        start = max(segment.offset, mapping.offset)
        end = min(segment.offset + segment.file_size,
            mapping.offset + mapping.end - mapping.start)
        if end > start:
            intervals.append((start, end))
    cursor = segment.offset
    for start, end in sorted(intervals):
        if start > cursor:
            return False
        cursor = max(cursor, end)
    return cursor >= segment.offset + segment.file_size


def mapping_biases(segments, mappings, address_bits):
    """Return every bias completely supported by selected module mappings.

    All file-backed LOAD bytes must have consistent offset/address coverage.
    Multiple instances (including dlmopen or independent mappings of one file)
    remain multiple candidates. The caller must not silently pick one.
    Runtime memory identity remains a separate mandatory verification step.
    """
    _check_segments(segments, address_bits)
    limit = 1 << address_bits
    if len(mappings) > _MAX_ROWS:
        raise LoaderError("too many selected process mappings")
    for mapping in mappings:
        if (any(type(value) is not int for value in mapping[:3]) or
                not 0 <= mapping.start < mapping.end <= limit or
                mapping.offset < 0 or
                mapping.offset + mapping.end - mapping.start > 1 << 64):
            raise LoaderError("mapping exceeds target address bounds")
    # Every valid instance must cover the first byte of this segment. Use that
    # byte as an anchor rather than forming a quadratic candidate cross product.
    anchor = next(segment for segment in segments if segment.file_size)
    candidates = set()
    for mapping in mappings:
        if mapping.offset <= anchor.offset < mapping.offset + mapping.end - mapping.start:
            candidates.add(mapping.start + anchor.offset - mapping.offset - anchor.address)
            if len(candidates) > _MAX_CANDIDATES:
                raise LoaderError("too many possible runtime module instances")
    valid = []
    for bias in sorted(candidates):
        if all(0 <= segment.address + bias < limit and
                segment.address + bias + segment.memory_size <= limit and
                (not segment.file_size or _covered(segment, mappings, bias))
                for segment in segments):
            valid.append(bias)
    return tuple(valid)


def select_bias(segments, mappings, address_bits, override=None):
    """Select a unique evidence-backed bias; an override selects an instance.

    With unavailable mappings the adapter must separately validate an explicit
    override against target memory. Passing an empty list here is not a bypass.
    """
    candidates = mapping_biases(segments, mappings, address_bits)
    if override is not None:
        if type(override) is not int or override not in candidates:
            raise LoaderError("explicit load bias contradicts runtime mappings")
        return override
    if not candidates:
        raise LoaderError("no complete ELF LOAD mapping; provide mapping evidence or an explicit load bias")
    if len(candidates) != 1:
        raise LoaderError("ambiguous runtime module instances; supply an explicit load bias")
    return candidates[0]


def _path(value):
    if (not isinstance(value, str) or not value or len(value) > 16384 or
            any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise LoaderError("unsupported pathname in loader manifest")
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise LoaderError("invalid SHA-256 in loader manifest")


def validate_manifest(manifest):
    """Validate and detach the generated schema before registering commands."""
    if not isinstance(manifest, dict) or set(manifest) != {
            "schema", "target", "sidecar", "source", "address_bits", "segments", "checks"}:
        raise LoaderError("unsupported loader manifest fields")
    if type(manifest["schema"]) is not int or manifest["schema"] != 1:
        raise LoaderError("unsupported loader manifest version")
    for role in ("target", "sidecar", "source"):
        artifact = manifest[role]
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise LoaderError("invalid loader artifact binding")
        if not os.path.isabs(_path(artifact["path"])):
            raise LoaderError("loader artifact paths must be absolute")
        _digest(artifact["sha256"])
    rows = manifest["segments"]
    if not isinstance(rows, list) or any(not isinstance(row, list) or len(row) != 4 for row in rows):
        raise LoaderError("invalid loader segment table")
    segments = [LoadSegment(*row) for row in rows]
    _check_segments(segments, manifest["address_bits"])
    checks = manifest["checks"]
    if not isinstance(checks, list) or not checks or len(checks) > _MAX_SEGMENTS:
        raise LoaderError("missing or excessive runtime identity checks")
    total = 0
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"address", "size", "sha256"}:
            raise LoaderError("invalid runtime identity check")
        address, size = check["address"], check["size"]
        if type(address) is not int or type(size) is not int or size <= 0:
            raise LoaderError("invalid runtime identity bounds")
        if not any(segment.address <= address and
                address + size <= segment.address + segment.file_size for segment in segments):
            raise LoaderError("runtime identity check is outside file-backed LOAD bytes")
        _digest(check["sha256"])
        total += size
    if total > 1024 * 1024 * 1024:
        raise LoaderError("runtime identity checks exceed the supported size")
    return json.loads(json.dumps(manifest, sort_keys=True))


def manifest_id(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()[:16]


def _identity(attributes):
    return (attributes.st_dev, attributes.st_ino, attributes.st_size,
        attributes.st_mtime_ns, attributes.st_ctime_ns)


def verify_files(manifest):
    """Stream every explicitly selected artifact; never read paths from reports."""
    identities = []
    for role in ("target", "sidecar", "source"):
        artifact = manifest[role]
        path = artifact["path"]
        try:
            if not stat.S_ISREG(os.stat(path).st_mode):
                raise LoaderError(role + " is not a regular file")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise LoaderError(role + " is not a regular file")
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(65536), b""):
                    digest.update(chunk)
                if (_identity(before) != _identity(os.fstat(stream.fileno())) or
                        _identity(before) != _identity(os.stat(path))):
                    raise LoaderError(role + " changed during identity verification")
            if digest.hexdigest() != artifact["sha256"]:
                raise LoaderError(role + " SHA-256 mismatch; regenerate the companion for the selected artifacts")
            identity = (before.st_dev, before.st_ino)
            if identity in identities:
                raise LoaderError("loader artifacts alias one another")
            identities.append(identity)
        except OSError as error:
            raise LoaderError("cannot verify " + role + ": " + str(error)) from error


def verify_memory(manifest, bias, read_memory):
    """Check selected immutable file bytes at the proposed runtime addresses.

    The producer selects executable file-backed LOAD ranges. Text relocations,
    patched/self-modifying code and unreadable ranges fail explicitly. This is
    image matching, not an assertion of original-source provenance.
    """
    limit = 1 << manifest["address_bits"]
    if type(bias) is not int:
        raise LoaderError("load bias must be an integer")
    for offset, address, file_size, memory_size in manifest["segments"]:
        if not 0 <= address + bias < limit or address + bias + memory_size > limit:
            raise LoaderError("relocated LOAD range exceeds target address width")
    for check in manifest["checks"]:
        digest = hashlib.sha256()
        cursor = 0
        while cursor < check["size"]:
            count = min(65536, check["size"] - cursor)
            try:
                chunk = bytes(read_memory(bias + check["address"] + cursor, count))
            except Exception as error:
                raise LoaderError("runtime identity bytes are unreadable at the proposed load bias") from error
            if len(chunk) != count:
                raise LoaderError("incomplete runtime identity read")
            digest.update(chunk)
            cursor += count
        if digest.hexdigest() != check["sha256"]:
            raise LoaderError("runtime image mismatch; wrong load bias, changed code or unsupported text relocation")


def _quote(path):
    return '"' + _path(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def register(manifest):
    """Explicitly register a companion; never load symbols merely by sourcing it."""
    import gdb

    manifest = validate_manifest(manifest)
    registry = getattr(gdb, "_forge_loader_registry_v1", None)
    if registry is None:
        registry = _Registry(gdb)
        gdb._forge_loader_registry_v1 = registry
    return registry.register(manifest)


class _Registry:
    def __init__(self, gdb):
        self.gdb = gdb
        self.manifests = {}
        self.loaded = {}
        self.busy = False
        event_names = ("exited", "executable_changed", "new_inferior",
            "clear_objfiles", "free_objfile", "stop")
        for name in event_names:
            if not hasattr(gdb.events, name):
                raise LoaderError("GDB lacks required lifecycle event: " + name)
        if not hasattr(gdb, "with_parameter"):
            raise LoaderError("GDB lacks scoped parameter support")
        registry = self

        class Command(gdb.Command):
            def __init__(self, name, unload):
                super().__init__(name, gdb.COMMAND_FILES)
                self.unload = unload

            def invoke(self, argument, from_tty):
                self.dont_repeat()
                try:
                    registry.invoke(argument, self.unload)
                except (LoaderError, OSError, ValueError) as error:
                    raise gdb.GdbError("Forge loader: " + str(error)) from error

        self.commands = (Command("forge-load", False), Command("forge-unload", True))
        self.handlers = []
        for name, handler in (("exited", self.invalidate),
                ("executable_changed", self.invalidate),
                ("new_inferior", self.invalidate), ("clear_objfiles", self.cleared),
                ("free_objfile", self.freed), ("stop", self.stopped)):
            event = getattr(gdb.events, name, None)
            event.connect(handler)
            self.handlers.append((event, handler))

    def register(self, manifest):
        identifier = manifest_id(manifest)
        if identifier in self.manifests and self.manifests[identifier] != manifest:
            raise LoaderError("companion identifier collision")
        self.manifests[identifier] = manifest
        self.gdb.write("Forge companion registered: forge-load " + identifier +
            " [--bias INTEGER] [--module EXACT_RUNTIME_PATH]\n")
        return identifier

    def invoke(self, argument, unload):
        args = self.gdb.string_to_argv(argument)
        if args == ["--list"] and not unload:
            for identifier, manifest in sorted(self.manifests.items()):
                self.gdb.write(identifier + " " + manifest["sidecar"]["path"] + "\n")
            return
        identifier = args.pop(0) if args and not args[0].startswith("--") else None
        if identifier is None:
            if len(self.manifests) != 1:
                raise LoaderError("select a companion identifier; use forge-load --list")
            identifier = next(iter(self.manifests))
        if identifier not in self.manifests:
            raise LoaderError("unknown companion identifier")
        if unload:
            if args:
                raise LoaderError("usage: forge-unload [COMPANION_ID]")
            self.remove(identifier)
            return
        options = {}
        while args:
            option = args.pop(0)
            if option not in ("--bias", "--module") or not args or option in options:
                raise LoaderError("usage: forge-load [COMPANION_ID] [--bias INTEGER] [--module EXACT_RUNTIME_PATH]")
            options[option] = args.pop(0)
        bias = None
        if "--bias" in options:
            value = options["--bias"]
            if not re.fullmatch(r"[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)", value) or len(value) > 24:
                raise LoaderError("bias must be a literal integer, not an expression or runtime .text address")
            bias = int(value, 16 if "x" in value.lower() else 10)
        module = _path(options.get("--module", self.manifests[identifier]["target"]["path"]))
        self.load(identifier, module, bias)

    def mapping_bias(self, manifest, module, override):
        try:
            text = self.gdb.execute("info proc mappings", to_string=True)
        except self.gdb.error as error:
            if override is None:
                raise LoaderError("runtime mappings unavailable; supply --bias and retain runtime identity verification") from error
            return override, False
        # Empty/unsupported output may occur on remote transports. Malformed
        # rows or contradictory existing mappings must never become a bypass.
        if not any(line.lstrip().startswith("0x") for line in text.splitlines()):
            if override is None:
                raise LoaderError("runtime mappings unavailable; supply --bias")
            return override, False
        mappings = [row for row in parse_mappings(text) if row.path == module]
        segments = [LoadSegment(*row) for row in manifest["segments"]]
        return select_bias(segments, mappings, manifest["address_bits"], override), True

    def load(self, identifier, module, override):
        gdb = self.gdb
        if len(gdb.inferiors()) != 1:
            raise LoaderError("use a single-inferior GDB session for this companion")
        inferior = gdb.selected_inferior()
        if not inferior.pid or any(thread.is_running() for thread in inferior.threads()):
            raise LoaderError("stop the running target before loading its companion")
        manifest = self.manifests[identifier]
        if gdb.lookup_type("void").pointer().sizeof * 8 != manifest["address_bits"]:
            raise LoaderError("GDB target address width disagrees with the companion")
        verify_files(manifest)
        bias, discovered = self.mapping_bias(manifest, module, override)
        verify_memory(manifest, bias, inferior.read_memory)
        previous = self.loaded.get(identifier)
        if previous is not None:
            if (previous["object"].is_valid() and previous["bias"] == bias and
                    previous["inferior"] == inferior and previous["module"] == module):
                gdb.write("Forge companion already loaded at bias " + hex(bias) + "\n")
                return
            self.remove(identifier)
        sidecar = os.path.realpath(manifest["sidecar"]["path"])
        if any(obj.filename and os.path.realpath(obj.filename) == sidecar for obj in gdb.objfiles()):
            raise LoaderError("sidecar is already loaded outside this companion; unload it explicitly first")
        before = list(gdb.objfiles())
        self.busy = True
        try:
            with gdb.with_parameter("confirm", False):
                gdb.execute("add-symbol-file " + _quote(sidecar) + " -o " + hex(bias), to_string=True)
            added = [obj for obj in gdb.objfiles() if obj not in before and obj.filename and
                os.path.realpath(obj.filename) == sidecar]
            if len(added) != 1:
                raise LoaderError("GDB did not install exactly one selected sidecar")
            self.loaded[identifier] = {"object": added[0], "bias": bias,
                "inferior": inferior, "module": module, "discovered": discovered}
            verify_files(manifest)
        except BaseException:
            # A cancelled command may have installed an objfile before returning.
            if any(obj not in before and obj.filename and os.path.realpath(obj.filename) == sidecar
                    for obj in gdb.objfiles()):
                with gdb.with_parameter("confirm", False):
                    gdb.execute("remove-symbol-file " + _quote(sidecar), to_string=True)
            self.loaded.pop(identifier, None)
            raise
        finally:
            self.busy = False
        gdb.write("Forge companion loaded at bias " + hex(bias) + "\n")

    def remove(self, identifier):
        state = self.loaded.get(identifier)
        if state is None:
            return
        obj = state["object"]
        if obj.is_valid():
            if obj.progspace != self.gdb.current_progspace():
                raise LoaderError("select the original inferior before unloading its companion")
            self.busy = True
            try:
                with self.gdb.with_parameter("confirm", False):
                    self.gdb.execute("remove-symbol-file " + _quote(obj.filename), to_string=True)
            finally:
                self.busy = False
        self.loaded.pop(identifier, None)

    def invalidate(self, event):
        if self.busy:
            return
        for identifier in list(self.loaded):
            self.remove(identifier)

    def cleared(self, event):
        if not self.busy:
            for identifier, state in list(self.loaded.items()):
                if not state["object"].is_valid():
                    self.loaded.pop(identifier)

    def freed(self, event):
        if self.busy:
            return
        for identifier, state in list(self.loaded.items()):
            if event.objfile == state["object"]:
                self.loaded.pop(identifier)
            elif event.objfile.filename == state["module"]:
                self.remove(identifier)

    def stopped(self, event):
        if self.busy:
            return
        for identifier, state in list(self.loaded.items()):
            manifest = self.manifests[identifier]
            try:
                if len(self.gdb.inferiors()) != 1 or state["inferior"] != self.gdb.selected_inferior():
                    raise LoaderError("inferior selection changed")
                if state["discovered"]:
                    unused_bias, discovered = self.mapping_bias(manifest, state["module"], state["bias"])
                    if not discovered:
                        raise LoaderError("previously available runtime mappings were lost")
                verify_memory(manifest, state["bias"], state["inferior"].read_memory)
            except (LoaderError, self.gdb.error) as error:
                self.remove(identifier)
                self.gdb.write("Forge companion invalidated: " + str(error) +
                    "; invoke forge-load again after establishing the mapping\n")
