"""Forge companion runtime. No GDB commands execute when this module is imported.

Mapping arithmetic deliberately does not assume an architecture, page size or
section table. The GDB adapter and manifest generator supply selected identity
and PT_LOAD evidence; a mapping pathname alone is not an identity proof.
"""

import re
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
