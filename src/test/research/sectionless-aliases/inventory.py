"""Bounded PT_DYNAMIC research reader. No section headers or guessed extents."""
from pathlib import Path
import struct

MAX_ROWS = 262144
MAX_BYTES = 16 * 1024 * 1024


class Unsupported(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Unsupported(message)


class Inventory:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        require(len(self.data) >= 64 and self.data[:4] == b'\x7fELF', 'ELF header')
        require(self.data[4] in (1, 2) and self.data[5] in (1, 2), 'ELF encoding')
        self.wide = self.data[4] == 2
        self.order = '<' if self.data[5] == 1 else '>'
        header = self.unpack('HHIQQQIHHHHHH' if self.wide else 'HHIIIIIHHHHHH', 16)
        require(header[5] == header[11] == header[12] == 0, 'research input must be sectionless')
        self.machine = header[1]
        offset, width, count = header[4], header[8], header[9]
        require(width == (56 if self.wide else 32) and 0 < count < 65535, 'program table framing')
        self.loads = []
        dynamic = []
        for index in range(count):
            fields = self.unpack('IIQQQQQQ' if self.wide else 'IIIIIIII', offset + index * width)
            if self.wide:
                kind, flags, file, address, _, size, memory, _ = fields
            else:
                kind, file, address, _, size, memory, flags, _ = fields
            require(file <= len(self.data) and size <= len(self.data) - file, 'segment file extent')
            if kind == 1:
                require(size <= memory and address + memory <= (1 << (64 if self.wide else 32)), 'load extent')
                if memory:
                    self.loads.append((address, memory, file, size, flags, index))
            if kind == 2:
                dynamic.append((file, size))
        require(len(dynamic) == 1, 'requires one dynamic segment')
        file, size = dynamic[0]
        width = 16 if self.wide else 8
        require(0 < size <= MAX_BYTES and size % width == 0, 'dynamic framing')
        self.tags = {}
        critical = {4, 5, 6, 10, 11, 34, 0x6ffffef5, 0x6ffffff0, 0x6ffffffc, 0x6ffffffd, 0x70000011}
        for at in range(file, file + size, width):
            tag, value = self.unpack('QQ' if self.wide else 'II', at)
            if tag == 0:
                break
            if tag in critical:
                require(tag not in self.tags, 'duplicate dynamic tag')
                self.tags[tag] = value
        else:
            raise Unsupported('unterminated dynamic segment')
        require({5, 6, 10, 11} <= self.tags.keys(), 'missing symbol framing')
        self.width = 24 if self.wide else 16
        require(self.tags[11] == self.width and 0 < self.tags[10] <= MAX_BYTES, 'symbol/string size')
        self.counts = {}
        if 4 in self.tags:
            buckets, count = self.virtual_unpack('II', self.tags[4])
            require(0 < buckets <= MAX_ROWS and 0 < count <= MAX_ROWS, 'SysV hash limits')
            payload = self.virtual(self.tags[4] + 8, 4 * (buckets + count))
            require(all(value < count for (value,) in struct.iter_unpack(self.order + 'I', payload)), 'SysV hash index')
            self.counts['sysv'] = count
        if self.machine == 8 and 0x70000011 in self.tags:
            count = self.tags[0x70000011]
            require(0 < count <= MAX_ROWS, 'MIPS symbol count')
            self.counts['mips'] = count
        self.empty_gnu = False
        if 0x6ffffef5 in self.tags:
            address = self.tags[0x6ffffef5]
            buckets, first, bloom, shift = self.virtual_unpack('IIII', address)
            require(0 < buckets <= MAX_ROWS and 0 < first <= MAX_ROWS and
                0 < bloom <= MAX_ROWS and bloom & (bloom - 1) == 0 and shift < 32, 'GNU hash framing')
            base = address + 16 + bloom * (8 if self.wide else 4)
            self.virtual(address, base - address)
            values = [v for (v,) in struct.iter_unpack(self.order + 'I', self.virtual(base, buckets * 4))]
            starts = sorted(v for v in values if v)
            require(len(starts) == len(set(starts)), 'overlapping GNU buckets')
            self.empty_gnu = not starts
            if starts:
                require(starts[0] == first, 'GNU hash omitted first hashed symbol')
                cursor = first
                for start in starts:
                    require(start == cursor, 'GNU hash gap/overlap')
                    while True:
                        require(cursor < MAX_ROWS, 'GNU chain limit')
                        value, = self.virtual_unpack('I', base + buckets * 4 + (cursor - first) * 4)
                        cursor += 1
                        if value & 1:
                            break
                self.counts['gnu'] = cursor
        require(self.counts, 'complete symbol count unavailable (an empty GNU hash is not a count)')
        require(len(set(self.counts.values())) == 1, 'symbol count sources disagree')
        self.count = next(iter(self.counts.values()))
        self.raw = self.virtual(self.tags[6], self.count * self.width)
        self.strings = self.virtual(self.tags[5], self.tags[10])
        require(self.strings[0] == self.strings[-1] == 0, 'string boundary')
        require(self.raw[:self.width] == bytes(self.width), 'null symbol')
        require(34 not in self.tags, 'extended dynamic indices need separate evidence')
        self.versions = self.virtual(self.tags[0x6ffffff0], self.count * 2) if 0x6ffffff0 in self.tags else None
        require((0x6ffffffc in self.tags) == (0x6ffffffd in self.tags), 'version definition pair')
        definitions = {}
        if 0x6ffffffc in self.tags:
            require(self.versions is not None, 'definition without versions')
            count = self.tags[0x6ffffffd]
            require(0 < count <= MAX_ROWS, 'version definition count')
            address = self.tags[0x6ffffffc]
            total = 0
            for index in range(count):
                revision, flags, identifier, members, _, aux, following = self.virtual_unpack('HHHHIII', address)
                require(revision == 1 and flags & ~7 == 0 and 0 < identifier < 0x8000 and members > 0 and aux >= 20, 'version definition')
                total += members
                require(total <= MAX_ROWS and (index == count - 1) == (following == 0), 'version chain count')
                require(following == 0 or following >= aux + 8, 'version extent')
                location = address + aux
                for member in range(members):
                    require(following == 0 or location + 8 <= address + following, 'aux outside definition')
                    name, next_aux = self.virtual_unpack('II', location)
                    text = self.name(name)
                    require(text and (member == members - 1) == (next_aux == 0), 'version auxiliary')
                    if member == 0:
                        require(identifier not in definitions, 'duplicate version')
                        definitions[identifier] = text
                    require(next_aux == 0 or next_aux >= 8, 'aux chain')
                    location += next_aux
                address += following
        self.records = bytearray(self.raw)
        self.names = bytearray(self.strings)
        self.locals = 0
        seen_nonlocal = False
        self.changes = []
        for index in range(self.count):
            at = index * self.width
            if self.wide:
                name, info, other, section, value, size = self.unpack('IBBHQQ', at, self.raw)
            else:
                name, value, size, info, other, section = self.unpack('IIIBBH', at, self.raw)
            text = self.name(name)
            local = info >> 4 == 0
            require(not (local and seen_nonlocal), 'local after nonlocal')
            self.locals += local
            seen_nonlocal |= not local
            require(info & 15 != 6 or section == 0, 'defined TLS requires TLS-specific mapping')
            if section not in (0, 0xfff1, 0xfff2):
                require(section < 0xff00, 'unverified reserved section semantics')
                matches = [i + 1 for i, (address, memory, *_) in enumerate(self.loads)
                    if address <= value < address + memory and size <= address + memory - value]
                if not matches and size == 0:
                    matches = [i + 1 for i, (address, memory, *_) in enumerate(self.loads) if value == address + memory]
                require(len(matches) == 1 and matches[0] < 0xff00, 'definition has no unique load allocation')
                struct.pack_into(self.order + 'H', self.records, at + (6 if self.wide else 14), matches[0])
                self.changes.append({'index': index, 'originalSection': section, 'loadSection': matches[0]})
            if self.versions:
                version, = struct.unpack_from(self.order + 'H', self.versions, index * 2)
                require(index != 0 or version == 0, 'versioned null symbol')
                identifier = version & 0x7fff
                if section != 0 and identifier > 1:
                    require(identifier in definitions, 'missing version definition')
                    suffix = definitions[identifier]
                    if section == 0xfff1 and value == 0 and text == suffix:
                        continue
                    qualified = text + (b'@' if version & 0x8000 else b'@@') + suffix
                    require(text and len(qualified) <= 65536 and len(self.names) + len(qualified) + 1 <= MAX_BYTES, 'qualified name limit')
                    struct.pack_into(self.order + 'I', self.records, at, len(self.names))
                    self.names.extend(qualified + b'\0')

    def unpack(self, fmt, offset, data=None):
        data = self.data if data is None else data
        size = struct.calcsize(self.order + fmt)
        require(0 <= offset <= len(data) and size <= len(data) - offset, 'truncated file data')
        return struct.unpack_from(self.order + fmt, data, offset)

    def virtual(self, address, size):
        require(0 <= size <= MAX_BYTES, 'virtual read limit')
        matches = [(file + address - base) for base, memory, file, length, *_ in self.loads
            if base <= address and address - base <= length and size <= length - (address - base)]
        require(len(matches) == 1, 'virtual read has no unique file backing')
        at = matches[0]
        return self.data[at:at + size]

    def virtual_unpack(self, fmt, address):
        return struct.unpack(self.order + fmt, self.virtual(address, struct.calcsize(self.order + fmt)))

    def name(self, offset):
        require(0 <= offset < len(self.strings), 'string offset')
        end = self.strings.find(b'\0', offset, min(len(self.strings), offset + 65537))
        require(end >= offset, 'name termination/limit')
        return self.strings[offset:end]
