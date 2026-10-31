package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Bounded PT_DYNAMIC inventory. No count is inferred from adjacent pointers or relocations. */
final class SectionlessDynamicSymbols {
    private static final int MAX_SYMBOLS = 262144;
    private static final long GNU_HASH = 0x6ffffef5L;
    private static final long VERSYM = 0x6ffffff0L;
    private static final long VERDEF = 0x6ffffffcL;
    private static final long VERDEFNUM = 0x6ffffffdL;
    private static final Set<Long> SINGLETONS = Set.of(4L, 5L, 6L, 10L, 11L, 34L,
        GNU_HASH, VERSYM, VERDEF, VERDEFNUM, MipsDynamicSymbols.DT_MIPS_SYMTABNO);

    private SectionlessDynamicSymbols() {
    }

    static DynamicSymbolMirror.Input read(ElfImage image, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        ElfImage.Segment dynamic = null;
        for (var segment : image.segments()) {
            checkCancelled(cancelled);
            if (segment.type == 2) {
                require(dynamic == null, "multiple PT_DYNAMIC inventories");
                dynamic = segment;
            }
        }
        if (dynamic == null) {
            return null;
        }
        try (Reader reader = new Reader(image, cancelled)) {
            var tags = tags(reader, dynamic);
            int width = image.is64Bit() ? 24 : 16;
            require(tags.keySet().containsAll(Set.of(5L, 6L, 10L, 11L)) && tags.get(11L) == width &&
                tags.get(10L) > 0 && tags.get(10L) <= ElfImage.MAX_NAME_TABLE_BYTES,
                "unsupported PT_DYNAMIC symbol/string framing");
            int count = count(reader, tags);
            byte[] records = reader.bytes(tags.get(6L), (long) count * width);
            byte[] names = reader.bytes(tags.get(5L), tags.get(10L));
            ByteBuffer rows = ByteBuffer.wrap(records).order(image.byteOrder());
            ByteBuffer originalIndices = tags.containsKey(34L) ? reader.buffer(tags.get(34L), count * 4L) : null;
            ByteBuffer indices = ByteBuffer.allocate(count * 4).order(image.byteOrder());
            boolean hasExtended = false;
            int locals = 0;
            boolean nonlocal = false;
            for (int index = 0; index < count; index++) {
                checkCancelled(cancelled);
                int offset = index * width;
                int info = Byte.toUnsignedInt(records[offset + (image.is64Bit() ? 4 : 12)]);
                boolean local = (info >>> 4) == 0;
                require(!local || !nonlocal, "PT_DYNAMIC local symbol follows a nonlocal symbol");
                if (local) {
                    locals++;
                }
                nonlocal |= !local;
                int field = offset + (image.is64Bit() ? 6 : 14);
                int section = Short.toUnsignedInt(rows.getShort(field));
                long escaped = originalIndices == null ? 0 : Integer.toUnsignedLong(originalIndices.getInt(index * 4));
                require(section == 0xffff ? escaped > 0 : escaped == 0,
                    "invalid PT_DYNAMIC extended section index");
                require(section == 0 || (info & 15) != 6,
                    "defined PT_DYNAMIC TLS symbol requires a TLS-relative allocation policy");
                if (section == 0 || section == 0xfff1 || section == 0xfff2) {
                    continue;
                }
                require(section < 0xff00 || section == 0xffff, "unsupported PT_DYNAMIC reserved section index");
                long value = image.is64Bit() ? rows.getLong(offset + 8) : Integer.toUnsignedLong(rows.getInt(offset + 4));
                long size = image.is64Bit() ? rows.getLong(offset + 16) : Integer.toUnsignedLong(rows.getInt(offset + 8));
                int allocation = reader.definition(value, size);
                if (allocation >= 0xff00) {
                    rows.putShort(field, (short) 0xffff);
                    indices.putInt(index * 4, allocation);
                    hasExtended = true;
                }
                else {
                    rows.putShort(field, (short) allocation);
                }
            }
            byte[] versions = tags.containsKey(VERSYM) ? reader.bytes(tags.get(VERSYM), count * 2L) : null;
            require(tags.containsKey(VERDEF) == tags.containsKey(VERDEFNUM), "incomplete PT_DYNAMIC version-definition pair");
            byte[] definitions = null;
            long definitionCount = 0;
            if (tags.containsKey(VERDEF)) {
                require(versions != null, "PT_DYNAMIC definitions lack symbol versions");
                definitionCount = tags.get(VERDEFNUM);
                definitions = definitions(reader, tags.get(VERDEF), definitionCount);
            }
            reader.verify();
            return new DynamicSymbolMirror.Input(locals, records, names, hasExtended ? indices.array() : null,
                versions, definitions, definitionCount, reader.allocations.size() + 1);
        }
    }

    private static Map<Long, Long> tags(Reader reader, ElfImage.Segment dynamic) throws IOException {
        int width = reader.image.is64Bit() ? 16 : 8;
        require(dynamic.fileSize >= width && dynamic.fileSize <= ElfImage.MAX_NAME_TABLE_BYTES &&
            dynamic.fileSize % width == 0, "unsupported PT_DYNAMIC framing");
        require(reader.locate(dynamic.virtualAddress, dynamic.fileSize) == dynamic.offset,
            "PT_DYNAMIC file and virtual mappings disagree");
        ByteBuffer bytes = reader.buffer(dynamic.virtualAddress, dynamic.fileSize);
        Map<Long, Long> tags = new HashMap<>();
        for (int at = 0; at < bytes.limit(); at += width) {
            checkCancelled(reader.cancelled);
            long tag = reader.image.is64Bit() ? bytes.getLong(at) : Integer.toUnsignedLong(bytes.getInt(at));
            long value = reader.image.is64Bit() ? bytes.getLong(at + 8) : Integer.toUnsignedLong(bytes.getInt(at + 4));
            if (tag == 0) {
                return tags;
            }
            if (SINGLETONS.contains(tag)) {
                require(value >= 0 && tags.putIfAbsent(tag, value) == null, "invalid or duplicate PT_DYNAMIC metadata tag");
            }
        }
        throw new IllegalArgumentException("unterminated PT_DYNAMIC inventory");
    }

    private static int count(Reader reader, Map<Long, Long> tags) throws IOException {
        List<Long> counts = new ArrayList<>();
        if (tags.containsKey(4L)) {
            long address = tags.get(4L);
            ByteBuffer header = reader.buffer(address, 8);
            long buckets = Integer.toUnsignedLong(header.getInt(0));
            long count = Integer.toUnsignedLong(header.getInt(4));
            require(buckets > 0 && buckets <= MAX_SYMBOLS && count > 0 && count <= MAX_SYMBOLS,
                "PT_DYNAMIC SysV hash exceeds limits");
            ByteBuffer values = reader.buffer(add(address, 8), (buckets + count) * 4);
            while (values.hasRemaining()) {
                checkCancelled(reader.cancelled);
                require(Integer.toUnsignedLong(values.getInt()) < count, "PT_DYNAMIC SysV hash index exceeds count");
            }
            counts.add(count);
        }
        Long mips = MipsDynamicSymbols.count(reader.image, tags);
        if (mips != null) {
            counts.add(mips);
        }
        if (tags.containsKey(GNU_HASH)) {
            long gnu = gnuCount(reader, tags.get(GNU_HASH));
            if (gnu != 0) {
                counts.add(gnu);
            }
        }
        require(!counts.isEmpty(), "complete PT_DYNAMIC symbol count unavailable; empty GNU hash is not a count");
        long count = counts.getFirst();
        require(count > 0 && count <= MAX_SYMBOLS, "PT_DYNAMIC symbol count exceeds limits");
        for (long observed : counts) {
            require(count == observed, "PT_DYNAMIC symbol count sources disagree");
        }
        return (int) count;
    }

    private static long gnuCount(Reader reader, long address) throws IOException {
        ByteBuffer header = reader.buffer(address, 16);
        long bucketCount = Integer.toUnsignedLong(header.getInt(0));
        long first = Integer.toUnsignedLong(header.getInt(4));
        long bloom = Integer.toUnsignedLong(header.getInt(8));
        long shift = Integer.toUnsignedLong(header.getInt(12));
        require(bucketCount > 0 && bucketCount <= MAX_SYMBOLS && first > 0 && first <= MAX_SYMBOLS &&
            bloom > 0 && bloom <= MAX_SYMBOLS && (bloom & (bloom - 1)) == 0 && shift < 32,
            "unsupported PT_DYNAMIC GNU hash framing");
        long bloomSize = bloom * (reader.image.is64Bit() ? 8 : 4);
        long bucketsAddress = add(address, 16 + bloomSize);
        reader.locate(address, 16 + bloomSize); // Prove the complete header/bloom extent exists.
        ByteBuffer buckets = reader.buffer(bucketsAddress, bucketCount * 4);
        List<Long> starts = new ArrayList<>();
        while (buckets.hasRemaining()) {
            checkCancelled(reader.cancelled);
            long start = Integer.toUnsignedLong(buckets.getInt());
            if (start != 0) {
                require(start >= first && start < MAX_SYMBOLS, "GNU bucket outside symbol bounds");
                starts.add(start);
            }
        }
        if (starts.isEmpty()) {
            return 0;
        }
        starts.sort(Long::compare);
        long cursor = first;
        long chains = add(bucketsAddress, bucketCount * 4);
        for (long start : starts) {
            checkCancelled(reader.cancelled);
            require(start == cursor, "PT_DYNAMIC GNU chains overlap or leave a gap");
            while (true) {
                checkCancelled(reader.cancelled);
                require(cursor < MAX_SYMBOLS, "PT_DYNAMIC GNU chain exceeds symbol budget");
                long value = Integer.toUnsignedLong(reader.buffer(add(chains, (cursor - first) * 4), 4).getInt());
                cursor++;
                if ((value & 1) != 0) {
                    break;
                }
            }
        }
        return cursor;
    }

    /** Determine only a bounded extent here; shared decoding validates names and semantics. */
    private static byte[] definitions(Reader reader, long address, long count) throws IOException {
        require(count > 0 && count <= MAX_SYMBOLS, "PT_DYNAMIC version-definition count exceeds limits");
        long cursor = 0;
        long end = 0;
        long totalAux = 0;
        for (long index = 0; index < count; index++) {
            checkCancelled(reader.cancelled);
            require(cursor <= ElfImage.MAX_TABLE_BYTES - 20, "PT_DYNAMIC version-definition extent exceeds limits");
            ByteBuffer header = reader.buffer(add(address, cursor), 20);
            int members = Short.toUnsignedInt(header.getShort(6));
            long auxiliary = Integer.toUnsignedLong(header.getInt(12));
            long next = Integer.toUnsignedLong(header.getInt(16));
            require(members > 0 && (totalAux += members) <= MAX_SYMBOLS && auxiliary >= 20 &&
                auxiliary <= ElfImage.MAX_TABLE_BYTES - cursor - 8 &&
                (index + 1 == count) == (next == 0), "invalid PT_DYNAMIC version-definition chain");
            long aux = cursor + auxiliary;
            long boundary = next == 0 ? ElfImage.MAX_TABLE_BYTES : add(cursor, next);
            require(boundary <= ElfImage.MAX_TABLE_BYTES && boundary >= aux + 8,
                "PT_DYNAMIC version-definition chain overlaps");
            for (int member = 0; member < members; member++) {
                checkCancelled(reader.cancelled);
                require(aux <= boundary - 8, "PT_DYNAMIC version auxiliary exceeds definition");
                ByteBuffer row = reader.buffer(add(address, aux), 8);
                long following = Integer.toUnsignedLong(row.getInt(4));
                require((member + 1 == members) == (following == 0), "invalid PT_DYNAMIC version auxiliary count");
                end = Math.max(end, aux + 8);
                if (following != 0) {
                    require(following >= 8 && following <= boundary - aux - 8,
                        "invalid PT_DYNAMIC version auxiliary chain");
                    aux += following;
                }
            }
            if (next != 0) {
                cursor += next;
            }
        }
        return reader.bytes(address, end);
    }

    private static final class Reader implements AutoCloseable {
        private final ElfImage image;
        private final BooleanSupplier cancelled;
        private final List<ElfLoadAllocations.Allocation> allocations;
        private final FileChannel channel;
        private long comparisons;
        private long bytesRead;

        private Reader(ElfImage image, BooleanSupplier cancelled) throws IOException {
            this.image = image;
            this.cancelled = cancelled;
            allocations = ElfLoadAllocations.read(image, cancelled);
            channel = FileChannel.open(image.sourcePath(), StandardOpenOption.READ);
            try {
                verify();
            }
            catch (IOException | RuntimeException failure) {
                channel.close();
                throw failure;
            }
        }

        private void comparison() {
            checkCancelled(cancelled);
            require(++comparisons <= 16L * 1024 * 1024, "PT_DYNAMIC allocation comparison budget exceeded");
        }

        private long locate(long address, long size) {
            require(address >= 0 && size > 0 && size <= ElfImage.MAX_TABLE_BYTES,
                "unsupported PT_DYNAMIC virtual read extent");
            long end = add(address, size);
            ElfLoadAllocations.Allocation selected = null;
            for (var allocation : allocations) {
                comparison();
                var section = allocation.section();
                if (address < section.address + section.size && section.address < end) {
                    require(selected == null, "ambiguous PT_DYNAMIC load mapping");
                    selected = allocation;
                }
            }
            require(selected != null && address >= selected.section().address &&
                address - selected.section().address <= selected.fileSize() &&
                size <= selected.fileSize() - (address - selected.section().address),
                "PT_DYNAMIC metadata is not uniquely file backed");
            return add(selected.section().offset, address - selected.section().address);
        }

        private byte[] bytes(long address, long size) throws IOException {
            long offset = locate(address, size);
            require(size <= 128L * 1024 * 1024 - bytesRead, "PT_DYNAMIC read budget exceeded");
            bytesRead += size;
            ByteBuffer bytes = ByteBuffer.allocate((int) size);
            while (bytes.hasRemaining()) {
                checkCancelled(cancelled);
                // Bound each I/O operation, including large string/definition reads.
                int limit = bytes.limit();
                bytes.limit(Math.min(limit, bytes.position() + 65536));
                int read = channel.read(bytes, offset + bytes.position());
                bytes.limit(limit);
                if (read <= 0) {
                    throw new IOException("PT_DYNAMIC source ended or stopped making progress");
                }
            }
            return bytes.array();
        }

        private ByteBuffer buffer(long address, long size) throws IOException {
            return ByteBuffer.wrap(bytes(address, size)).order(image.byteOrder());
        }

        private int definition(long address, long size) {
            require(address >= 0 && size >= 0, "PT_DYNAMIC symbol address/size exceeds supported range");
            long end = add(address, size);
            int selected = 0;
            for (var allocation : allocations) {
                comparison();
                var section = allocation.section();
                boolean intersects = size == 0 ? address >= section.address && address < section.address + section.size :
                    address < section.address + section.size && section.address < end;
                if (intersects) {
                    require(selected == 0, "PT_DYNAMIC definition has overlapping load allocations");
                    require(address >= section.address && end <= section.address + section.size,
                        "PT_DYNAMIC definition crosses load allocations");
                    selected = section.originalIndex;
                }
            }
            // A zero-sized end marker may describe the exact end of an allocation.
            if (selected == 0 && size == 0) {
                for (var allocation : allocations) {
                    comparison();
                    var section = allocation.section();
                    if (address == section.address + section.size) {
                        require(selected == 0, "PT_DYNAMIC end marker has ambiguous allocations");
                        selected = section.originalIndex;
                    }
                }
            }
            require(selected != 0, "PT_DYNAMIC definition has no complete load allocation");
            return selected;
        }

        private void verify() throws IOException {
            checkCancelled(cancelled);
            image.requireUnchanged(channel);
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }
    }

    private static long add(long value, long increment) {
        require(value >= 0 && increment >= 0 && increment <= Long.MAX_VALUE - value,
            "PT_DYNAMIC address/extent overflows supported range");
        return value + increment;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("PT_DYNAMIC symbol inventory cancelled");
        }
    }
}
