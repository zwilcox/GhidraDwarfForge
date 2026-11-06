package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Bounded gABI relocation inventory from PT_DYNAMIC, including sectionless ELF.
 * Raw tags and r_info are preserved: this is not a processor-specific write
 * footprint proof, and must not itself authorize generated unwind coverage.
 */
public final class ElfRuntimeRelocations {
    public enum Format { REL, RELA, RELR }
    public record Tag(long tag, long value) { }
    /** REL/RELR have no explicit addend. RELR has no r_info (represented by null). */
    public record Relocation(long recordOffset, long address, Long info, Long addend) { }
    public record Table(String role, Format format, long address, long offset, long size,
            int entrySize, String sha256, List<Relocation> relocations) {
        public Table { relocations = List.copyOf(relocations); }
    }
    public record Inventory(List<Tag> tags, List<Table> tables) {
        public Inventory { tags = List.copyOf(tags); tables = List.copyOf(tables); }
    }
    private static final int MAX_BYTES = 64 * 1024 * 1024;
    private static final int MAX_RECORDS = 262144;
    private static final Set<Long> SELECTED = Set.of(2L, 7L, 8L, 9L, 17L, 18L, 19L, 20L, 23L, 35L, 36L, 37L);
    private ElfRuntimeRelocations() { }

    public static Inventory inspect(ElfImage image, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        require(image.type() == 2 || image.type() == 3, "runtime relocation inventory requires linked ELF");
        ElfImage.Segment dynamic = null;
        for (var segment : image.segments()) {
            check(cancelled);
            if (segment.type == 2) {
                require(dynamic == null, "multiple PT_DYNAMIC segments");
                dynamic = segment;
            }
        }
        var tags = new ArrayList<Tag>();
        var selected = new HashMap<Long, Long>();
        var tables = new ArrayList<Table>();
        try (var reader = new Reader(image, cancelled)) {
            if (dynamic != null) {
                int size = reader.width * 2;
                require(dynamic.fileSize > 0 && dynamic.fileSize <= dynamic.memorySize && dynamic.fileSize % size == 0 &&
                    dynamic.fileSize / size <= MAX_RECORDS, "invalid dynamic relocation tag framing");
                require(reader.locate(dynamic.virtualAddress, dynamic.fileSize) == dynamic.offset,
                    "PT_DYNAMIC virtual and file mappings disagree");
                var bytes = reader.read(dynamic.virtualAddress, dynamic.fileSize);
                boolean terminated = false;
                while (bytes.hasRemaining()) {
                    check(cancelled);
                    long tag = reader.signed(bytes), value = reader.unsigned(bytes);
                    if (tag == 0) { terminated = true; break; }
                    tags.add(new Tag(tag, value));
                    if (SELECTED.contains(tag)) require(value >= 0 && selected.putIfAbsent(tag, value) == null,
                        "duplicate or oversized dynamic relocation tag");
                }
                require(terminated, "unterminated dynamic relocation tags");
                // gABI specifies RELR processing before REL/RELA.
                table(reader, selected, tables, "DT_RELR", Format.RELR, 36, 35, 37);
                table(reader, selected, tables, "DT_REL", Format.REL, 17, 18, 19);
                table(reader, selected, tables, "DT_RELA", Format.RELA, 7, 8, 9);
                if (selected.containsKey(23L) || selected.containsKey(2L) || selected.containsKey(20L)) {
                    require(selected.containsKey(23L) && selected.containsKey(2L) && selected.containsKey(20L),
                        "incomplete PLT relocation metadata");
                    long format = selected.get(20L);
                    require(format == 7 || format == 17, "unknown PLT relocation format");
                    tables.add(reader.table("DT_JMPREL", format == 7 ? Format.RELA : Format.REL,
                        selected.get(23L), selected.get(2L)));
                }
            }
            corroborate(image, dynamic, tables, cancelled);
            reader.verify();
        }
        check(cancelled);
        return new Inventory(tags, tables);
    }

    private static void table(Reader reader, Map<Long, Long> tags, List<Table> tables, String role,
            Format format, long pointer, long size, long entry) throws IOException {
        if (!tags.containsKey(pointer) && !tags.containsKey(size) && !tags.containsKey(entry)) return;
        // The entry width can describe a PLT-only table without a general table.
        if (!tags.containsKey(pointer) && !tags.containsKey(size)) {
            require(tags.get(entry) == reader.entrySize(format), "wrong standalone relocation entry size");
            return;
        }
        require(tags.containsKey(pointer) && tags.containsKey(size) && tags.containsKey(entry),
            "incomplete " + role + " metadata");
        require(tags.get(entry) == reader.entrySize(format), "wrong " + role + " entry size");
        tables.add(reader.table(role, format, tags.get(pointer), tags.get(size)));
    }

    private static void corroborate(ElfImage image, ElfImage.Segment dynamic, List<Table> tables,
            BooleanSupplier cancelled) {
        for (var section : image.sections()) {
            check(cancelled);
            if ((section.flags & 2) == 0 || section.size == 0) continue;
            if (section.type == 6) require(dynamic != null && section.address == dynamic.virtualAddress &&
                section.offset == dynamic.offset && section.size == dynamic.fileSize,
                "allocated dynamic section disagrees with PT_DYNAMIC");
            Format format = section.type == 4 ? Format.RELA : section.type == 9 ? Format.REL :
                section.type == 19 ? Format.RELR : null;
            if (format == null) continue;
            require((section.flags & 0x800) == 0, "compressed allocated relocation table");
            boolean covered = false;
            for (var table : tables) {
                check(cancelled);
                if (table.format() != format || section.address < table.address()) continue;
                long delta = section.address - table.address();
                if (delta <= table.size() && section.size <= table.size() - delta) {
                    require(section.offset == add(table.offset(), delta) &&
                        section.entrySize == table.entrySize() && delta % table.entrySize() == 0 &&
                        section.size % table.entrySize() == 0,
                        "section and dynamic relocation table disagree");
                    covered = true;
                }
            }
            require(covered, "allocated relocation section lacks a complete dynamic table");
        }
        // Overlapping roles can describe identical record boundaries (e.g. a
        // PLT subset). Keep both roles, never silently reinterpret their bytes.
        for (int i = 0; i < tables.size(); i++) for (int j = i + 1; j < tables.size(); j++) {
            check(cancelled);
            var a = tables.get(i); var b = tables.get(j);
            if (a.size() == 0 || b.size() == 0) continue;
            long start = Math.max(a.offset(), b.offset()), end = Math.min(add(a.offset(), a.size()), add(b.offset(), b.size()));
            if (start >= end) continue;
            require(a.format() == b.format() && (start - a.offset()) % a.entrySize() == 0 &&
                (start - b.offset()) % b.entrySize() == 0 &&
                add(a.address(), start - a.offset()) == add(b.address(), start - b.offset()),
                "conflicting overlapping dynamic relocation tables");
        }
    }

    private static final class Reader implements AutoCloseable {
        private final ElfImage image;
        private final BooleanSupplier cancelled;
        private final FileChannel channel;
        private final int width;
        private long bytesRead, comparisons, records;
        private Reader(ElfImage image, BooleanSupplier cancelled) throws IOException {
            this.image = image; this.cancelled = cancelled; width = image.is64Bit() ? 8 : 4;
            channel = FileChannel.open(image.sourcePath(), StandardOpenOption.READ);
            try { verify(); }
            catch (IOException | RuntimeException failure) { channel.close(); throw failure; }
        }
        private void verify() throws IOException { check(cancelled); image.requireUnchanged(channel); }
        private long unsigned(ByteBuffer bytes) { return width == 8 ? bytes.getLong() : Integer.toUnsignedLong(bytes.getInt()); }
        private long signed(ByteBuffer bytes) { return width == 8 ? bytes.getLong() : bytes.getInt(); }
        private int entrySize(Format format) { return width * (format == Format.RELR ? 1 : format == Format.RELA ? 3 : 2); }
        private long locate(long address, long size) {
            require(address >= 0 && size > 0 && size <= MAX_BYTES, "invalid runtime relocation read extent");
            long end = add(address, size - 1);
            require(width == 8 || end <= 0xffff_ffffL, "runtime relocation extent exceeds address width");
            ElfImage.Segment selected = null;
            for (var segment : image.segments()) {
                check(cancelled);
                require(++comparisons <= 16L * 1024 * 1024, "runtime relocation mapping budget exceeded");
                if (segment.type != 1 || segment.memorySize == 0) continue;
                long last = add(segment.virtualAddress, segment.memorySize - 1);
                require(width == 8 || last <= 0xffff_ffffL, "runtime relocation load exceeds address width");
                if (address <= last && segment.virtualAddress <= end) {
                    require(selected == null, "ambiguous runtime relocation load mapping");
                    selected = segment;
                }
            }
            require(selected != null && address >= selected.virtualAddress &&
                address - selected.virtualAddress <= selected.fileSize &&
                size <= selected.fileSize - (address - selected.virtualAddress),
                "runtime relocation metadata is not uniquely file backed");
            return add(selected.offset, address - selected.virtualAddress);
        }
        private ByteBuffer read(long address, long size) throws IOException {
            long offset = locate(address, size);
            require(size <= MAX_BYTES - bytesRead, "runtime relocation byte budget exceeded");
            bytesRead += size;
            verify();
            var data = ByteBuffer.allocate((int) size).order(image.byteOrder());
            while (data.hasRemaining()) {
                check(cancelled);
                int limit = data.limit(); data.limit(Math.min(limit, data.position() + 32768));
                int count = channel.read(data, offset + data.position()); data.limit(limit);
                if (count <= 0) throw new IOException("runtime relocation read made no progress");
            }
            verify(); data.flip(); return data;
        }
        private Table table(String role, Format format, long address, long size) throws IOException {
            int entrySize = entrySize(format);
            require(address >= 0 && size >= 0 && size % entrySize == 0 && size / entrySize <= MAX_RECORDS,
                "invalid " + role + " table framing");
            var bytes = size == 0 ? ByteBuffer.allocate(0).order(image.byteOrder()) : read(address, size);
            long offset = size == 0 ? 0 : locate(address, size);
            var rows = new ArrayList<Relocation>();
            long next = -1;
            while (bytes.hasRemaining()) {
                check(cancelled);
                long at = add(offset, bytes.position()), value = unsigned(bytes);
                if (format != Format.RELR) {
                    require(value >= 0, "relocation target exceeds signed address domain");
                    append(rows, new Relocation(at, value, unsigned(bytes), format == Format.RELA ? signed(bytes) : null));
                }
                else if ((value & 1) == 0) {
                    require(value >= 0, "RELR target exceeds signed address domain");
                    append(rows, new Relocation(at, value, null, null));
                    next = add(value, width);
                    require(width == 8 || next <= 0x1_0000_0000L, "RELR target extent exceeds ELF32");
                }
                else {
                    require(next >= 0, "RELR bitmap has no preceding address");
                    for (int bit = 1; bit < width * 8; bit++) {
                        check(cancelled);
                        if ((value & (1L << bit)) != 0) {
                            long target = add(next, (long) (bit - 1) * width);
                            require(width == 8 || target <= 0x1_0000_0000L - width, "RELR bitmap exceeds ELF32");
                            add(target, width - 1);
                            append(rows, new Relocation(at, target, null, null));
                        }
                    }
                    next = add(next, (long) (width * 8 - 1) * width);
                }
            }
            verify();
            return new Table(role, format, address, offset, size, entrySize, hash(bytes.array()), rows);
        }
        private void append(List<Relocation> rows, Relocation row) {
            require(++records <= MAX_RECORDS, "expanded runtime relocation count exceeds budget"); rows.add(row);
        }
        private String hash(byte[] bytes) {
            try {
                var digest = MessageDigest.getInstance("SHA-256");
                for (int offset = 0; offset < bytes.length; offset += 32768) {
                    check(cancelled); digest.update(bytes, offset, Math.min(32768, bytes.length - offset));
                }
                return HexFormat.of().formatHex(digest.digest());
            }
            catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
        }
        @Override public void close() throws IOException { channel.close(); }
    }
    private static long add(long left, long right) {
        try { return Math.addExact(left, right); }
        catch (ArithmeticException overflow) { throw new IllegalArgumentException("runtime relocation extent overflows", overflow); }
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("runtime relocation inventory cancelled");
    }
}
