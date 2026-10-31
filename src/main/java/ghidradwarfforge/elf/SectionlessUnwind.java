package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Exposes original, table-proven unwind records; never creates call-frame instructions. */
final class SectionlessUnwind {
    private static final long PT_GNU_EH_FRAME = 0x6474e550L;
    private static final int MAX_RECORDS = 262144;

    private SectionlessUnwind() {
    }

    static ElfImage.Section find(ElfImage image, BooleanSupplier cancelled,
            Consumer<String> diagnostic) throws IOException {
        checkCancelled(cancelled);
        if (!image.sections().isEmpty()) {
            return null;
        }
        try {
            ElfImage.Segment header = null;
            for (var segment : image.segments()) {
                checkCancelled(cancelled);
                if (segment.type == PT_GNU_EH_FRAME) {
                    require(header == null, "multiple PT_GNU_EH_FRAME headers");
                    header = segment;
                }
            }
            if (header == null) {
                return null;
            }
            try (Reader reader = new Reader(image, cancelled)) {
                var section = read(reader, header);
                image.requireUnchanged(reader.channel);
                return section;
            }
        }
        catch (IllegalArgumentException unsupported) {
            diagnostic.accept("Omitted original .eh_frame: " + unsupported.getMessage());
            return null;
        }
    }

    private static ElfImage.Section read(Reader reader, ElfImage.Segment header) throws IOException {
        require(header.fileSize >= 4 && header.fileSize <= ElfImage.MAX_NAME_TABLE_BYTES,
            "unsupported PT_GNU_EH_FRAME size");
        require(reader.locate(header.virtualAddress, header.fileSize) == header.offset,
            "PT_GNU_EH_FRAME file and virtual mappings disagree");
        ByteBuffer bytes = reader.bytes(header.virtualAddress, (int) header.fileSize);
        require(Byte.toUnsignedInt(bytes.get()) == 1, "unsupported unwind header version");
        int pointerEncoding = Byte.toUnsignedInt(bytes.get());
        int countEncoding = Byte.toUnsignedInt(bytes.get());
        int tableEncoding = Byte.toUnsignedInt(bytes.get());
        require((countEncoding & 0xf0) == 0, "unwind count has no bounded absolute encoding");
        long start = encoded(reader, bytes, header.virtualAddress, pointerEncoding);
        long count = encoded(reader, bytes, header.virtualAddress, countEncoding);
        require(count > 0 && count <= MAX_RECORDS, "unwind search-table count outside supported bounds");
        Set<Long> referenced = new HashSet<>();
        long lastPc = -1;
        long end = start;
        for (long index = 0; index < count; index++) {
            checkCancelled(reader.cancelled);
            long pc = encoded(reader, bytes, header.virtualAddress, tableEncoding);
            long fde = encoded(reader, bytes, header.virtualAddress, tableEncoding);
            require(pc > lastPc && referenced.add(fde), "unordered or duplicate unwind search-table entry");
            lastPc = pc;
            require(fde >= start && fde - start <= ElfImage.MAX_TABLE_BYTES - 8,
                "unwind FDE outside bounded frame extent");
            long length = length(reader.bytes(fde, 4).getInt());
            end = Math.max(end, add(fde, 4 + length));
        }
        require(end > start && end - start <= ElfImage.MAX_TABLE_BYTES, "unwind frame extent exceeds budget");
        long offset = reader.locate(start, end - start);
        Set<Long> cies = new HashSet<>();
        Set<Long> fdes = new HashSet<>();
        long cursor = start;
        int records = 0;
        while (cursor < end) {
            checkCancelled(reader.cancelled);
            require(++records <= MAX_RECORDS, "unwind record count exceeds budget");
            require(end - cursor >= 8, "truncated unwind record header");
            ByteBuffer record = reader.bytes(cursor, 8);
            long length = length(record.getInt());
            require(length <= end - cursor - 4, "unwind record crosses proven extent");
            long identity = Integer.toUnsignedLong(record.getInt());
            if (identity == 0) {
                require(length >= 9, "truncated unwind CIE");
                int version = Byte.toUnsignedInt(reader.bytes(add(cursor, 8), 1).get());
                require(version == 1 || version == 3 || version == 4, "unsupported unwind CIE version");
                require(version != 4 || length >= 11, "truncated version-4 unwind CIE");
                cies.add(cursor);
            }
            else {
                require(length >= 6, "truncated unwind FDE");
                long field = add(cursor, 4);
                require(identity <= field && cies.contains(field - identity),
                    "unwind FDE does not reference an earlier complete CIE");
                require(fdes.add(cursor), "duplicate unwind record");
            }
            cursor = add(cursor, 4 + length);
        }
        require(cursor == end && fdes.equals(referenced), "unwind records disagree with search-table boundaries");
        var result = new ElfImage.Section();
        result.name = ".eh_frame";
        result.type = 1;
        result.flags = 2;
        result.address = start;
        result.offset = offset;
        result.size = end - start;
        result.alignment = 1;
        return result;
    }

    private static long length(int value) {
        long length = Integer.toUnsignedLong(value);
        require(length >= 4 && length < 0xfffffff0L && length <= ElfImage.MAX_TABLE_BYTES,
            "unsupported, terminated or excessive unwind record length");
        return length;
    }

    private static long encoded(Reader reader, ByteBuffer bytes, long base, int encoding) {
        checkCancelled(reader.cancelled);
        int form = encoding & 15;
        int width = switch (form) {
            case 0 -> reader.image.is64Bit() ? 8 : 4;
            case 2, 10 -> 2;
            case 3, 11 -> 4;
            case 4, 12 -> 8;
            default -> throw new IllegalArgumentException("unsupported unwind pointer encoding " + encoding);
        };
        int application = encoding & 0xf0;
        require(application == 0 || application == 0x10 || application == 0x30,
            "unsupported indirect or relative unwind pointer encoding " + encoding);
        require(bytes.remaining() >= width, "truncated encoded unwind field");
        long field = add(base, bytes.position());
        long value = switch (form) {
            case 2 -> Short.toUnsignedInt(bytes.getShort());
            case 3 -> Integer.toUnsignedLong(bytes.getInt());
            case 10 -> bytes.getShort();
            case 11 -> bytes.getInt();
            case 4, 12 -> bytes.getLong();
            default -> reader.image.is64Bit() ? bytes.getLong() : Integer.toUnsignedLong(bytes.getInt());
        };
        require(form >= 10 || value >= 0, "unwind pointer exceeds signed address range");
        long result;
        try {
            result = Math.addExact(value, application == 0x10 ? field : application == 0x30 ? base : 0);
        }
        catch (ArithmeticException overflow) {
            throw new IllegalArgumentException("unwind encoded address overflow", overflow);
        }
        require(result >= 0 && (reader.image.is64Bit() || result <= 0xffffffffL),
            "unwind value outside target address range");
        return result;
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
                image.requireUnchanged(channel);
            }
            catch (IOException | RuntimeException failure) {
                channel.close();
                throw failure;
            }
        }

        private long locate(long address, long size) {
            require(size > 0 && size <= ElfImage.MAX_TABLE_BYTES, "unsupported unwind read extent");
            long end = add(address, size);
            ElfLoadAllocations.Allocation selected = null;
            for (var allocation : allocations) {
                checkCancelled(cancelled);
                require(++comparisons <= 16L * 1024 * 1024, "unwind load-comparison budget exceeded");
                var section = allocation.section();
                if (address < section.address + section.size && section.address < end) {
                    require(selected == null, "ambiguous unwind load mapping");
                    selected = allocation;
                }
            }
            require(selected != null && address >= selected.section().address &&
                address - selected.section().address <= selected.fileSize() &&
                size <= selected.fileSize() - (address - selected.section().address),
                "unwind extent is not uniquely file backed");
            return add(selected.section().offset, address - selected.section().address);
        }

        private ByteBuffer bytes(long address, int size) throws IOException {
            long offset = locate(address, size);
            require(size <= 128L * 1024 * 1024 - bytesRead, "unwind read budget exceeded");
            bytesRead += size;
            ByteBuffer result = ByteBuffer.allocate(size).order(image.byteOrder());
            while (result.hasRemaining()) {
                checkCancelled(cancelled);
                int limit = result.limit();
                result.limit(Math.min(limit, result.position() + 65536));
                int count = channel.read(result, offset + result.position());
                result.limit(limit);
                if (count <= 0) {
                    throw new IOException("unwind input ended or stopped making progress");
                }
            }
            result.flip();
            return result;
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }
    }

    private static long add(long value, long increment) {
        require(value >= 0 && increment >= 0 && increment <= Long.MAX_VALUE - value,
            "unwind address or extent overflow");
        return value + increment;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("original unwind inventory cancelled");
        }
    }
}
