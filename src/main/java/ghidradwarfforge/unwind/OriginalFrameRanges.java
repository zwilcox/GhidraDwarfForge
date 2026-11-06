package ghidradwarfforge.unwind;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Bounded inventory of linked .debug_frame/.eh_frame record extents.
 * This does not validate CFI instructions or establish their runtime correctness.
 * Unsupported/malformed input throws; callers must not treat failure as absence.
 */
public final class OriginalFrameRanges {
    public enum Format { DEBUG_FRAME, EH_FRAME }
    public record Frame(int offset, int cieOffset, long address, long size, boolean signalFrame) { }
    public record Inventory(int cies, List<Frame> frames) {
        public Inventory { frames = List.copyOf(frames); }
    }
    private record Record(int start, int body, int end, int offsetBytes, long identity) { }
    private record Cie(int addressBytes, int encoding, boolean augmented, boolean signalFrame) { }
    private static final int MAX_BYTES = 64 * 1024 * 1024;
    private static final int MAX_RECORDS = 262144;
    private OriginalFrameRanges() { }

    public static Inventory read(byte[] data, ByteOrder order, int addressBytes,
            Format format, long sectionAddress, BooleanSupplier cancelled) {
        Objects.requireNonNull(data);
        Objects.requireNonNull(order);
        Objects.requireNonNull(format);
        Objects.requireNonNull(cancelled);
        check(cancelled);
        require(data.length <= MAX_BYTES && (addressBytes == 4 || addressBytes == 8),
            "unsupported frame section size or address width");
        require(sectionAddress >= 0 && (addressBytes != 4 || sectionAddress <= 0xffff_ffffL),
            "frame section address exceeds supported domain");
        var reader = new Reader(data, order, cancelled);
        var records = new ArrayList<Record>();
        while (reader.position() < data.length) {
            check(cancelled);
            require(records.size() < MAX_RECORDS, "frame record budget exceeded");
            int start = reader.position();
            long length = reader.integer(4);
            if (length == 0) {
                require(format == Format.EH_FRAME, "zero length in .debug_frame");
                while (reader.position() < data.length) {
                    require(reader.integer(1) == 0, "nonzero data after .eh_frame terminator");
                }
                break;
            }
            int offsetBytes = 4;
            if (length == 0xffff_ffffL) {
                length = reader.integer(8);
                offsetBytes = 8;
            }
            else require(length < 0xffff_fff0L, "reserved frame initial length");
            require(length >= offsetBytes && length <= data.length - reader.position(),
                "truncated or excessive frame record");
            int end = reader.position() + (int) length;
            long identity = reader.integer(offsetBytes);
            records.add(new Record(start, reader.position(), end, offsetBytes, identity));
            reader.position(end);
        }
        var cies = new HashMap<Integer, Cie>();
        for (Record record : records) {
            check(cancelled);
            long marker = format == Format.EH_FRAME ? 0 : record.offsetBytes() == 8 ? -1L : 0xffff_ffffL;
            if (record.identity() == marker) {
                reader.window(record.body(), record.end());
                int version = (int) reader.integer(1);
                require(version == 1 || version == 3 || version == 4, "unsupported CIE version");
                String augmentation = reader.string();
                int width = version == 4 ? (int) reader.integer(1) : addressBytes;
                require(width == addressBytes, "CIE address width differs from target");
                if (version == 4) require(reader.integer(1) == 0, "segmented CIE addresses are unsupported");
                reader.leb(false);
                reader.leb(true);
                if (version == 1) reader.integer(1);
                else reader.leb(false);
                boolean augmented = !augmentation.isEmpty();
                int encoding = 0;
                boolean signal = false;
                if (augmented) {
                    require(format == Format.EH_FRAME && augmentation.charAt(0) == 'z',
                        "unsupported CIE augmentation");
                    long bytes = reader.leb(false);
                    require(bytes >= 0 && bytes <= reader.remaining(), "CIE augmentation crosses record");
                    int augmentationEnd = reader.position() + (int) bytes;
                    reader.limit(augmentationEnd);
                    var seen = new HashSet<Character>();
                    for (int index = 1; index < augmentation.length(); index++) {
                        check(cancelled);
                        char kind = augmentation.charAt(index);
                        require(seen.add(kind), "duplicate CIE augmentation");
                        switch (kind) {
                            case 'R' -> {
                                encoding = (int) reader.integer(1);
                                require((encoding & 0xf0) == 0 || (encoding & 0xf0) == 0x10,
                                    "unsupported FDE pointer application");
                                require(scalarEncoding(encoding & 15), "unsupported FDE pointer format");
                            }
                            case 'L' -> {
                                int lsda = (int) reader.integer(1);
                                require(lsda == 0xff || skipEncoding(lsda), "unsupported LSDA encoding");
                            }
                            case 'P' -> {
                                int personality = (int) reader.integer(1);
                                require(skipEncoding(personality), "unsupported personality encoding");
                                reader.scalar(personality & 15, width);
                            }
                            case 'S' -> signal = true;
                            default -> throw new IllegalArgumentException("unsupported CIE augmentation " + kind);
                        }
                    }
                    require(reader.position() == augmentationEnd, "unexplained CIE augmentation bytes");
                }
                cies.put(record.start(), new Cie(width, encoding, augmented, signal));
            }
        }
        var frames = new ArrayList<Frame>();
        for (Record record : records) {
            check(cancelled);
            if (cies.containsKey(record.start())) continue;
            long reference = record.identity();
            if (format == Format.EH_FRAME) {
                int field = record.body() - record.offsetBytes();
                require(reference > 0 && reference <= field, "invalid relative CIE reference");
                reference = field - reference;
            }
            require(reference >= 0 && reference <= Integer.MAX_VALUE, "CIE reference outside section");
            Cie cie = cies.get((int) reference);
            require(cie != null, "FDE does not reference a complete CIE");
            reader.window(record.body(), record.end());
            long fieldAddress = add(sectionAddress, reader.position(), "encoded pointer field overflows");
            long address = reader.scalar(cie.encoding() & 15, cie.addressBytes());
            require((cie.encoding() & 8) != 0 || address >= 0, "unsigned FDE pointer exceeds supported domain");
            if ((cie.encoding() & 0x70) == 0x10) {
                try { address = Math.addExact(fieldAddress, address); }
                catch (ArithmeticException overflow) { throw new IllegalArgumentException("relative FDE address overflows", overflow); }
            }
            long size = reader.scalar(cie.encoding() & 15, cie.addressBytes());
            require(address >= 0 && size >= 0, "FDE range exceeds supported address domain");
            long last = size == 0 ? address : add(address, size - 1, "FDE extent overflows");
            require(addressBytes != 4 || last <= 0xffff_ffffL, "FDE extent exceeds target address width");
            if (cie.augmented()) {
                long bytes = reader.leb(false);
                require(bytes >= 0 && bytes <= reader.remaining(), "FDE augmentation crosses record");
                reader.position(reader.position() + (int) bytes);
            }
            frames.add(new Frame(record.start(), (int) reference, address, size, cie.signalFrame()));
        }
        check(cancelled);
        return new Inventory(cies.size(), frames);
    }

    private static boolean scalarEncoding(int format) {
        return format == 0 || format == 1 || format == 2 || format == 3 || format == 4 ||
            format == 9 || format == 10 || format == 11 || format == 12;
    }
    private static boolean skipEncoding(int encoding) {
        int application = encoding & 0x70;
        return scalarEncoding(encoding & 15) &&
            (application == 0 || application == 0x10 || application == 0x20 ||
             application == 0x30 || application == 0x40);
    }
    private static long add(long value, long increment, String message) {
        require(value >= 0 && increment >= 0 && increment <= Long.MAX_VALUE - value, message);
        return value + increment;
    }
    private static void require(boolean condition, String reason) {
        if (!condition) throw new IllegalArgumentException(reason);
    }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("original frame inventory cancelled");
    }
    private static final class Reader {
        private final ByteBuffer bytes;
        private final BooleanSupplier cancelled;
        private Reader(byte[] data, ByteOrder order, BooleanSupplier cancelled) {
            bytes = ByteBuffer.wrap(data).order(order);
            this.cancelled = cancelled;
        }
        private int position() { return bytes.position(); }
        private int remaining() { return bytes.remaining(); }
        private void position(int value) { bytes.position(value); }
        private void limit(int value) { bytes.limit(value); }
        private void window(int start, int end) { bytes.limit(bytes.capacity()); bytes.position(start); bytes.limit(end); }
        private long integer(int size) {
            check(cancelled);
            require(size <= bytes.remaining(), "truncated frame field");
            return switch (size) {
                case 1 -> Byte.toUnsignedLong(bytes.get());
                case 2 -> Short.toUnsignedLong(bytes.getShort());
                case 4 -> Integer.toUnsignedLong(bytes.getInt());
                case 8 -> bytes.getLong();
                default -> throw new IllegalArgumentException("unsupported frame scalar width");
            };
        }
        private String string() {
            var value = new StringBuilder();
            while (true) {
                int next = (int) integer(1);
                if (next == 0) return value.toString();
                require(next < 128 && value.length() < 64, "unsupported or excessive CIE augmentation string");
                value.append((char) next);
            }
        }
        private long leb(boolean signed) {
            long value = 0;
            for (int index = 0; index < 10; index++) {
                int next = (int) integer(1);
                int payload = next & 127, shift = index * 7;
                if (index == 9) require(signed ? payload == 0 || payload == 127 : payload <= 1,
                    "overflowing frame LEB128");
                value |= (long) payload << shift;
                if ((next & 128) == 0) {
                    if (signed && shift < 63 && (next & 64) != 0) value |= -1L << (shift + 7);
                    return value;
                }
            }
            throw new IllegalArgumentException("unterminated frame LEB128");
        }
        private long scalar(int format, int addressBytes) {
            return switch (format) {
                case 0 -> integer(addressBytes);
                case 1 -> leb(false);
                case 2 -> integer(2);
                case 3 -> integer(4);
                case 4 -> integer(8);
                case 9 -> leb(true);
                case 10 -> (short) integer(2);
                case 11 -> (int) integer(4);
                case 12 -> integer(8);
                default -> throw new IllegalArgumentException("unsupported frame scalar encoding");
            };
        }
    }
}
