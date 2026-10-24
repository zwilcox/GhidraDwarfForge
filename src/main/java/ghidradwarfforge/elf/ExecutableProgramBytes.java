package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Read-only correspondence of declared ELF/program-header bytes and all non-NULL
 * program payloads. Only the standard ELF header's section-table fields may
 * differ, after both inputs pass ElfImage's structural checks. This is not active
 * section-table, build-ID, debuglink, DWARF, source or complete-file validation,
 * executable validity, file identity, a snapshot, or attachment readiness.
 * Ordinary export does not call this helper. No processor whitelist is used.
 *
 * Differences take precedence over lack of file-backed LOAD evidence. Phase
 * order is the full declared ELF header, resolved program count, raw program
 * table, then the ascending union of program payloads. An issue identifies the
 * first difference in that phase order, not a globally lowest physical offset.
 * Program-count differences have no common physical offset: PN_XNUM values can
 * reside at different section-table locations.
 *
 * ElfImage's bounded metadata and signed offset/address limits apply; not every
 * maximum table combination is promised to fit a 64 MiB heap. Comparison uses
 * two 64 KiB buffers and at most MAX_HEADER_COUNT payload intervals, sorted and
 * merged once. Unknown program kinds, p_paddr, PT_NULL rows and entry extensions
 * are retained as bytes. Cancellation is checked around metadata reads and each
 * bounded comparison; it cannot interrupt a blocked filesystem operation or
 * every internal ElfImage read. Owned channels close on all paths. Basic source
 * change checks are best effort, not proof of immutable inputs or file identity.
 */
public final class ExecutableProgramBytes {
    private static final int BUFFER_BYTES = 64 * 1024;

    public enum Status {
        MATCHING_PROGRAM_BYTES, DIFFERENT_PROGRAM_BYTES, NO_FILE_BACKED_LOAD_EVIDENCE
    }

    public enum Region {
        ELF_HEADER, PROGRAM_COUNT, PROGRAM_TABLE, PROGRAM_PAYLOAD
    }

    public record Issue(Region region, OptionalLong offset, String expected, String observed) {
        public Issue {
            Objects.requireNonNull(region, "region");
            Objects.requireNonNull(offset, "offset");
            if ((region == Region.PROGRAM_COUNT) == offset.isPresent() ||
                    offset.isPresent() && offset.getAsLong() < 0) {
                throw new IllegalArgumentException("invalid program-byte issue offset");
            }
            requireText(expected, "expected");
            requireText(observed, "observed");
        }
    }

    public record Result(Status status, Optional<Issue> issue, String diagnostic) {
        public Result {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(issue, "issue");
            if ((status == Status.DIFFERENT_PROGRAM_BYTES) != issue.isPresent()) {
                throw new IllegalArgumentException("inconsistent program-byte observation");
            }
            requireText(diagnostic, "diagnostic");
        }
    }

    @FunctionalInterface
    interface ChannelOpener {
        SeekableByteChannel open(Path path) throws IOException;
    }

    private record Header(byte[] fixed, int size, long programOffset, int programEntrySize,
            int encodedProgramCount, long sectionOffset) {
        static Header of(ElfImage elf) {
            byte[] bytes = elf.headerBytes();
            ByteBuffer data = ByteBuffer.wrap(bytes).order(elf.byteOrder());
            boolean wide = elf.is64Bit();
            return new Header(bytes, Short.toUnsignedInt(data.getShort(wide ? 52 : 40)),
                word(data, wide ? 32 : 28, wide),
                Short.toUnsignedInt(data.getShort(wide ? 54 : 42)),
                Short.toUnsignedInt(data.getShort(wide ? 56 : 44)),
                word(data, wide ? 40 : 32, wide));
        }
    }

    private record Range(long start, long end) {
    }

    private ExecutableProgramBytes() {
    }

    public static Result compare(Path original, Path candidate) throws IOException {
        return compare(original, candidate, () -> false);
    }

    public static Result compare(Path original, Path candidate, BooleanSupplier cancelled)
            throws IOException {
        return compare(original, candidate, cancelled,
            path -> FileChannel.open(path, StandardOpenOption.READ));
    }

    static Result compare(Path original, Path candidate, BooleanSupplier cancelled,
            ChannelOpener opener) throws IOException {
        Objects.requireNonNull(original, "original");
        Objects.requireNonNull(candidate, "candidate");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(opener, "opener");
        checkCancelled(cancelled);
        BasicFileAttributes originalState = attributes(original);
        checkCancelled(cancelled);
        BasicFileAttributes candidateState = attributes(candidate);
        ElfImage before = read(original, cancelled);
        ElfImage after = read(candidate, cancelled);
        requireUnchanged(original, originalState);
        requireUnchanged(candidate, candidateState);
        if (before.fileSize() != originalState.size() || after.fileSize() != candidateState.size()) {
            throw new IOException("ELF size changed during program-byte metadata observation");
        }
        Result result;
        try (SeekableByteChannel left = open(original, cancelled, opener);
                SeekableByteChannel right = open(candidate, cancelled, opener)) {
            requireSize(left, before.fileSize());
            requireSize(right, after.fileSize());
            result = new Comparison(before, after, left, right, cancelled).compare();
            requireSize(left, before.fileSize());
            requireSize(right, after.fileSize());
            requireUnchanged(original, originalState);
            requireUnchanged(candidate, candidateState);
            checkCancelled(cancelled);
        }
        checkCancelled(cancelled);
        requireUnchanged(original, originalState);
        requireUnchanged(candidate, candidateState);
        checkCancelled(cancelled);
        return result;
    }

    private static final class Comparison {
        private final ElfImage before;
        private final ElfImage after;
        private final Header originalHeader;
        private final Header candidateHeader;
        private final SeekableByteChannel original;
        private final SeekableByteChannel candidate;
        private final BooleanSupplier cancelled;
        private final ByteBuffer left = ByteBuffer.allocate(BUFFER_BYTES);
        private final ByteBuffer right = ByteBuffer.allocate(BUFFER_BYTES);

        Comparison(ElfImage before, ElfImage after, SeekableByteChannel original,
                SeekableByteChannel candidate, BooleanSupplier cancelled) {
            this.before = before;
            this.after = after;
            this.originalHeader = Header.of(before);
            this.candidateHeader = Header.of(after);
            this.original = original;
            this.candidate = candidate;
            this.cancelled = cancelled;
            left.order(before.byteOrder());
            right.order(after.byteOrder());
        }

        Result compare() throws IOException {
            readAt(original, left, 0, originalHeader.fixed().length);
            readAt(candidate, right, 0, candidateHeader.fixed().length);
            requireObservedHeader(left, originalHeader.fixed());
            requireObservedHeader(right, candidateHeader.fixed());
            Result difference = bytes(Region.ELF_HEADER, 0,
                Math.min(originalHeader.fixed().length, candidateHeader.fixed().length), true);
            if (difference != null) {
                return difference;
            }
            // Class/order/e_ehsize are unmasked, so both declared spans now agree.
            difference = range(Region.ELF_HEADER, originalHeader.fixed().length,
                originalHeader.size());
            if (difference != null) {
                return difference;
            }
            requireObservedCount(original, before, originalHeader, left);
            requireObservedCount(candidate, after, candidateHeader, right);
            int count = before.segments().size();
            if (count != after.segments().size()) {
                return new Result(Status.DIFFERENT_PROGRAM_BYTES,
                    Optional.of(new Issue(Region.PROGRAM_COUNT, OptionalLong.empty(),
                        Integer.toString(count), Integer.toString(after.segments().size()))),
                    "resolved program-header count differs; values have no common file offset");
            }
            long tableEnd = add(originalHeader.programOffset(),
                multiply(originalHeader.programEntrySize(), count));
            difference = programTable(count);
            if (difference != null) {
                return difference;
            }
            boolean loadEvidence = false;
            List<Range> ranges = new ArrayList<>();
            for (ElfImage.Segment segment : before.segments()) {
                checkCancelled(cancelled);
                if (segment.type == 1 && segment.fileSize > 0) {
                    loadEvidence = true;
                }
                if (segment.type != 0 && segment.fileSize > 0) {
                    ranges.add(new Range(segment.offset, add(segment.offset, segment.fileSize)));
                }
            }
            ranges.sort(Comparator.comparingLong(Range::start).thenComparingLong(Range::end));
            long start = -1;
            long end = -1;
            for (Range range : ranges) {
                checkCancelled(cancelled);
                if (start < 0) {
                    start = range.start();
                    end = range.end();
                }
                else if (range.start() <= end) {
                    end = Math.max(end, range.end());
                }
                else {
                    difference = payload(start, end, tableEnd);
                    if (difference != null) {
                        return difference;
                    }
                    start = range.start();
                    end = range.end();
                }
            }
            if (start >= 0) {
                difference = payload(start, end, tableEnd);
                if (difference != null) {
                    return difference;
                }
            }
            checkCancelled(cancelled);
            return new Result(loadEvidence ? Status.MATCHING_PROGRAM_BYTES :
                Status.NO_FILE_BACKED_LOAD_EVIDENCE, Optional.empty(), loadEvidence
                    ? "declared header, program table and program payload bytes match except ELF section-table fields"
                    : "compared bytes match, but original has no PT_LOAD with nonzero file size");
        }

        private Result programTable(int count) throws IOException {
            if (count == 0) {
                return null;
            }
            int entrySize = originalHeader.programEntrySize();
            int entriesPerBuffer = BUFFER_BYTES / entrySize;
            for (int index = 0; index < count;) {
                checkCancelled(cancelled);
                int entries = Math.min(entriesPerBuffer, count - index);
                int bytes = entries * entrySize;
                long at = add(originalHeader.programOffset(), multiply(index, entrySize));
                readAt(original, left, at, bytes);
                readAt(candidate, right, at, bytes);
                for (int item = 0; item < entries; item++) {
                    checkCancelled(cancelled);
                    requireObservedSegment(left, item * entrySize, before.segments().get(index + item),
                        before.is64Bit());
                    requireObservedSegment(right, item * entrySize, after.segments().get(index + item),
                        after.is64Bit());
                }
                Result difference = bytes(Region.PROGRAM_TABLE, at, bytes, false);
                if (difference != null) {
                    return difference;
                }
                index += entries;
            }
            return null;
        }

        /** Exclude already-compared header/table bytes from the merged payload union. */
        private Result payload(long start, long end, long tableEnd) throws IOException {
            long next = Math.max(start, originalHeader.size());
            if (next >= end) {
                return null;
            }
            long tableStart = originalHeader.programOffset();
            if (tableStart < tableEnd && next < tableEnd && end > tableStart) {
                Result difference = range(Region.PROGRAM_PAYLOAD, next, Math.min(end, tableStart));
                if (difference != null) {
                    return difference;
                }
                next = Math.max(next, tableEnd);
            }
            return range(Region.PROGRAM_PAYLOAD, next, end);
        }

        private Result range(Region region, long start, long end) throws IOException {
            for (long at = start; at < end;) {
                checkCancelled(cancelled);
                int count = (int) Math.min(BUFFER_BYTES, end - at);
                readAt(original, left, at, count);
                readAt(candidate, right, at, count);
                Result difference = bytes(region, at, count, false);
                if (difference != null) {
                    return difference;
                }
                at += count;
            }
            return null;
        }

        private Result bytes(Region region, long at, int count, boolean maskHeader) {
            checkCancelled(cancelled);
            int different = -1;
            if (maskHeader) {
                for (int index = 0; index < count; index++) {
                    if (!sectionField(before.is64Bit(), index) && left.get(index) != right.get(index)) {
                        different = index;
                        break;
                    }
                }
            }
            else {
                different = Arrays.mismatch(left.array(), 0, count, right.array(), 0, count);
            }
            if (different < 0) {
                return null;
            }
            return new Result(Status.DIFFERENT_PROGRAM_BYTES, Optional.of(new Issue(region,
                OptionalLong.of(at + different), hex(left.get(different)), hex(right.get(different)))),
                "first byte difference in " + region + " comparison phase");
        }

        private void requireObservedCount(SeekableByteChannel channel, ElfImage elf,
                Header header, ByteBuffer buffer) throws IOException {
            if (header.encodedProgramCount() == 0xffff) {
                readAt(channel, buffer, add(header.sectionOffset(), elf.is64Bit() ? 44 : 28), 4);
                if (Integer.toUnsignedLong(buffer.getInt(0)) != elf.segments().size()) {
                    throw new IOException("extended program count changed after metadata observation");
                }
            }
        }

        private void readAt(SeekableByteChannel channel, ByteBuffer buffer, long at, int count)
                throws IOException {
            checkCancelled(cancelled);
            buffer.clear().limit(count);
            channel.position(at);
            while (buffer.hasRemaining()) {
                checkCancelled(cancelled);
                int remaining = buffer.remaining();
                int read = channel.read(buffer);
                if (read <= 0 || read > remaining || buffer.remaining() != remaining - read) {
                    throw new IOException("ELF program bytes ended or made no valid read progress");
                }
            }
            checkCancelled(cancelled);
        }
    }

    private static void requireObservedSegment(ByteBuffer data, int at, ElfImage.Segment expected,
            boolean wide) throws IOException {
        long type = Integer.toUnsignedLong(data.getInt(at));
        boolean same = type == expected.type;
        if (type != 0 && same) {
            same = word(data, at + (wide ? 8 : 4), wide) == expected.offset &&
                word(data, at + (wide ? 16 : 8), wide) == expected.virtualAddress &&
                word(data, at + (wide ? 32 : 16), wide) == expected.fileSize &&
                word(data, at + (wide ? 40 : 20), wide) == expected.memorySize &&
                Integer.toUnsignedLong(data.getInt(at + (wide ? 4 : 24))) == expected.flags &&
                word(data, at + (wide ? 48 : 28), wide) == expected.alignment;
        }
        if (!same) {
            throw new IOException("program fields changed after metadata observation");
        }
    }

    private static boolean sectionField(boolean wide, int offset) {
        return wide ? offset >= 40 && offset < 48 || offset >= 58 && offset < 64
            : offset >= 32 && offset < 36 || offset >= 46 && offset < 52;
    }

    private static void requireObservedHeader(ByteBuffer actual, byte[] expected) throws IOException {
        for (int index = 0; index < expected.length; index++) {
            if (actual.get(index) != expected[index]) {
                throw new IOException("ELF header changed after metadata observation");
            }
        }
    }

    private static ElfImage read(Path path, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        ElfImage elf;
        try {
            elf = ElfImage.read(path);
        }
        catch (IllegalArgumentException malformed) {
            throw new IOException("invalid ELF metadata for program-byte observation", malformed);
        }
        checkCancelled(cancelled);
        return elf;
    }

    private static SeekableByteChannel open(Path path, BooleanSupplier cancelled, ChannelOpener opener)
            throws IOException {
        checkCancelled(cancelled);
        return Objects.requireNonNull(opener.open(path), "opened channel");
    }

    private static BasicFileAttributes attributes(Path path) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class);
        if (!attributes.isRegularFile()) {
            throw new IOException("program-byte input is not a regular file: " + path);
        }
        return attributes;
    }

    private static void requireUnchanged(Path path, BasicFileAttributes before) throws IOException {
        BasicFileAttributes after = attributes(path);
        if (before.size() != after.size() ||
                !before.lastModifiedTime().equals(after.lastModifiedTime()) ||
                !Objects.equals(before.fileKey(), after.fileKey())) {
            throw new IOException("ELF input changed during program-byte observation: " + path);
        }
    }

    private static void requireSize(SeekableByteChannel input, long expected) throws IOException {
        if (input.size() != expected) {
            throw new IOException("ELF channel size changed after metadata observation");
        }
    }

    private static long word(ByteBuffer data, int offset, boolean wide) {
        return wide ? data.getLong(offset) : Integer.toUnsignedLong(data.getInt(offset));
    }

    private static long add(long left, long right) throws IOException {
        try {
            return Math.addExact(left, right);
        }
        catch (ArithmeticException overflow) {
            throw new IOException("ELF program-byte offset overflow", overflow);
        }
    }

    private static long multiply(long left, long right) throws IOException {
        try {
            return Math.multiplyExact(left, right);
        }
        catch (ArithmeticException overflow) {
            throw new IOException("ELF program-table size overflow", overflow);
        }
    }

    private static String hex(byte value) {
        return String.format(java.util.Locale.ROOT, "0x%02x", Byte.toUnsignedInt(value));
    }

    private static void requireText(String text, String description) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException(description + " is required");
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("executable program-byte observation cancelled");
        }
    }
}
