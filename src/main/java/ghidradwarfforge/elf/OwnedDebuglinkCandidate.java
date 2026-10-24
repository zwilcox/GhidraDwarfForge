package ghidradwarfforge.elf;

import ghidradwarfforge.output.FileDigests;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Prepares an initial debuglink candidate in a new, caller-owned scratch directory.
 * Never publishes to an executable path, invokes a backend or applies the matched
 * sidecar transformations. Only e_shoff/e_shnum/e_shstrndx change in the copied
 * prefix; two nonallocated records and their payloads are appended. Original
 * section indexes, raw names/records, e_shentsize and PN_XNUM are retained.
 *
 * This deliberately narrower envelope requires ET_EXEC/ET_DYN, canonical named
 * sections, no existing association, file-backed LOAD and covered allocation
 * evidence. Rejection does not narrow ordinary export. Literal basename bytes
 * have no implied host encoding or correspondence to the selected sidecar name.
 * No permissions, identity, snapshot, valid-DWARF or attachment approval follows.
 * The caller retains successful scratch output and arranges any colocation.
 *
 * ElfImage's signed offsets and metadata limits apply. Appended names/records
 * stay within those limits; files copy with bounded buffers. Maximum metadata
 * combinations are not promised to fit 64 MiB. Observations are sequential,
 * change checks best effort, and cancellation cannot interrupt every filesystem
 * call. Failure cleanup removes only the exact created file and empty directory;
 * cleanup failures carry retained paths and are suppressed on the original error.
 */
public final class OwnedDebuglinkCandidate {
    private static final byte[] LINK_NAME = ".gnu_debuglink".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] EXTRA_NAMES = ".gnu_debuglink\0.shstrtab\0".getBytes(StandardCharsets.US_ASCII);
    private static final long UINT32_END = 0x1_0000_0000L;
    private static final int SHN_LORESERVE = 0xff00;
    private static final int SHN_XINDEX = 0xffff;

    /** Successful scratch ownership transfers to the caller; there is no automatic deletion. */
    public record Result(Path directory, Path candidate, DebuglinkCandidateContent.Result content) {
        public Result {
            Objects.requireNonNull(directory, "directory");
            Objects.requireNonNull(candidate, "candidate");
            Objects.requireNonNull(content, "content");
        }
    }

    // Package-only fault seam: create owns a newly opened read/write channel;
    // the factory closes it. Deletion is invoked only for factory-owned paths.
    interface FileOperations {
        FileChannel create(Path path) throws IOException;
        void delete(Path path) throws IOException;
    }

    private static final FileOperations FILES = new FileOperations() {
        public FileChannel create(Path path) throws IOException {
            return FileChannel.open(path, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ, StandardOpenOption.WRITE);
        }
        public void delete(Path path) throws IOException { Files.deleteIfExists(path); }
    };

    private OwnedDebuglinkCandidate() {
    }

    public static Result create(Path original, Path sidecar, byte[] basename, Path parent)
            throws IOException {
        return create(original, sidecar, basename, parent, () -> false);
    }

    public static Result create(Path original, Path sidecar, byte[] basename, Path parent,
            BooleanSupplier cancelled) throws IOException {
        return create(original, sidecar, basename, parent, cancelled, FILES);
    }

    static Result create(Path original, Path sidecar, byte[] selectedBasename, Path parent,
            BooleanSupplier cancelled, FileOperations files) throws IOException {
        Objects.requireNonNull(original, "original");
        Objects.requireNonNull(sidecar, "sidecar");
        Objects.requireNonNull(parent, "parent");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(files, "files");
        byte[] basename = basename(selectedBasename);
        checkCancelled(cancelled);
        regular(original);
        regular(sidecar);
        Path workspace = parent.toRealPath();
        if (!Files.isDirectory(workspace)) {
            throw new IOException("candidate parent is not an existing directory: " + parent);
        }
        ElfImage image = read(original, cancelled);
        Plan plan = plan(image, basename.length, cancelled);
        // The deliberately absent link is not a positive link observation.
        // Reuse only the independent positive program/allocation checks and digest.
        var before = DebuglinkCandidateContent.observe(original, original, sidecar, basename, cancelled);
        requireProgramAndAllocation(before);
        checkCancelled(cancelled);
        Path directory = Files.createTempDirectory(workspace, "forge-debuglink-");
        Path candidate = directory.resolve("candidate.elf");
        boolean created = false;
        try {
            checkCancelled(cancelled);
            try (FileChannel output = files.create(candidate)) {
                created = true;
                image.copyTo(output, cancelled);
                // Reread/copy races must not silently install a stale section plan.
                requireCopied(output, 0, image.headerBytes(), cancelled);
                requireCopied(output, plan.oldTableOffset, plan.records, cancelled);
                requireCopied(output, plan.oldNamesOffset, plan.names, cancelled);
                serialize(output, image, plan, basename, before.sidecarDigest(), cancelled);
            }
            var content = DebuglinkCandidateContent.observe(original, candidate, sidecar, basename, cancelled);
            requireProgramAndAllocation(content);
            if (content.newDebuglink().status() != DebuglinkCandidateContent.DebuglinkStatus.MATCHING) {
                throw new IOException("candidate debuglink construction postcondition failed: " + content.newDebuglink());
            }
            if (!before.sidecarDigest().equals(content.sidecarDigest())) {
                throw new IOException("selected sidecar digest changed during candidate construction");
            }
            checkCancelled(cancelled);
            return new Result(directory, candidate, content);
        }
        catch (IOException | RuntimeException | Error failure) {
            if (created) {
                cleanup(files, candidate, failure);
            }
            cleanup(files, directory, failure);
            throw failure;
        }
    }

    private static void requireProgramAndAllocation(DebuglinkCandidateContent.Result content) throws IOException {
        if (content.programBytes().status() != ExecutableProgramBytes.Status.MATCHING_PROGRAM_BYTES) {
            throw new IOException("unsupported candidate program evidence: " + content.programBytes());
        }
        if (content.allocatedSections().status() != DebuglinkCandidateContent.AllocationStatus.MATCHING) {
            throw new IOException("unsupported candidate allocation evidence: " + content.allocatedSections());
        }
    }

    private record Plan(Layout layout, long oldTableOffset, byte[] records,
            long oldNamesOffset, byte[] names) { }

    // Pure package-visible arithmetic allows exact 4-GiB/long boundaries to be
    // tested without claiming a 4-GiB runtime fixture or allocating that array.
    record Layout(long linkOffset, int linkSize, long namesOffset, int namesSize,
            long tableOffset, int tableSize, int count, int nameIndex, long end) { }

    static Layout layout(boolean wide, long inputSize, int oldNamesSize, int oldCount,
            int basenameSize) throws IOException {
        if (inputSize < 0 || oldNamesSize < 1 || oldCount < 1 || basenameSize < 1 || basenameSize > 65536) {
            throw new IOException("invalid candidate layout dimensions");
        }
        long count = add(oldCount, 2);
        long namesSize = add(oldNamesSize, EXTRA_NAMES.length);
        long tableSize = count * (wide ? 64 : 40);
        if (count > ElfImage.MAX_HEADER_COUNT || namesSize > ElfImage.MAX_NAME_TABLE_BYTES ||
                tableSize > ElfImage.MAX_TABLE_BYTES) {
            throw new IOException("candidate appended metadata exceeds reader safety limits");
        }
        int linkSize = ((basenameSize + 4) & ~3) + 4;
        long linkOffset = align(inputSize, 4);
        long namesOffset = add(linkOffset, linkSize);
        long tableOffset = align(add(namesOffset, namesSize), wide ? 8 : 4);
        long end = add(tableOffset, tableSize);
        if (!wide && (linkOffset >= UINT32_END || namesOffset >= UINT32_END ||
                tableOffset >= UINT32_END || end > UINT32_END)) {
            throw new IOException("candidate layout exceeds ELF32 encoded offsets or 2^32 end");
        }
        return new Layout(linkOffset, linkSize, namesOffset, (int) namesSize,
            tableOffset, (int) tableSize, (int) count, (int) count - 1, end);
    }

    private static Plan plan(ElfImage image, int basenameSize, BooleanSupplier cancelled) throws IOException {
        if (image.type() != 2 && image.type() != 3) {
            throw new IOException("unsupported candidate type: requires ET_EXEC or ET_DYN");
        }
        boolean wide = image.is64Bit();
        ByteBuffer header = ByteBuffer.wrap(image.headerBytes()).order(image.byteOrder());
        int entrySize = Short.toUnsignedInt(header.getShort(wide ? 58 : 46));
        if (image.sections().isEmpty() || image.sectionNameIndex() == 0 || entrySize != (wide ? 64 : 40)) {
            throw new IOException("unsupported candidate section table: requires canonical named records");
        }
        ElfImage.Section zero = image.sections().get(0);
        if ((header.getShort(wide ? 60 : 48) != 0 && zero.size != 0) ||
                (Short.toUnsignedInt(header.getShort(wide ? 62 : 50)) != SHN_XINDEX && zero.link != 0) ||
                (Short.toUnsignedInt(header.getShort(wide ? 56 : 44)) != 0xffff && zero.info != 0)) {
            throw new IOException("unsupported nonzero unused section-zero extension bookkeeping");
        }
        ElfImage.Section namesSection = image.sections().get(image.sectionNameIndex());
        Layout layout = layout(wide, image.fileSize(), Math.toIntExact(namesSection.size),
            image.sections().size(), basenameSize);
        long tableOffset = wide ? header.getLong(40) : Integer.toUnsignedLong(header.getInt(32));
        checkCancelled(cancelled);
        byte[] records = range(image, tableOffset, (long) entrySize * image.sections().size(), "candidate original section records");
        checkCancelled(cancelled);
        byte[] names = range(image, namesSection.offset, namesSection.size, "candidate raw section names");
        if (names.length == 0 || names.length > ElfImage.MAX_NAME_TABLE_BYTES || names[0] != 0 || names[names.length - 1] != 0) {
            throw new IOException("raw section-name table must be nonempty, bounded and NUL-bounded");
        }
        ByteBuffer raw = ByteBuffer.wrap(records).order(image.byteOrder());
        Map<Long, Integer> ends = new HashMap<>();
        long aggregate = EXTRA_NAMES.length - 2;
        for (ElfImage.Section section : image.sections()) {
            checkCancelled(cancelled);
            int at = section.originalIndex * entrySize;
            long[] expected = {section.nameOffset, section.type, section.flags, section.address,
                section.offset, section.size, section.link, section.info, section.alignment, section.entrySize};
            int[] offsets = wide ? new int[] {0, 4, 8, 16, 24, 32, 40, 44, 48, 56} :
                new int[] {0, 4, 8, 12, 16, 20, 24, 28, 32, 36};
            for (int index = 0; index < offsets.length; index++) {
                long observed = wide && index >= 2 && index != 6 && index != 7 ? raw.getLong(at + offsets[index]) :
                    Integer.toUnsignedLong(raw.getInt(at + offsets[index]));
                if (expected[index] != observed) {
                    throw new IOException("original section record changed after parsing at index " + section.originalIndex);
                }
            }
            long offset = section.nameOffset;
            if (offset < 0 || offset >= names.length) {
                throw new IOException("raw section-name offset is outside table");
            }
            Integer end = ends.get(offset);
            if (end == null) {
                int cursor = (int) offset;
                while (cursor < names.length && names[cursor] != 0) {
                    if ((cursor & 1023) == 0) { checkCancelled(cancelled); }
                    if (cursor - offset == ElfImage.MAX_NAME_BYTES) {
                        throw new IOException("raw section name exceeds 65536-byte safety limit");
                    }
                    cursor++;
                }
                if (cursor == names.length) { throw new IOException("unterminated raw section name"); }
                aggregate += cursor - offset;
                if (aggregate > ElfImage.MAX_NAME_TABLE_BYTES) {
                    throw new IOException("appended decoded-name aggregate exceeds safety limit");
                }
                end = cursor;
                ends.put(offset, end);
            }
            if (end - offset == LINK_NAME.length &&
                    Arrays.equals(names, (int) offset, end, LINK_NAME, 0, LINK_NAME.length)) {
                throw new IOException("unsupported initial candidate: original already names .gnu_debuglink");
            }
        }
        checkCancelled(cancelled);
        return new Plan(layout, tableOffset, records, namesSection.offset, names);
    }

    private static void serialize(FileChannel output, ElfImage image, Plan plan, byte[] basename,
            FileDigests.Result digest, BooleanSupplier cancelled) throws IOException {
        Layout layout = plan.layout;
        boolean wide = image.is64Bit();
        byte[] link = Arrays.copyOf(basename, layout.linkSize);
        ByteBuffer.wrap(link).order(image.byteOrder()).putInt(link.length - 4, (int) digest.gnuDebuglinkCrc32());
        // Positional file expansion does not specify the contents of a gap.
        // Write alignment bytes explicitly rather than relying on filesystem holes.
        write(output, image.fileSize(), new byte[(int) (layout.linkOffset - image.fileSize())], cancelled);
        write(output, layout.linkOffset, link, cancelled);
        write(output, layout.namesOffset, plan.names, cancelled);
        write(output, layout.namesOffset + plan.names.length, EXTRA_NAMES, cancelled);
        long namesEnd = layout.namesOffset + layout.namesSize;
        write(output, namesEnd, new byte[(int) (layout.tableOffset - namesEnd)], cancelled);
        // Patch only the NEW section zero. The original table remains inert and
        // byte-identical in the retained prefix, including its original escapes.
        byte[] zero = Arrays.copyOf(plan.records, wide ? 64 : 40);
        ByteBuffer nullRecord = ByteBuffer.wrap(zero).order(image.byteOrder());
        word(nullRecord, wide ? 32 : 20, layout.count >= SHN_LORESERVE ? layout.count : 0, wide);
        nullRecord.putInt(wide ? 40 : 24, layout.nameIndex >= SHN_LORESERVE ? layout.nameIndex : 0);
        write(output, layout.tableOffset, zero, cancelled);
        write(output, layout.tableOffset + zero.length, ByteBuffer.wrap(plan.records, zero.length,
            plan.records.length - zero.length), cancelled);
        write(output, layout.tableOffset + plan.records.length,
            section(image, plan.names.length, 1, layout.linkOffset, layout.linkSize, 4), cancelled);
        write(output, layout.tableOffset + plan.records.length + zero.length,
            section(image, plan.names.length + LINK_NAME.length + 1, 3, layout.namesOffset, layout.namesSize, 1), cancelled);
        ByteBuffer field = ByteBuffer.allocate(wide ? 8 : 4).order(image.byteOrder());
        word(field, 0, layout.tableOffset, wide);
        write(output, wide ? 40 : 32, field.array(), cancelled);
        ByteBuffer counts = ByteBuffer.allocate(4).order(image.byteOrder());
        counts.putShort((short) (layout.count >= SHN_LORESERVE ? 0 : layout.count));
        counts.putShort((short) (layout.nameIndex >= SHN_LORESERVE ? SHN_XINDEX : layout.nameIndex));
        write(output, wide ? 60 : 48, counts.array(), cancelled);
        if (output.size() != layout.end) { throw new IOException("candidate length disagrees with construction plan"); }
        checkCancelled(cancelled);
    }

    private static byte[] section(ElfImage image, int name, int type, long offset, long size, int alignment) {
        boolean wide = image.is64Bit();
        ByteBuffer b = ByteBuffer.allocate(wide ? 64 : 40).order(image.byteOrder());
        b.putInt(0, name).putInt(4, type);
        word(b, wide ? 24 : 16, offset, wide);
        word(b, wide ? 32 : 20, size, wide);
        word(b, wide ? 48 : 32, alignment, wide);
        return b.array();
    }

    private static void word(ByteBuffer data, int at, long value, boolean wide) {
        if (wide) { data.putLong(at, value); }
        else { data.putInt(at, (int) value); }
    }

    private static void requireCopied(FileChannel output, long offset, byte[] expected,
            BooleanSupplier cancelled) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(Math.min(65536, expected.length));
        int at = 0;
        while (at < expected.length) {
            checkCancelled(cancelled);
            buffer.clear().limit(Math.min(buffer.capacity(), expected.length - at));
            int count = output.read(buffer, offset + at);
            if (count <= 0) { throw new IOException("copied metadata read made no progress"); }
            for (int index = 0; index < count; index++) {
                if (buffer.get(index) != expected[at + index]) {
                    throw new IOException("copied original metadata differs from construction plan at " + (offset + at + index));
                }
            }
            at += count;
        }
    }

    private static void write(FileChannel output, long offset, byte[] bytes, BooleanSupplier cancelled) throws IOException {
        write(output, offset, ByteBuffer.wrap(bytes), cancelled);
    }

    private static void write(FileChannel output, long offset, ByteBuffer bytes, BooleanSupplier cancelled) throws IOException {
        int start = bytes.position();
        while (bytes.hasRemaining()) {
            checkCancelled(cancelled);
            int count = Math.min(bytes.remaining(), 65536);
            int limit = bytes.limit();
            bytes.limit(bytes.position() + count);
            int written = output.write(bytes, offset + bytes.position() - start);
            bytes.limit(limit);
            if (written <= 0) { throw new IOException("candidate write made no progress"); }
        }
    }

    private static ElfImage read(Path path, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        ElfImage image;
        try { image = ElfImage.read(path); }
        catch (IllegalArgumentException malformed) { throw new IOException("malformed original ELF: " + malformed.getMessage(), malformed); }
        checkCancelled(cancelled);
        return image;
    }

    private static byte[] range(ElfImage image, long offset, long size, String description) throws IOException {
        try { return image.readSourceRange(offset, size, description); }
        catch (IllegalArgumentException malformed) { throw new IOException(description + ": " + malformed.getMessage(), malformed); }
    }

    private static byte[] basename(byte[] value) {
        Objects.requireNonNull(value, "basename");
        if (value.length == 0 || value.length > 65536) { throw new IllegalArgumentException("basename requires 1..65536 bytes"); }
        byte[] copy = value.clone();
        for (byte b : copy) {
            if (b == 0 || b == '/') { throw new IllegalArgumentException("basename contains NUL or slash"); }
        }
        if ((copy.length == 1 && copy[0] == '.') || (copy.length == 2 && copy[0] == '.' && copy[1] == '.')) {
            throw new IllegalArgumentException("basename is a dot directory");
        }
        return copy;
    }

    private static void regular(Path path) throws IOException {
        if (!Files.isRegularFile(path)) { throw new IOException("selected input is not a regular file: " + path); }
    }

    private static long add(long left, long right) throws IOException {
        try { return Math.addExact(left, right); }
        catch (ArithmeticException overflow) { throw new IOException("candidate layout overflows signed offsets", overflow); }
    }

    private static long align(long value, int alignment) throws IOException {
        return add(value, (alignment - value % alignment) % alignment);
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) { throw new CancellationException("owned debuglink candidate cancelled"); }
    }

    private static void cleanup(FileOperations files, Path path, Throwable failure) {
        try { files.delete(path); }
        catch (IOException | RuntimeException cleanup) {
            failure.addSuppressed(new IOException("candidate cleanup failed; retained path may exist: " + path, cleanup));
        }
    }
}
