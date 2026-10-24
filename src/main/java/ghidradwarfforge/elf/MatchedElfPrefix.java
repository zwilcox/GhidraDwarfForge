package ghidradwarfforge.elf;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Read-only comparison of the original-file prefix retained by the current
 * matched sidecar writer. A match establishes this byte relationship only,
 * not file identity, provenance, a snapshot, allocated-section/DWARF correctness,
 * source correlation, or attachment readiness. Appended data is not compared.
 * Ordinary export does not call this helper.
 *
 * Both files first pass {@link ElfImage}'s bounded metadata parsing. Its limits
 * and signed file-offset model apply; metadata parsing is not interruptible at
 * every read and is not promised to fit every maximum-table combination in a
 * 64 MiB heap. Prefix comparison uses two 64 KiB buffers, checks cancellation
 * around bounded reads/comparisons, and owns/closes both streams. A blocked
 * filesystem read cannot be interrupted by the cancellation supplier.
 *
 * Class/order disagreement, shorter candidate, and header-layout disagreement
 * are considered in that order before comparing bytes. Malformed ELF, I/O
 * failures and cancellation throw rather than returning an observation.
 */
public final class MatchedElfPrefix {
    private static final int BUFFER_BYTES = 64 * 1024;

    public enum Status {
        MATCHING_COPIED_PREFIX, DIFFERENT_PREFIX, SHORTER_CANDIDATE, DIFFERENT_LAYOUT
    }

    /**
     * Lengths are observed metadata lengths, not hashes or stable identities.
     * comparedExtent is the exclusive original-file offset examined, including
     * permitted header fields whose meaning was checked separately. It is zero
     * for pre-comparison outcomes, firstDifferentOffset+1 for a byte difference,
     * and originalByteCount for a match. Reads may look ahead by one buffer.
     */
    public record Result(Status status, long originalByteCount, long candidateByteCount,
            long comparedExtent, OptionalLong firstDifferentOffset, String diagnostic) {
        public Result {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(firstDifferentOffset, "firstDifferentOffset");
            if (originalByteCount < 0 || candidateByteCount < 0 || comparedExtent < 0 ||
                    comparedExtent > originalByteCount || comparedExtent > candidateByteCount ||
                    diagnostic == null || diagnostic.isBlank()) {
                throw new IllegalArgumentException("invalid copied-prefix observation");
            }
            if (status == Status.DIFFERENT_PREFIX) {
                if (firstDifferentOffset.isEmpty() || firstDifferentOffset.getAsLong() < 0 ||
                        firstDifferentOffset.getAsLong() >= comparedExtent ||
                        firstDifferentOffset.getAsLong() != comparedExtent - 1) {
                    throw new IllegalArgumentException("byte difference requires its examined offset");
                }
            }
            else if (firstDifferentOffset.isPresent() ||
                    (status == Status.MATCHING_COPIED_PREFIX ? comparedExtent != originalByteCount
                        : comparedExtent != 0)) {
                throw new IllegalArgumentException("inconsistent copied-prefix outcome");
            }
            if (status == Status.SHORTER_CANDIDATE && candidateByteCount >= originalByteCount) {
                throw new IllegalArgumentException("shorter candidate requires a smaller observed length");
            }
        }
    }

    @FunctionalInterface
    interface InputOpener {
        InputStream open(Path path) throws IOException;
    }

    private MatchedElfPrefix() {
    }

    public static Result compare(Path original, Path candidate) throws IOException {
        return compare(original, candidate, () -> false);
    }

    public static Result compare(Path original, Path candidate, BooleanSupplier cancelled)
            throws IOException {
        return compare(original, candidate, cancelled, Files::newInputStream);
    }

    /** Owns both successfully opened streams; the supplied paths are not rewritten. */
    static Result compare(Path original, Path candidate, BooleanSupplier cancelled, InputOpener opener)
            throws IOException {
        Objects.requireNonNull(original, "original");
        Objects.requireNonNull(candidate, "candidate");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(opener, "opener");
        checkCancelled(cancelled);
        BasicFileAttributes originalState = attributes(original);
        BasicFileAttributes candidateState = attributes(candidate);
        ElfImage before = readMetadata(original, "original", cancelled);
        ElfImage after = readMetadata(candidate, "candidate", cancelled);
        requireUnchanged(original, originalState);
        requireUnchanged(candidate, candidateState);
        if (before.fileSize() != originalState.size() || after.fileSize() != candidateState.size()) {
            throw new IOException("ELF size changed during metadata observation");
        }
        checkCancelled(cancelled);
        if (before.is64Bit() != after.is64Bit() || before.byteOrder() != after.byteOrder()) {
            return observation(Status.DIFFERENT_LAYOUT, before, after, "ELF class or byte order differs");
        }
        if (after.fileSize() < before.fileSize()) {
            return observation(Status.SHORTER_CANDIDATE, before, after, "candidate is shorter than original");
        }
        String layout = layoutDifference(before, after);
        if (layout != null) {
            return observation(Status.DIFFERENT_LAYOUT, before, after, layout);
        }

        Result result;
        try (InputStream first = open(original, cancelled, opener);
                InputStream second = open(candidate, cancelled, opener)) {
            result = compareStreams(first, second, before, after, cancelled);
            requireUnchanged(original, originalState);
            requireUnchanged(candidate, candidateState);
            checkCancelled(cancelled);
        }
        return result;
    }

    private static ElfImage readMetadata(Path path, String description, BooleanSupplier cancelled)
            throws IOException {
        checkCancelled(cancelled);
        try {
            ElfImage image = ElfImage.read(path);
            checkCancelled(cancelled);
            return image;
        }
        catch (IllegalArgumentException malformed) {
            throw new IOException("invalid " + description + " ELF metadata", malformed);
        }
    }

    private static InputStream open(Path path, BooleanSupplier cancelled, InputOpener opener)
            throws IOException {
        checkCancelled(cancelled);
        return Objects.requireNonNull(opener.open(path), "opened input");
    }

    private static String layoutDifference(ElfImage original, ElfImage candidate) {
        boolean wide = candidate.is64Bit();
        ByteBuffer header = ByteBuffer.wrap(candidate.headerBytes()).order(candidate.byteOrder());
        long programOffset = wide ? header.getLong(32) : Integer.toUnsignedLong(header.getInt(28));
        int programEntrySize = Short.toUnsignedInt(header.getShort(wide ? 54 : 42));
        int programCount = Short.toUnsignedInt(header.getShort(wide ? 56 : 44));
        if (programOffset != 0 || programEntrySize != 0 || programCount != 0) {
            return "matched candidate must have zero program-table offset, entry size and count";
        }
        long sectionOffset = wide ? header.getLong(40) : Integer.toUnsignedLong(header.getInt(32));
        int sectionEntrySize = Short.toUnsignedInt(header.getShort(wide ? 58 : 46));
        if (sectionOffset < original.fileSize() || candidate.sections().isEmpty() ||
                sectionEntrySize != (wide ? 64 : 40) || candidate.sectionNameIndex() == 0) {
            return "matched candidate requires an appended canonical section table with names";
        }
        return null;
    }

    private static Result compareStreams(InputStream first, InputStream second,
            ElfImage original, ElfImage candidate, BooleanSupplier cancelled) throws IOException {
        byte[] left = new byte[BUFFER_BYTES];
        byte[] right = new byte[BUFFER_BYTES];
        byte[] originalHeader = original.headerBytes();
        byte[] candidateHeader = candidate.headerBytes();
        long offset = 0;
        while (offset < original.fileSize()) {
            checkCancelled(cancelled);
            int count = (int) Math.min(BUFFER_BYTES, original.fileSize() - offset);
            readFully(first, left, count, cancelled);
            readFully(second, right, count, cancelled);
            int start = 0;
            if (offset == 0) {
                // Even permitted fields must still contain the metadata just
                // validated; do not silently mask a later header replacement.
                requireObservedHeader(left, originalHeader);
                requireObservedHeader(right, candidateHeader);
                for (int index = 0; index < originalHeader.length; index++) {
                    if (!permittedHeaderField(original.is64Bit(), index) && left[index] != right[index]) {
                        return difference(original, candidate, index, cancelled);
                    }
                }
                start = originalHeader.length;
            }
            int different = Arrays.mismatch(left, start, count, right, start, count);
            if (different >= 0) {
                // Every term is bounded by original.fileSize(); no int file offsets.
                return difference(original, candidate, offset + start + different, cancelled);
            }
            offset += count;
            checkCancelled(cancelled);
        }
        checkCancelled(cancelled);
        if (first.read() != -1) {
            throw new IOException("original grew after metadata observation");
        }
        checkCancelled(cancelled);
        return new Result(Status.MATCHING_COPIED_PREFIX, original.fileSize(), candidate.fileSize(),
            offset, OptionalLong.empty(), "original bytes retained except documented matched-header edits");
    }

    private static Result difference(ElfImage original, ElfImage candidate, long position,
            BooleanSupplier cancelled) {
        checkCancelled(cancelled);
        return new Result(Status.DIFFERENT_PREFIX, original.fileSize(), candidate.fileSize(),
            position + 1, OptionalLong.of(position), "retained original byte differs");
    }

    private static boolean permittedHeaderField(boolean wide, long offset) {
        return wide ? (offset >= 32 && offset < 48) || (offset >= 54 && offset < 64)
            : (offset >= 28 && offset < 36) || (offset >= 42 && offset < 52);
    }

    private static void readFully(InputStream input, byte[] buffer, int size, BooleanSupplier cancelled)
            throws IOException {
        int offset = 0;
        while (offset < size) {
            checkCancelled(cancelled);
            int count = input.read(buffer, offset, size - offset);
            if (count <= 0 || count > size - offset) {
                throw new IOException("ELF prefix input ended or made no valid progress after metadata observation");
            }
            offset += count;
        }
        checkCancelled(cancelled);
    }

    private static void requireObservedHeader(byte[] observed, byte[] expected) throws IOException {
        for (int offset = 0; offset < expected.length; offset++) {
            if (observed[offset] != expected[offset]) {
                throw new IOException("ELF header changed after metadata observation");
            }
        }
    }

    private static Result observation(Status status, ElfImage original, ElfImage candidate, String diagnostic) {
        return new Result(status, original.fileSize(), candidate.fileSize(), 0, OptionalLong.empty(), diagnostic);
    }

    private static BasicFileAttributes attributes(Path path) throws IOException {
        BasicFileAttributes result = Files.readAttributes(path, BasicFileAttributes.class);
        if (!result.isRegularFile()) {
            throw new IOException("ELF prefix input is not a regular file: " + path);
        }
        return result;
    }

    private static void requireUnchanged(Path path, BasicFileAttributes before) throws IOException {
        BasicFileAttributes after = attributes(path);
        // Best-effort ordinary-change detection, not file identity or a snapshot.
        // In particular, two null file keys do not establish file identity.
        if (before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime()) ||
                !Objects.equals(before.fileKey(), after.fileKey())) {
            throw new IOException("ELF prefix input changed during observation: " + path);
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("matched ELF prefix comparison cancelled");
        }
    }
}
