package ghidradwarfforge.elf;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.elf.MatchedElfPrefix.Status;
import ghidradwarfforge.elf.MatchedElfPrefixFixtures.Pair;
import ghidradwarfforge.elf.MatchedElfPrefixFixtures.Shape;
import ghidradwarfforge.output.FileDigests;

/** Read-only relationship tests; synthetic debug bytes do not claim valid DWARF. */
public final class MatchedElfPrefixSmoke {
    private MatchedElfPrefixSmoke() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 1 || (args.length == 1 && !args[0].equals("--large"))) {
            throw new IllegalArgumentException("optional --large runs actual >2GiB sparse I/O");
        }
        Path root = Files.createTempDirectory("forge-matched-prefix-");
        try {
            List<Pair> pairs = new ArrayList<>();
            for (boolean wide : new boolean[] { false, true }) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    for (Shape shape : Shape.values()) {
                        Pair pair = MatchedElfPrefixFixtures.create(root.resolve(wide + "-" + order + "-" + shape), wide, order, shape);
                        matchPreserving(pair);
                        if (shape == Shape.NAMED) {
                            pairs.add(pair);
                            differences(pair);
                            layoutControls(pair);
                            complementaryControls(pair);
                        }
                        if (shape == Shape.LARGE_HEADER) {
                            byteDifference(pair, wide ? 70 : 58, "header-extension.dbg");
                        }
                    }
                }
            }
            result(MatchedElfPrefix.compare(pairs.get(0).original(), pairs.get(2).candidate()),
                Status.DIFFERENT_LAYOUT, 0, OptionalLong.empty());
            result(MatchedElfPrefix.compare(pairs.get(0).original(), pairs.get(1).candidate()),
                Status.DIFFERENT_LAYOUT, 0, OptionalLong.empty());
            resources(pairs.get(0));
            if (args.length == 1) {
                large(root.resolve("large"));
            }
            System.out.println("matched-elf-prefix-smoke=PASS large=" + (args.length == 1));
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
    }

    private static void matchPreserving(Pair pair) throws Exception {
        var originalDigest = FileDigests.read(pair.original());
        var candidateDigest = FileDigests.read(pair.candidate());
        var originalTime = Files.getLastModifiedTime(pair.original());
        var candidateTime = Files.getLastModifiedTime(pair.candidate());
        var observed = MatchedElfPrefix.compare(pair.original(), pair.candidate());
        result(observed, Status.MATCHING_COPIED_PREFIX, originalDigest.byteCount(), OptionalLong.empty());
        require(observed.originalByteCount() == originalDigest.byteCount() &&
            observed.candidateByteCount() == candidateDigest.byteCount(), "observed file lengths changed");
        result(MatchedElfPrefix.compare(pair.original(), pair.candidate(), () -> false), Status.MATCHING_COPIED_PREFIX,
            originalDigest.byteCount(), OptionalLong.empty());
        require(FileDigests.read(pair.original()).equals(originalDigest) && FileDigests.read(pair.candidate()).equals(candidateDigest)
            && Files.getLastModifiedTime(pair.original()).equals(originalTime)
            && Files.getLastModifiedTime(pair.candidate()).equals(candidateTime), "comparison changed input bytes or mtime");
        ElfImage image = ElfImage.read(pair.original());
        require(image.machine() == 0xffee && image.flags() == 0x8000_0001L,
            "unknown-machine/unsigned-flags control is vacuous");
    }

    private static void differences(Pair pair) throws Exception {
        int headerSize = pair.wide() ? 64 : 52;
        // Adjacent bytes on EVERY preserved side of the exception ranges,
        // plus non-layout target metadata, copied tables and opaque trailing bytes.
        int[] offsets = pair.wide()
            ? new int[] { 7, 8, 9, 15, 16, 18, 24, 31, 48, 51, 52, 53, 64, 0x90, 0x245, 0x320 }
            : new int[] { 7, 8, 9, 15, 16, 18, 24, 27, 36, 39, 40, 41, 52, 0x90, 0x245, 0x320 };
        for (int offset : offsets) {
            byteDifference(pair, offset, "changed-" + offset + ".dbg");
        }
        byteDifference(pair, Files.size(pair.original()) - 1, "last-original-byte.dbg");
        Path malformed = MatchedElfPrefixFixtures.changed(pair, "invalid-magic.dbg", 0, (byte) 0);
        expect(IOException.class, () -> MatchedElfPrefix.compare(pair.original(), malformed));
        Path truncated = pair.original().resolveSibling("truncated.elf");
        Files.write(truncated, new byte[headerSize - 1]);
        expect(IOException.class, () -> MatchedElfPrefix.compare(truncated, pair.candidate()));
        result(MatchedElfPrefix.compare(pair.original(), pair.original()), Status.DIFFERENT_LAYOUT, 0, OptionalLong.empty());
        Path longer = pair.original().resolveSibling("longer-original.elf");
        Files.copy(pair.original(), longer);
        try (FileChannel channel = FileChannel.open(longer, StandardOpenOption.WRITE)) {
            channel.position(Files.size(pair.candidate()) + 9);
            channel.write(ByteBuffer.wrap(new byte[] { 3 }));
        }
        result(MatchedElfPrefix.compare(longer, pair.candidate()), Status.SHORTER_CANDIDATE, 0, OptionalLong.empty());
    }

    private static void byteDifference(Pair pair, long offset, String name) throws Exception {
        byte old;
        try (FileChannel input = FileChannel.open(pair.candidate())) {
            ByteBuffer one = ByteBuffer.allocate(1);
            require(input.read(one, offset) == 1, "missing mutation byte");
            old = one.array()[0];
        }
        Path changed = MatchedElfPrefixFixtures.changed(pair, name, offset, (byte) (old ^ 1));
        result(MatchedElfPrefix.compare(pair.original(), changed), Status.DIFFERENT_PREFIX, offset + 1, OptionalLong.of(offset));
    }

    private static void layoutControls(Pair pair) throws Exception {
        byte[] original = Files.readAllBytes(pair.original());
        byte[] candidate = Files.readAllBytes(pair.candidate());
        ByteBuffer before = ByteBuffer.wrap(original).order(pair.order());
        for (String variant : List.of("ph-table", "ph-size", "old-sh-table", "nameless", "oversized-sh-entry")) {
            byte[] changed = candidate.clone();
            ByteBuffer b = ByteBuffer.wrap(changed).order(pair.order());
            switch (variant) {
                case "ph-table" -> {
                    if (pair.wide()) {
                        b.putLong(32, before.getLong(32));
                    }
                    else {
                        b.putInt(28, before.getInt(28));
                    }
                    b.putShort(pair.wide() ? 54 : 42, before.getShort(pair.wide() ? 54 : 42));
                    b.putShort(pair.wide() ? 56 : 44, before.getShort(pair.wide() ? 56 : 44));
                }
                case "ph-size" -> b.putShort(pair.wide() ? 54 : 42, (short) 1);
                case "old-sh-table" -> {
                    if (pair.wide()) {
                        b.putLong(40, before.getLong(40));
                    }
                    else {
                        b.putInt(32, before.getInt(32));
                    }
                    b.putShort(pair.wide() ? 60 : 48, before.getShort(pair.wide() ? 60 : 48));
                    b.putShort(pair.wide() ? 62 : 50, before.getShort(pair.wide() ? 62 : 50));
                }
                case "nameless" -> b.putShort(pair.wide() ? 62 : 50, (short) 0);
                case "oversized-sh-entry" -> {
                    int oldOffset = pair.wide() ? Math.toIntExact(b.getLong(40)) : b.getInt(32);
                    int size = pair.wide() ? 64 : 40;
                    int count = Short.toUnsignedInt(b.getShort(pair.wide() ? 60 : 48));
                    int newOffset = changed.length + 8;
                    changed = Arrays.copyOf(changed, newOffset + (size + 8) * count);
                    for (int index = 0; index < count; index++) {
                        System.arraycopy(candidate, oldOffset + index * size, changed, newOffset + index * (size + 8), size);
                    }
                    b = ByteBuffer.wrap(changed).order(pair.order());
                    if (pair.wide()) {
                        b.putLong(40, newOffset);
                    }
                    else {
                        b.putInt(32, newOffset);
                    }
                    b.putShort(pair.wide() ? 58 : 46, (short) (size + 8));
                }
                default -> throw new AssertionError();
            }
            Path path = pair.original().resolveSibling(variant + ".dbg");
            Files.write(path, changed);
            ElfImage.read(path); // Non-vacuous valid ELF: reject the envelope, not corrupt metadata.
            result(MatchedElfPrefix.compare(pair.original(), path), Status.DIFFERENT_LAYOUT, 0, OptionalLong.empty());
        }
        Path broken = pair.original().resolveSibling("broken-extended-count.dbg");
        ByteBuffer invalid = ByteBuffer.wrap(candidate.clone()).order(pair.order());
        invalid.putShort(pair.wide() ? 60 : 48, (short) 0);
        Files.write(broken, invalid.array());
        expect(IOException.class, () -> MatchedElfPrefix.compare(pair.original(), broken));
    }

    private static void complementaryControls(Pair pair) throws Exception {
        Path differentCode = pair.original().resolveSibling("different-code.elf");
        byte[] bytes = Files.readAllBytes(pair.original());
        bytes[0x245] ^= 1;
        Files.write(differentCode, bytes);
        require(ElfBuildId.compare(ElfBuildId.read(differentCode), ElfBuildId.read(pair.candidate()))
            == ElfBuildId.Relationship.SAME_BUILD_ID, "code mutant changed build ID");
        require(Arrays.equals(ElfImage.read(differentCode).headerBytes(), ElfImage.read(pair.original()).headerBytes()),
            "code mutant changed header fields");
        result(MatchedElfPrefix.compare(differentCode, pair.candidate()), Status.DIFFERENT_PREFIX, 0x246, OptionalLong.of(0x245));

        byte[] altered = Files.readAllBytes(pair.candidate());
        ByteBuffer b = ByteBuffer.wrap(altered).order(pair.order());
        int table = pair.wide() ? Math.toIntExact(b.getLong(40)) : b.getInt(32);
        int addressOffset = table + (pair.wide() ? 64 + 16 : 40 + 12);
        require(addressOffset >= Files.size(pair.original()), "active table is not appended");
        if (pair.wide()) {
            b.putLong(addressOffset, b.getLong(addressOffset) + 0x10000000);
        }
        else {
            b.putInt(addressOffset, b.getInt(addressOffset) + 0x10000000);
        }
        Path differentLayout = pair.original().resolveSibling("different-active-address.dbg");
        Files.write(differentLayout, altered);
        require(ElfImage.read(differentLayout).sections().get(1).address != ElfImage.read(pair.candidate()).sections().get(1).address,
            "active allocated address mutation is vacuous");
        require(ElfBuildId.compare(ElfBuildId.read(pair.original()), ElfBuildId.read(differentLayout))
            == ElfBuildId.Relationship.SAME_BUILD_ID, "active-address mutant changed build ID");
        result(MatchedElfPrefix.compare(pair.original(), differentLayout), Status.MATCHING_COPIED_PREFIX,
            Files.size(pair.original()), OptionalLong.empty());
    }

    private static void resources(Pair pair) throws Exception {
        AtomicInteger opens = new AtomicInteger();
        expect(CancellationException.class, () -> MatchedElfPrefix.compare(Path.of("unopened-missing"), pair.candidate(),
            () -> true, path -> { opens.incrementAndGet(); throw new AssertionError(); }));
        require(opens.get() == 0, "cancel-before-open touched the opener");
        IllegalArgumentException parserCallback = new IllegalArgumentException("supplier after parser");
        AtomicInteger metadataPolls = new AtomicInteger();
        require(expect(IllegalArgumentException.class, () -> MatchedElfPrefix.compare(pair.original(), pair.candidate(),
            () -> {
                boolean inRead = StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                    frame.getClassName().equals(MatchedElfPrefix.class.getName()) &&
                    frame.getMethodName().equals("readMetadata")));
                if (inRead && metadataPolls.incrementAndGet() == 2) {
                    throw parserCallback;
                }
                return false;
            }, path -> { opens.incrementAndGet(); throw new AssertionError(); })) == parserCallback,
            "supplier failure was relabeled malformed ELF");
        require(metadataPolls.get() == 2 && opens.get() == 0,
            "post-parser callback control did not precede comparison streams");
        byte[] a = Files.readAllBytes(pair.original()), b = Files.readAllBytes(pair.candidate());
        IOException firstOpen = new IOException("first open sentinel");
        AtomicInteger firstAttempts = new AtomicInteger();
        require(expect(IOException.class, () -> MatchedElfPrefix.compare(pair.original(), pair.candidate(), () -> false,
            path -> { firstAttempts.incrementAndGet(); throw firstOpen; })) == firstOpen && firstAttempts.get() == 1,
            "first-open failure identity or open count changed");
        for (int chunk : new int[] { 1, 3, 7, 65536 }) {
            Tracked first = new Tracked(a, chunk), second = new Tracked(b, chunk);
            result(run(pair, first, second, () -> false), Status.MATCHING_COPIED_PREFIX, a.length, OptionalLong.empty());
            require(first.closes == 1 && second.closes == 1 && first.eof, "success leaked streams or skipped EOF");
        }
        IOException secondOpen = new IOException("second open sentinel"), firstClose = new IOException("first close sentinel");
        Tracked first = new Tracked(a, 3);
        first.closeFailure = firstClose;
        IOException openResult = expect(IOException.class, () -> MatchedElfPrefix.compare(pair.original(), pair.candidate(), () -> false,
            path -> { if (path == pair.original()) { return first; } throw secondOpen; }));
        require(openResult == secondOpen && Arrays.equals(openResult.getSuppressed(), new Throwable[] { firstClose })
            && first.closes == 1, "second-open failure did not close first or preserve exceptions");
        for (int checkpoint : new int[] { 1, 2, 3, 4 }) {
            Tracked left = new Tracked(a, 3), right = new Tracked(b, 3);
            AtomicInteger count = new AtomicInteger();
            expect(CancellationException.class, () -> MatchedElfPrefix.compare(pair.original(), pair.candidate(),
                () -> checkpoint <= 2 ? count.get() >= checkpoint : checkpoint == 3 ? left.position > 3 : left.eof,
                path -> { count.incrementAndGet(); return path == pair.original() ? left : right; }));
            require(left.closes == 1 && right.closes == (checkpoint == 1 ? 0 : 1), "cancellation leaked an opened stream");
        }
        for (boolean failRead : new boolean[] { false, true }) {
            Tracked left = new Tracked(a, 7), right = new Tracked(b, 7);
            IOException read = new IOException("read sentinel"), closeLeft = new IOException("close left sentinel"),
                closeRight = new IOException("close right sentinel");
            left.failure = failRead ? read : null;
            left.closeFailure = closeLeft;
            right.closeFailure = closeRight;
            IOException error = expect(IOException.class, () -> run(pair, left, right, () -> false));
            require(left.closes == 1 && right.closes == 1, "read/close failure leaked streams");
            require(failRead ? error == read && Arrays.equals(error.getSuppressed(), new Throwable[] { closeRight, closeLeft })
                : error == closeRight && Arrays.equals(error.getSuppressed(), new Throwable[] { closeLeft }),
                "primary/suppressed failure order changed");
        }
        Tracked cancelledLeft = new Tracked(a, 3), cancelledRight = new Tracked(b, 3);
        IOException cancelLeftClose = new IOException("cancel left close sentinel"),
            cancelRightClose = new IOException("cancel right close sentinel");
        cancelledLeft.closeFailure = cancelLeftClose;
        cancelledRight.closeFailure = cancelRightClose;
        CancellationException cancelled = expect(CancellationException.class,
            () -> run(pair, cancelledLeft, cancelledRight, () -> cancelledLeft.position > 3));
        require(Arrays.equals(cancelled.getSuppressed(), new Throwable[] { cancelRightClose, cancelLeftClose })
            && cancelledLeft.closes == 1 && cancelledRight.closes == 1, "cancel/close exception ownership changed");
        byte[] different = b.clone();
        different[0x245] ^= 1;
        Tracked equalLeft = new Tracked(a, 7), unequalRight = new Tracked(different, 7);
        result(run(pair, equalLeft, unequalRight, () -> false), Status.DIFFERENT_PREFIX, 0x246, OptionalLong.of(0x245));
        require(equalLeft.closes == 1 && unequalRight.closes == 1, "early byte mismatch leaked streams");
        for (int badCount : new int[] { 0, -1, -2, 99999 }) {
            Tracked left = new Tracked(a, 7), right = new Tracked(b, 7);
            right.invalidCount = badCount;
            expect(IOException.class, () -> run(pair, left, right, () -> false));
            require(left.closes == 1 && right.closes == 1, "invalid read leaked streams");
        }
        byte[] replaced = b.clone();
        replaced[pair.wide() ? 54 : 42] = 1; // A masked field cannot change after envelope validation.
        Tracked oldLeft = new Tracked(a, 7), replacedRight = new Tracked(replaced, 7);
        expect(IOException.class, () -> run(pair, oldLeft, replacedRight, () -> false));
        require(oldLeft.closes == 1 && replacedRight.closes == 1, "changed observed header leaked streams");
        Tracked grown = new Tracked(Arrays.copyOf(a, a.length + 1), 7), stable = new Tracked(b, 7);
        expect(IOException.class, () -> run(pair, grown, stable, () -> false));
        require(grown.closes == 1 && stable.closes == 1, "unexpected original tail leaked streams");
        AtomicBoolean ready = new AtomicBoolean();
        RuntimeException failure = new IllegalStateException("supplier sentinel");
        Tracked left = new Tracked(a, 3), right = new Tracked(b, 3);
        require(expect(IllegalStateException.class, () -> MatchedElfPrefix.compare(pair.original(), pair.candidate(),
            () -> { if (ready.get()) { throw failure; } return false; }, path -> {
                if (path == pair.candidate()) { ready.set(true); return right; }
                return left;
            })) == failure && left.closes == 1 && right.closes == 1, "supplier exception/closure changed");
    }

    private static MatchedElfPrefix.Result run(Pair pair, InputStream first, InputStream second,
            java.util.function.BooleanSupplier cancelled) throws IOException {
        return MatchedElfPrefix.compare(pair.original(), pair.candidate(), cancelled, path -> {
            require(path == pair.original() || path == pair.candidate(), "supplied Path was rewritten");
            return path == pair.original() ? first : second;
        });
    }

    private static void large(Path directory) throws Exception {
        long size = 0x8000_0000L + 65537;
        Pair pair = MatchedElfPrefixFixtures.sparse(directory, size);
        result(MatchedElfPrefix.compare(pair.original(), pair.candidate()), Status.MATCHING_COPIED_PREFIX, size, OptionalLong.empty());
        try (FileChannel candidate = FileChannel.open(pair.candidate(), StandardOpenOption.WRITE)) {
            candidate.position(size - 1);
            candidate.write(ByteBuffer.wrap(new byte[] { 78 }));
        }
        result(MatchedElfPrefix.compare(pair.original(), pair.candidate()), Status.DIFFERENT_PREFIX, size, OptionalLong.of(size - 1));
        System.out.println("matched-elf-prefix-large=PASS original-bytes=" + size + " mismatch-offset=" + (size - 1));
    }

    private static void result(MatchedElfPrefix.Result result, Status status, long extent, OptionalLong difference) {
        require(result.status() == status && result.comparedExtent() == extent && result.firstDifferentOffset().equals(difference)
            && result.originalByteCount() >= extent && result.candidateByteCount() >= extent && !result.diagnostic().isBlank(),
            "unexpected observation: " + result);
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }

    private static <T extends Throwable> T expect(Class<T> type, Action action) throws Exception {
        try {
            action.run();
        }
        catch (Throwable failure) {
            if (type.isInstance(failure)) {
                return type.cast(failure);
            }
            throw new AssertionError("expected " + type.getName() + ", got " + failure, failure);
        }
        throw new AssertionError("expected " + type.getName());
    }

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }

    private static final class Tracked extends InputStream {
        private final ByteArrayInputStream input;
        private final int chunk;
        private int position;
        private int closes;
        private boolean eof;
        private Integer invalidCount;
        private IOException failure;
        private IOException closeFailure;

        private Tracked(byte[] bytes, int chunk) {
            input = new ByteArrayInputStream(bytes);
            this.chunk = chunk;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (failure != null) {
                throw failure;
            }
            if (invalidCount != null) {
                return invalidCount;
            }
            int count = input.read(buffer, offset, Math.min(length, chunk));
            eof |= count == -1;
            if (count > 0) {
                position += count;
            }
            return count;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) == -1 ? -1 : one[0] & 255;
        }

        @Override
        public void close() throws IOException {
            closes++;
            if (closeFailure != null) {
                throw closeFailure;
            }
            input.close();
        }
    }
}
