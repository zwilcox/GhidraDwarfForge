package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.elf.ExecutableProgramBytes.Region;
import ghidradwarfforge.elf.ExecutableProgramBytes.Result;
import ghidradwarfforge.elf.ExecutableProgramBytes.Status;
import ghidradwarfforge.elf.ExecutableProgramBytesFixtures.Pair;
import ghidradwarfforge.elf.ExecutableProgramBytesFixtures.Shape;

/** Native-free controlled ELF metadata/bytes and scoped-channel ownership checks. */
public final class ExecutableProgramBytesSmoke {
    private static int checks;

    private ExecutableProgramBytesSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-program-bytes-").toRealPath();
        try {
            for (boolean wide : List.of(false, true)) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    Path directory = root.resolve((wide ? "64" : "32") + "-" + order);
                    for (Shape shape : Shape.values()) {
                        Pair pair = ExecutableProgramBytesFixtures.create(directory.resolve(shape.name()),
                            wide, order, shape);
                        basic(pair, shape);
                    }
                    Pair pair = ExecutableProgramBytesFixtures.create(directory.resolve("controls"),
                        wide, order, Shape.NORMAL);
                    differences(pair);
                    permittedAndExcluded(pair);
                    headerCoveringLoad(pair);
                    rereadChanges(pair);
                }
            }
            Pair pair = ExecutableProgramBytesFixtures.create(root.resolve("resources"), true,
                ByteOrder.LITTLE_ENDIAN, Shape.NORMAL);
            resources(pair);
            paths(pair);
            if (args.length == 1 && args[0].equals("--large")) {
                for (boolean wide : List.of(false, true)) {
                    for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                        large(root.resolve("large-" + wide + "-" + order), wide, order);
                    }
                }
            }
            else if (args.length != 0) {
                throw new IllegalArgumentException("only optional --large is supported");
            }
            System.out.println("executable-program-bytes-smoke=PASS checks=" + checks);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
    }

    private static void basic(Pair pair, Shape shape) throws Exception {
        Snapshot before = snapshot(pair);
        Status expected = switch (shape) {
            case NORMAL, EXTENDED_PROGRAMS, EXTENDED_SECTIONS -> Status.MATCHING_PROGRAM_BYTES;
            default -> Status.NO_FILE_BACKED_LOAD_EVIDENCE;
        };
        Result result = compare(pair);
        require(result.status() == expected && result.issue().isEmpty(), "wrong basic outcome " + shape);
        require(result.equals(compare(pair)), "repeated observation changed");
        require(ExecutableProgramBytes.compare(pair.original(), pair.original()).status() == expected,
            "same-file byte relationship was confused with identity or attachment");
        unchanged(pair, before);

        if (shape == Shape.EXTENDED_PROGRAMS) {
            // Identical encoded PN_XNUM fields, resolved counts at different SHT offsets.
            byte[] changed = before.candidate().clone();
            ByteBuffer data = ByteBuffer.wrap(changed).order(pair.order());
            data.putInt(pair.candidateSections() + pair.sectionInfo(), pair.programCount() + 1);
            Files.write(pair.candidate(), changed);
            Result count = compare(pair);
            require(count.status() == Status.DIFFERENT_PROGRAM_BYTES &&
                count.issue().orElseThrow().region() == Region.PROGRAM_COUNT &&
                count.issue().orElseThrow().offset().isEmpty() &&
                count.issue().orElseThrow().expected().equals(Integer.toString(pair.programCount())) &&
                count.issue().orElseThrow().observed().equals(Integer.toString(pair.programCount() + 1)),
                "resolved PN_XNUM difference invented a common offset");
            Files.write(pair.candidate(), before.candidate());
            // Phase order is explicit, even when a payload has a lower physical offset.
            changed = before.candidate().clone();
            int physical = pair.program(0) + (pair.wide() ? 24 : 12);
            changed[physical] ^= 1;
            changed[0x800] ^= 1;
            Files.write(pair.candidate(), changed);
            difference(compare(pair), Region.PROGRAM_TABLE, physical);
            Files.write(pair.candidate(), before.candidate());
        }
        if (expected == Status.NO_FILE_BACKED_LOAD_EVIDENCE) {
            byte[] changed = before.candidate().clone();
            changed[8] ^= 1;
            Files.write(pair.candidate(), changed);
            difference(compare(pair), Region.ELF_HEADER, 8);
            Files.write(pair.candidate(), before.candidate());
            if (shape == Shape.MEMORY_ONLY || shape == Shape.NOTE_ONLY) {
                changed = before.candidate().clone();
                changed[0x800] ^= 1;
                Files.write(pair.candidate(), changed);
                difference(compare(pair), Region.PROGRAM_PAYLOAD, 0x800);
                Files.write(pair.candidate(), before.candidate());
            }
        }
    }

    private static void differences(Pair pair) throws Exception {
        byte[] original = Files.readAllBytes(pair.candidate());
        int fixed = pair.wide() ? 64 : 52;
        // Raw header fields, immediate post-mask boundary, and declared extension tail.
        for (int offset : new int[] { 7, 8, 15, 18, 24, pair.wide() ? 48 : 36,
                fixed, pair.headerSize() - 1 }) {
            flip(pair, original, offset);
            difference(compare(pair), Region.ELF_HEADER, offset);
        }
        int first = pair.program(0);
        for (int offset : new int[] { first + (pair.wide() ? 24 : 12),
                first + (pair.wide() ? 56 : 32), pair.program(3) + 4,
                pair.program(3) + pair.entrySize() - 1 }) {
            flip(pair, original, offset);
            difference(compare(pair), Region.PROGRAM_TABLE, offset);
        }
        for (int offset : new int[] { 0x800, 0x81f, 0x1000, 0x1080, 0x1100, 0x111f }) {
            flip(pair, original, offset);
            difference(compare(pair), Region.PROGRAM_PAYLOAD, offset);
        }
        Files.write(pair.candidate(), original);
        // A valid relocated PHDR table is a forbidden executable-header change.
        int tableSize = pair.entrySize() * pair.programCount();
        int newTable = original.length + 32;
        byte[] moved = Arrays.copyOf(original, newTable + tableSize);
        System.arraycopy(original, pair.programOffset(), moved, newTable, tableSize);
        ExecutableProgramBytesFixtures.putWord(ByteBuffer.wrap(moved).order(pair.order()),
            pair.wide() ? 32 : 28, newTable, pair.wide());
        Files.write(pair.candidate(), moved);
        long firstChanged = firstDifferent(original, moved, pair.wide() ? 32 : 28, pair.wide() ? 8 : 4);
        difference(compare(pair), Region.ELF_HEADER, firstChanged);
        Files.write(pair.candidate(), original);
        // A valid changed plan is compared, not rejected as a concurrent rewrite.
        byte[] changed = original.clone();
        int field = first + (pair.wide() ? 8 : 4);
        ExecutableProgramBytesFixtures.putWord(ByteBuffer.wrap(changed).order(pair.order()),
            field, 0x1200, pair.wide());
        Files.write(pair.candidate(), changed);
        difference(compare(pair), Region.PROGRAM_TABLE,
            firstDifferent(original, changed, field, pair.wide() ? 8 : 4));
        Files.write(pair.candidate(), original);
    }

    private static void permittedAndExcluded(Pair pair) throws Exception {
        byte[] original = Files.readAllBytes(pair.candidate());
        // All four SHT fields have structural meaning: rebuild a valid wider table.
        int oldEntry = pair.sectionSize();
        int newEntry = oldEntry + 8;
        int table = original.length + 32;
        byte[] rebuilt = Arrays.copyOf(original, table + 5 * newEntry);
        for (int index = 0; index < 5; index++) {
            System.arraycopy(original, pair.candidateSections() + index * oldEntry,
                rebuilt, table + index * newEntry, oldEntry);
        }
        ByteBuffer data = ByteBuffer.wrap(rebuilt).order(pair.order());
        ExecutableProgramBytesFixtures.putWord(data, pair.wide() ? 40 : 32, table, pair.wide());
        data.putShort(pair.wide() ? 58 : 46, (short) newEntry);
        Files.write(pair.candidate(), rebuilt);
        require(compare(pair).status() == Status.MATCHING_PROGRAM_BYTES,
            "valid section-table changes were not exempt");
        // Exempting bytes does not permit invalid structural metadata.
        data.putShort(pair.wide() ? 58 : 46, (short) 1);
        Files.write(pair.candidate(), rebuilt);
        Tracking noOpen = new Tracking();
        IOException invalid = expect(IOException.class, () -> compare(pair, () -> false, noOpen));
        require(invalid.getCause() instanceof IllegalArgumentException && noOpen.opened.isEmpty(),
            "malformed SHT reached comparison or lost parser cause");

        for (int offset : new int[] { pair.candidateSections() + pair.sectionSize() +
                (pair.wide() ? 16 : 12), 0x180f, 0x1500 }) {
            flip(pair, original, offset);
            require(compare(pair).status() == Status.MATCHING_PROGRAM_BYTES,
                "active SHT, CRC or unreferenced tail was mistakenly part of byte proof");
        }
        Files.write(pair.candidate(), original);
        // Mask boundary before e_shoff: a changed phoff must not be silently masked.
        byte[] bad = original.clone();
        bad[(pair.wide() ? 40 : 32) - 1] ^= 0x40;
        Files.write(pair.candidate(), bad);
        if (pair.wide() && pair.order() == ByteOrder.BIG_ENDIAN) {
            // The low byte moves by exactly this fixture's 64-byte entry stride.
            // The shifted table still parses, so the header difference surfaces.
            difference(compare(pair), Region.ELF_HEADER, (pair.wide() ? 40 : 32) - 1);
        }
        else {
            expect(IOException.class, () -> compare(pair));
        }
        Files.write(pair.candidate(), original);
        // A normal encoded count change precedes any table/body evidence.
        bad = original.clone();
        ByteBuffer.wrap(bad).order(pair.order()).putShort(pair.wide() ? 56 : 44, (short) 3);
        Files.write(pair.candidate(), bad);
        difference(compare(pair), Region.ELF_HEADER,
            firstDifferent(original, bad, pair.wide() ? 56 : 44, 2));
        Files.write(pair.candidate(), original);
    }

    private static void rereadChanges(Pair pair) throws Exception {
        Snapshot saved = snapshot(pair);
        for (boolean header : List.of(false, true)) {
            Tracking access = new Tracking();
            access.beforeFirstOpen = () -> {
                for (Path path : List.of(pair.original(), pair.candidate())) {
                    byte[] bytes = Files.readAllBytes(path);
                    FileTime time = Files.getLastModifiedTime(path);
                    if (header) {
                        bytes[pair.wide() ? 40 : 32] ^= 1;
                    }
                    else {
                        ExecutableProgramBytesFixtures.putWord(ByteBuffer.wrap(bytes).order(pair.order()),
                            pair.program(0) + (pair.wide() ? 8 : 4), 0x1200, pair.wide());
                    }
                    Files.write(path, bytes);
                    Files.setLastModifiedTime(path, time);
                    require(Files.size(path) == bytes.length && Files.getLastModifiedTime(path).equals(time),
                        "controlled rewrite did not restore size/mtime");
                }
            };
            try {
                IOException failure = expect(IOException.class, () -> compare(pair, () -> false, access));
                require(failure.getMessage().equals(header ? "ELF header changed after metadata observation"
                    : "program fields changed after metadata observation"),
                    "rewrite was not rejected by raw metadata/plan reconciliation");
                require(access.opened.size() == 2, "rewrite did not reach both comparison channels");
                access.closedExactly();
            }
            finally {
                restore(pair, saved);
            }
            require(compare(pair).status() == Status.MATCHING_PROGRAM_BYTES, "restored pair no longer matches");
            unchanged(pair, saved);
        }
    }

    private static void headerCoveringLoad(Pair pair) throws Exception {
        Snapshot saved = snapshot(pair);
        try {
            for (Path path : List.of(pair.original(), pair.candidate())) {
                byte[] bytes = Files.readAllBytes(path);
                ExecutableProgramBytesFixtures.program(ByteBuffer.wrap(bytes).order(pair.order()),
                    pair.program(0), pair.wide(), 1, 5, 0, 0x400000, 0x1200, 0x1200);
                Files.write(path, bytes);
            }
            require(compare(pair).status() == Status.MATCHING_PROGRAM_BYTES,
                "header-covering LOAD rechecked permitted SHT edits as payload differences");
            byte[] candidate = Files.readAllBytes(pair.candidate());
            for (int offset : new int[] { pair.headerSize(),
                    pair.programOffset() + pair.programCount() * pair.entrySize() }) {
                flip(pair, candidate, offset);
                difference(compare(pair), Region.PROGRAM_PAYLOAD, offset);
            }
        }
        finally {
            restore(pair, saved);
        }
        unchanged(pair, saved);
    }

    private static void resources(Pair pair) throws Exception {
        Snapshot saved = snapshot(pair);
        for (int channel : new int[] { 0, 1 }) {
            for (String point : List.of("open", "read", "position", "size", "close", "zero")) {
                Tracking access = new Tracking();
                access.failChannel = channel;
                access.failPoint = point;
                IOException failure = expect(IOException.class, () -> compare(pair, () -> false, access));
                require(point.equals("zero") || failure == access.failure, "primary I/O exception was replaced");
                access.closedExactly();
                if (point.equals("open")) {
                    require(access.opened.size() == channel, "unexpected channels opened after open failure");
                }
            }
        }
        Tracking combined = new Tracking();
        combined.failChannel = 0;
        combined.failPoint = "read";
        combined.failCloses = true;
        IOException failed = expect(IOException.class, () -> compare(pair, () -> false, combined));
        require(failed == combined.failure && Arrays.equals(failed.getSuppressed(),
            new Throwable[] { combined.closeErrors[1], combined.closeErrors[0] }),
            "ordered suppressed close exceptions changed");
        combined.closedExactly();

        Tracking before = new Tracking();
        expect(CancellationException.class, () -> compare(pair, () -> true, before));
        require(before.opened.isEmpty(), "cancel before metadata opened a comparison channel");
        for (String point : List.of("first-open", "first-read", "table", "payload", "closed")) {
            Tracking access = new Tracking();
            BooleanSupplier cancelled = () -> switch (point) {
                case "first-open" -> access.opened.size() == 1;
                case "first-read" -> !access.opened.isEmpty() && access.opened.get(0).reads > 0;
                case "table" -> access.opened.size() == 2 && access.opened.get(1).lastPosition == pair.programOffset();
                case "payload" -> access.opened.size() == 2 && access.opened.get(1).lastPosition == 0x800;
                case "closed" -> access.opened.size() == 2 && access.opened.get(0).closes > 0;
                default -> throw new AssertionError();
            };
            expect(CancellationException.class, () -> compare(pair, cancelled, access));
            access.closedExactly();
        }
        Tracking callback = new Tracking();
        IllegalStateException callbackError = new IllegalStateException("supplier failure");
        require(expect(IllegalStateException.class, () -> compare(pair, () -> {
            if (callback.opened.size() == 2 && callback.opened.get(0).reads > 0) {
                throw callbackError;
            }
            return false;
        }, callback)) == callbackError, "supplier exception was replaced");
        callback.closedExactly();
        Tracking cancelClose = new Tracking();
        cancelClose.failCloses = true;
        CancellationException cancelled = expect(CancellationException.class,
            () -> compare(pair, () -> cancelClose.opened.size() == 2 &&
                cancelClose.opened.get(0).reads > 0, cancelClose));
        require(Arrays.equals(cancelled.getSuppressed(),
            new Throwable[] { cancelClose.closeErrors[1], cancelClose.closeErrors[0] }),
            "cancellation lost close failures");
        cancelClose.closedExactly();

        byte[] bad = saved.candidate().clone();
        bad[0] = 0;
        Files.write(pair.candidate(), bad);
        Tracking malformed = new Tracking();
        IOException invalid = expect(IOException.class, () -> compare(pair, () -> false, malformed));
        require(invalid.getCause() instanceof IllegalArgumentException && malformed.opened.isEmpty(),
            "malformed second input was hidden by a comparison outcome");
        restore(pair, saved);
        unchanged(pair, saved);
    }

    private static void paths(Pair pair) throws Exception {
        Path root = pair.original().getParent();
        Path logical = Files.createDirectory(root.resolve("logical"));
        Path actual = Files.createDirectory(root.resolve("actual"));
        Path child = Files.createDirectory(actual.resolve("child"));
        Files.createSymbolicLink(logical.resolve("link"), child);
        Files.copy(pair.original(), actual.resolve("input"));
        Files.copy(pair.original(), logical.resolve("input"));
        Path traversed = logical.resolve("link").resolve("..").resolve("input");
        require(ExecutableProgramBytes.compare(traversed, pair.candidate()).status() == Status.MATCHING_PROGRAM_BYTES,
            "actual path traversal failed");
        Path selected = traversed.toRealPath();
        Path other = Files.isSameFile(selected, actual.resolve("input")) ? logical.resolve("input") : actual.resolve("input");
        byte[] altered = Files.readAllBytes(other);
        altered[0x800] ^= 1;
        Files.write(other, altered);
        require(ExecutableProgramBytes.compare(traversed, pair.candidate()).status() == Status.MATCHING_PROGRAM_BYTES,
            "lexical normalization selected the wrong file");
        Path link = root.resolve("candidate-link");
        Files.createSymbolicLink(link, pair.candidate());
        require(ExecutableProgramBytes.compare(pair.original(), link).status() == Status.MATCHING_PROGRAM_BYTES &&
            Files.isSymbolicLink(link), "read-only selected leaf link changed");
        Path hard = root.resolve("hardlink");
        Files.createLink(hard, pair.original());
        require(Files.isSameFile(hard, pair.original()) &&
            ExecutableProgramBytes.compare(pair.original(), hard).status() == Status.MATCHING_PROGRAM_BYTES,
            "known read-only alias was mistaken for attachment permission");
        expect(IOException.class, () -> ExecutableProgramBytes.compare(root, pair.candidate()));
        expect(IOException.class, () -> ExecutableProgramBytes.compare(pair.original(), root));
        if (java.io.File.separatorChar != '\\') {
            Path fifo = root.resolve("fifo");
            Process process = new ProcessBuilder("mkfifo", fifo.toString()).start();
            require(process.waitFor() == 0, "FIFO creation failed");
            expect(IOException.class, () -> ExecutableProgramBytes.compare(fifo, pair.candidate()));
            expect(IOException.class, () -> ExecutableProgramBytes.compare(pair.original(), fifo));
            Files.delete(fifo);
        }
    }

    private static void large(Path root, boolean wide, ByteOrder order) throws Exception {
        Pair pair = ExecutableProgramBytesFixtures.create(root, wide, order, Shape.NORMAL);
        long start = (1L << 31) + 4096;
        long size = start + 65537;
        for (Path path : List.of(pair.original(), pair.candidate())) {
            byte[] bytes = Files.readAllBytes(path);
            ByteBuffer data = ByteBuffer.wrap(bytes).order(pair.order());
            ExecutableProgramBytesFixtures.program(data, pair.program(0), wide, 1, 5,
                start, 0x401000, 65537, 65537);
            Files.write(path, bytes);
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
                channel.write(ByteBuffer.wrap(new byte[] { 0x67 }), size - 1);
            }
        }
        FileTime originalTime = Files.getLastModifiedTime(pair.original());
        FileTime candidateTime = Files.getLastModifiedTime(pair.candidate());
        require(compare(pair).status() == Status.MATCHING_PROGRAM_BYTES, "large high-offset payload did not match");
        require(Files.size(pair.original()) == size && Files.size(pair.candidate()) == size &&
            Files.getLastModifiedTime(pair.original()).equals(originalTime) &&
            Files.getLastModifiedTime(pair.candidate()).equals(candidateTime), "large inputs changed");
        try (FileChannel channel = FileChannel.open(pair.candidate(), StandardOpenOption.WRITE)) {
            channel.write(ByteBuffer.wrap(new byte[] { 0x66 }), size - 1);
        }
        difference(compare(pair), Region.PROGRAM_PAYLOAD, size - 1);
        System.out.println("large-program-file-bytes=" + size + " mismatch-offset=" + (size - 1) +
            " class=" + (wide ? 64 : 32) + " order=" + order);
    }

    private static Result compare(Pair pair) throws IOException {
        return ExecutableProgramBytes.compare(pair.original(), pair.candidate());
    }

    private static Result compare(Pair pair, BooleanSupplier cancelled, Tracking access) throws IOException {
        return ExecutableProgramBytes.compare(pair.original(), pair.candidate(), cancelled, access);
    }

    private static void difference(Result result, Region region, long offset) {
        require(result.status() == Status.DIFFERENT_PROGRAM_BYTES && result.issue().isPresent() &&
            result.issue().get().region() == region && result.issue().get().offset().isPresent() &&
            result.issue().get().offset().getAsLong() == offset &&
            !result.issue().get().expected().equals(result.issue().get().observed()),
            "wrong mismatch context/offset: " + result + " expected=" + region + ":" + offset);
    }

    private static void flip(Pair pair, byte[] baseline, int offset) throws Exception {
        byte[] changed = baseline.clone();
        changed[offset] ^= 1;
        Files.write(pair.candidate(), changed);
    }

    private static long firstDifferent(byte[] before, byte[] after, int start, int size) {
        for (int index = start; index < start + size; index++) {
            if (before[index] != after[index]) {
                return index;
            }
        }
        throw new AssertionError("controlled field did not change");
    }

    private record Snapshot(byte[] original, byte[] candidate, FileTime originalTime, FileTime candidateTime) {
    }

    private static Snapshot snapshot(Pair pair) throws Exception {
        return new Snapshot(Files.readAllBytes(pair.original()), Files.readAllBytes(pair.candidate()),
            Files.getLastModifiedTime(pair.original()), Files.getLastModifiedTime(pair.candidate()));
    }

    private static void restore(Pair pair, Snapshot snapshot) throws Exception {
        Files.write(pair.original(), snapshot.original());
        Files.write(pair.candidate(), snapshot.candidate());
        Files.setLastModifiedTime(pair.original(), snapshot.originalTime());
        Files.setLastModifiedTime(pair.candidate(), snapshot.candidateTime());
    }

    private static void unchanged(Pair pair, Snapshot saved) throws Exception {
        require(Arrays.equals(Files.readAllBytes(pair.original()), saved.original()) &&
            Arrays.equals(Files.readAllBytes(pair.candidate()), saved.candidate()) &&
            Files.getLastModifiedTime(pair.original()).equals(saved.originalTime()) &&
            Files.getLastModifiedTime(pair.candidate()).equals(saved.candidateTime()), "inputs changed");
    }

    private static final class Tracking implements ExecutableProgramBytes.ChannelOpener {
        final List<Tracked> opened = new ArrayList<>();
        final IOException failure = new IOException("injected channel failure");
        final IOException[] closeErrors = { new IOException("first close"), new IOException("second close") };
        int failChannel = -1;
        String failPoint;
        boolean failCloses;
        Checked beforeFirstOpen;

        @Override
        public SeekableByteChannel open(Path path) throws IOException {
            if (opened.isEmpty() && beforeFirstOpen != null) {
                try {
                    beforeFirstOpen.run();
                }
                catch (IOException failure) {
                    throw failure;
                }
                catch (Exception failure) {
                    throw new IOException("controlled mutation failed", failure);
                }
            }
            int index = opened.size();
            if (index == failChannel && "open".equals(failPoint)) {
                throw failure;
            }
            Tracked channel = new Tracked(FileChannel.open(path, StandardOpenOption.READ), this, index);
            opened.add(channel);
            return channel;
        }

        void closedExactly() {
            for (Tracked channel : opened) {
                require(channel.closes == 1 && !channel.delegate.isOpen(), "comparison channel leaked");
            }
        }
    }

    private static final class Tracked implements SeekableByteChannel {
        final SeekableByteChannel delegate;
        final Tracking access;
        final int index;
        int closes;
        int reads;
        long lastPosition = -1;

        Tracked(SeekableByteChannel delegate, Tracking access, int index) {
            this.delegate = delegate;
            this.access = access;
            this.index = index;
        }

        private void fail(String point) throws IOException {
            if (index == access.failChannel && point.equals(access.failPoint)) {
                throw access.failure;
            }
        }

        @Override public int read(ByteBuffer buffer) throws IOException {
            reads++;
            fail("read");
            if (index == access.failChannel && "zero".equals(access.failPoint)) {
                return 0;
            }
            return delegate.read(buffer);
        }
        @Override public SeekableByteChannel position(long value) throws IOException {
            fail("position");
            lastPosition = value;
            delegate.position(value);
            return this;
        }
        @Override public long position() throws IOException { return delegate.position(); }
        @Override public long size() throws IOException { fail("size"); return delegate.size(); }
        @Override public boolean isOpen() { return delegate.isOpen(); }
        @Override public int write(ByteBuffer input) { throw new UnsupportedOperationException(); }
        @Override public SeekableByteChannel truncate(long value) { throw new UnsupportedOperationException(); }
        @Override public void close() throws IOException {
            closes++;
            delegate.close();
            if (access.failCloses) {
                throw access.closeErrors[index];
            }
            fail("close");
        }
    }

    @FunctionalInterface
    private interface Checked { void run() throws Exception; }

    private static <T extends Throwable> T expect(Class<T> type, Checked action) throws Exception {
        try {
            action.run();
        }
        catch (Throwable failure) {
            require(type.isInstance(failure), "unexpected failure: " + failure);
            return type.cast(failure);
        }
        throw new AssertionError("expected " + type.getName());
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
