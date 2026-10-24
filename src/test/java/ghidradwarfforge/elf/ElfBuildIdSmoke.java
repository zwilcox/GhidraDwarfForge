package ghidradwarfforge.elf;

import static ghidradwarfforge.elf.ElfBuildIdFixtures.View.section;
import static ghidradwarfforge.elf.ElfBuildIdFixtures.View.segment;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Native-free, independently constructed note containers and malformed controls. */
public final class ElfBuildIdSmoke {
    private static final byte[] GNU = { 'G', 'N', 'U', 0 };
    private static final byte[] ID = { 1, 2, 3, 4, 5 };
    private static final ByteOrder LE = ByteOrder.LITTLE_ENDIAN;

    private ElfBuildIdSmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        Path directory = Files.createTempDirectory("forge-build-id-");
        try {
            Path file = directory.resolve("fixture.elf");
            for (boolean elf64 : new boolean[] { false, true }) {
                for (ByteOrder order : List.of(LE, ByteOrder.BIG_ENDIAN)) {
                    for (int alignment : new int[] { 4, 8 }) {
                        checkViews(file, elf64, order, alignment);
                        checkMalformed(file, elf64, order, alignment);
                    }
                    checkExtended(file, elf64, order);
                    checkSparse(file, elf64, order);
                }
            }
            checkOverlap(file);
            checkAlternateFormat(file);
            checkLimits(file);
            checkCancellation(file);
            checkChangedSource(file);
            checkRelationships(file);
        }
        finally {
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
        System.out.println("elf-build-id-smoke=PASS");
    }

    private static void checkViews(Path path, boolean elf64, ByteOrder order, int alignment)
            throws Exception {
        byte[] unrelated = ElfBuildIdFixtures.note(order, alignment,
            new byte[] { 'A', 'B', 'C', 'D', 0 }, 77, new byte[] { 7, 8, 9 });
        byte[] id = ElfBuildIdFixtures.note(order, alignment, GNU, 3, ID);
        byte[] payload = ElfBuildIdFixtures.join(unrelated, id);
        for (boolean names : new boolean[] { true, false }) {
            var fixture = fixture(path, elf64, order, payload,
                List.of(section(0, payload.length, alignment)),
                List.of(segment(unrelated.length, id.length, alignment)), names);
            byte[] before = Files.readAllBytes(path);
            var time = Files.getLastModifiedTime(path);
            ElfBuildId.Observation result = ElfBuildId.read(path);
            require(result.hex().equals(Optional.of("0102030405")), "wrong GNU descriptor");
            require(result.occurrences().size() == 1, "duplicate views not deduplicated");
            var occurrence = result.occurrences().get(0);
            require(occurrence.noteOffset() == fixture.dataOffset() + unrelated.length &&
                occurrence.descriptorOffset() == occurrence.noteOffset() + 16 &&
                occurrence.descriptorSize() == ID.length, "wrong physical offsets");
            require(occurrence.containers().size() == 2 &&
                occurrence.containers().get(0).kind() == ElfBuildId.ContainerKind.SECTION &&
                occurrence.containers().get(0).index() == 1 &&
                occurrence.containers().get(1).kind() == ElfBuildId.ContainerKind.SEGMENT &&
                occurrence.containers().get(1).index() == 0, "lost view provenance");
            expect(UnsupportedOperationException.class, () -> result.occurrences().clear());
            expect(UnsupportedOperationException.class, () -> occurrence.containers().clear());
            require(result.equals(ElfBuildId.read(path)), "nondeterministic observation");
            require(Arrays.equals(before, Files.readAllBytes(path)) &&
                time.equals(Files.getLastModifiedTime(path)), "input changed");
        }
        fixture(path, elf64, order, id, List.of(), List.of(segment(0, id.length, alignment)), false);
        require(ElfImage.read(path).sections().isEmpty(), "sectionless test has sections");
        require(ElfBuildId.read(path).hex().orElseThrow().equals("0102030405"), "PT_NOTE lost");

        byte[] twice = ElfBuildIdFixtures.join(id, id);
        fixture(path, elf64, order, twice, List.of(section(0, twice.length, alignment)), List.of(), true);
        require(ElfBuildId.read(path).occurrences().size() == 2, "distinct equal records collapsed");

        // Type and exact owner determine recognition, never the section name.
        byte[] ignored = ElfBuildIdFixtures.join(
            ElfBuildIdFixtures.note(order, alignment, GNU, 2, ID),
            ElfBuildIdFixtures.note(order, alignment, new byte[] { 'G', 'N', 'U', 'x', 0 }, 3, ID));
        fixture(path, elf64, order, ignored, List.of(section(0, ignored.length, alignment)), List.of(), true);
        require(ElfBuildId.read(path).hex().isEmpty(), "owner prefix/type guessed an ID");
        fixture(path, elf64, order, id,
            List.of(new ElfBuildIdFixtures.View(0, id.length, alignment, 1, 0)), List.of(), true);
        require(ElfBuildId.read(path).hex().isEmpty(), "untyped bytes treated as notes");
        fixture(path, elf64, order, new byte[0], List.of(section(0, 0, alignment)), List.of(), false);
        require(ElfBuildId.read(path).hex().isEmpty(), "empty notes not absent");
        if (alignment == 4) {
            for (long declared : new long[] { 0, 1, 2, 3 }) {
                fixture(path, elf64, order, id, List.of(section(0, id.length, declared)), List.of(), false);
                require(ElfBuildId.read(path).hex().isPresent(), "sub-four alignment not promoted");
            }
        }
    }

    private static void checkMalformed(Path path, boolean elf64, ByteOrder order, int alignment)
            throws Exception {
        byte[] id = ElfBuildIdFixtures.note(order, alignment, GNU, 3, ID);
        fixture(path, elf64, order, id, List.of(section(0, id.length - 1, alignment)), List.of(), false);
        rejectUnchanged(path);
        byte[] trailing = Arrays.copyOf(id, id.length + 1);
        fixture(path, elf64, order, trailing, List.of(section(0, trailing.length, alignment)), List.of(), false);
        rejectUnchanged(path);
        for (long badAlignment : new long[] { 5, 16, 0x1000 }) {
            fixture(path, elf64, order, id, List.of(section(0, id.length, badAlignment)), List.of(), false);
            rejectUnchanged(path);
        }
        fixture(path, elf64, order, id,
            List.of(new ElfBuildIdFixtures.View(0, id.length, alignment, 7, 0x800)), List.of(), false);
        rejectUnchanged(path);
        byte[] emptyId = ElfBuildIdFixtures.note(order, alignment, GNU, 3, new byte[0]);
        fixture(path, elf64, order, emptyId, List.of(section(0, emptyId.length, alignment)), List.of(), false);
        rejectUnchanged(path);
        byte[] owner = ElfBuildIdFixtures.note(order, alignment, new byte[] { 'G', 'N', 'U', 'x' }, 3, ID);
        fixture(path, elf64, order, owner, List.of(section(0, owner.length, alignment)), List.of(), false);
        rejectUnchanged(path);
        byte[] conflict = ElfBuildIdFixtures.join(id,
            ElfBuildIdFixtures.note(order, alignment, GNU, 3, new byte[] { 9 }));
        fixture(path, elf64, order, conflict, List.of(section(0, conflict.length, alignment)), List.of(), false);
        rejectUnchanged(path);
        for (int field : new int[] { 0, 4 }) {
            var fixture = fixture(path, elf64, order, id,
                List.of(section(0, id.length, alignment)), List.of(), false);
            fixture.patch(fixture.dataOffset() + field, 4, 0xffffffffL);
            rejectUnchanged(path);
        }
        // A good section must not hide a truncated or otherwise bad segment view.
        fixture(path, elf64, order, id, List.of(section(0, id.length, alignment)),
            List.of(segment(0, id.length - 1, alignment)), false);
        rejectUnchanged(path);
        fixture(path, elf64, order, id, List.of(section(0, id.length, alignment)),
            List.of(segment(4, id.length - 4, alignment)), false);
        rejectUnchanged(path);
        var fixture = fixture(path, elf64, order, id,
            List.of(section(0, id.length, alignment)), List.of(), false);
        fixture.patch(fixture.section(1) + (elf64 ? 24 : 16), elf64 ? 8 : 4, Files.size(path));
        rejectUnchanged(path);
        if (elf64) {
            fixture = fixture(path, true, order, id,
                List.of(section(0, id.length, alignment)), List.of(), false);
            fixture.patch(fixture.section(1) + 24, 8, Long.MAX_VALUE - 4);
            rejectUnchanged(path);
        }
    }

    private static void checkOverlap(Path path) throws Exception {
        byte[] id = ElfBuildIdFixtures.note(LE, 8, GNU, 3, new byte[20]);
        fixture(path, true, LE, id, List.of(section(0, 36, 4)), List.of(segment(0, 40, 8)), false);
        var result = ElfBuildId.read(path);
        require(result.occurrences().size() == 1 && result.occurrences().get(0).containers().size() == 2,
            "complete mixed-padding views not deduplicated");
        fixture(path, true, LE, id, List.of(section(0, 40, 8)), List.of(segment(0, 36, 4)), false);
        require(ElfBuildId.read(path).occurrences().size() == 1, "mixed-padding view order mattered");

        // Each view alone is a valid note stream, but their record interpretations conflict.
        byte[] overlap = new byte[32];
        fixture(path, true, LE, overlap, List.of(section(0, 24, 4)), List.of(segment(4, 24, 4)), false);
        rejectUnchanged(path);
        // Same header, incompatible descriptor start under align4 versus align8.
        byte[] differentStart = ElfBuildIdFixtures.note(LE, 8,
            new byte[] { 'A', 'B', 'C', 'D', 0 }, 77, new byte[4]);
        fixture(path, true, LE, differentStart, List.of(section(0, 24, 4)),
            List.of(segment(0, 32, 8)), false);
        rejectUnchanged(path);
    }

    private static void checkExtended(Path path, boolean elf64, ByteOrder order) throws Exception {
        byte[] id = ElfBuildIdFixtures.note(order, 4, GNU, 3, ID);
        var fixture = ElfBuildIdFixtures.create(path, elf64, order, id,
            List.of(section(0, id.length, 4)), List.of(segment(0, id.length, 4)), true, true, true, 0);
        byte[] hash = hash(path);
        ElfImage image = ElfImage.read(path);
        require(image.sections().size() == 0xff01 && image.sectionNameIndex() == 0xff00 &&
            image.segments().size() == 0xffff, "extended counts test is not canonical");
        var result = ElfBuildId.read(path);
        require(result.hex().orElseThrow().equals("0102030405") &&
            result.occurrences().get(0).containers().get(1).index() == 0xfffe,
            "late PN_XNUM note missing");
        require(Arrays.equals(hash, hash(path)), "extended input changed");
        // PN_XNUM's mandatory section zero is not a note or a string table.
        fixture = ElfBuildIdFixtures.create(path, elf64, order, id, List.of(),
            List.of(segment(0, id.length, 4)), false, false, true, 0);
        require(ElfImage.read(path).sections().size() == 1 && ElfBuildId.read(path).hex().isPresent(),
            "section-zero-only PN_XNUM failed");
    }

    private static void checkAlternateFormat(Path path) throws Exception {
        // GNU's VMS variant uses three eight-byte fields and 8-byte name/desc
        // alignment. The generic12-byte interpretation must not quietly return absent.
        for (ByteOrder order : List.of(LE, ByteOrder.BIG_ENDIAN)) {
            byte[] note = ByteBuffer.allocate(64).order(order).putLong(4).putLong(32)
                .putLong(3).put(GNU).array();
            var fixture = fixture(path, true, order, note,
                List.of(section(0, note.length, 8)), List.of(segment(0, note.length, 8)), false);
            fixture.patch(18, 2, 50);
            fixture.patch(7, 1, 13);
            rejectUnchanged(path);

            // The discriminator is the pair, not either machine or OSABI alone.
            byte[] generic = ElfBuildIdFixtures.note(order, 4, GNU, 3, ID);
            fixture = fixture(path, true, order, generic,
                List.of(section(0, generic.length, 4)), List.of(), false);
            fixture.patch(18, 2, 50);
            require(ElfBuildId.read(path).hex().isPresent(), "machine alone rejected generic notes");
            fixture.patch(18, 2, 62);
            fixture.patch(7, 1, 13);
            require(ElfBuildId.read(path).hex().isPresent(), "OSABI alone rejected generic notes");

            fixture = fixture(path, true, order, new byte[0], List.of(), List.of(), false);
            fixture.patch(18, 2, 50);
            fixture.patch(7, 1, 13);
            require(ElfBuildId.read(path).hex().isEmpty(), "note-free input invented a format failure");
        }
    }

    private static void checkSparse(Path path, boolean elf64, ByteOrder order) throws Exception {
        byte[] id = ElfBuildIdFixtures.note(order, 8, GNU, 3, ID);
        var fixture = ElfBuildIdFixtures.create(path, elf64, order, id,
            List.of(section(0, id.length, 8)), List.of(segment(0, id.length, 8)), false,
            false, false, (1L << 31) + 4096);
        long size = Files.size(path);
        var time = Files.getLastModifiedTime(path);
        byte[] beginning = readRange(path, 0, 256);
        var result = ElfBuildId.read(path);
        require(size > Integer.MAX_VALUE && result.occurrences().get(0).noteOffset() == fixture.dataOffset(),
            "high offset truncated");
        require(Arrays.equals(id, readRange(path, fixture.dataOffset(), id.length)) &&
            Arrays.equals(beginning, readRange(path, 0, 256)) && size == Files.size(path) &&
            time.equals(Files.getLastModifiedTime(path)), "sparse input changed");
        Files.delete(path); // Also exercises closed channels on Windows.
    }

    private static void checkLimits(Path path) throws Exception {
        byte[] id = ElfBuildIdFixtures.note(LE, 4, GNU, 3, new byte[ElfBuildId.MAX_BUILD_ID_BYTES]);
        fixture(path, true, LE, id, List.of(section(0, id.length, 4)), List.of(), false);
        require(ElfBuildId.read(path).hex().orElseThrow().length() == 2 * ElfBuildId.MAX_BUILD_ID_BYTES,
            "exact ID limit rejected");
        id = ElfBuildIdFixtures.note(LE, 4, GNU, 3, new byte[ElfBuildId.MAX_BUILD_ID_BYTES + 1]);
        fixture(path, true, LE, id, List.of(section(0, id.length, 4)), List.of(), false);
        rejectUnchanged(path);

        byte[] emptyNote = ElfBuildIdFixtures.note(LE, 4, new byte[0], 0, new byte[0]);
        List<ElfBuildIdFixtures.View> views = new ArrayList<>();
        for (int index = 0; index < ElfBuildId.MAX_VIEWS; index++) {
            views.add(section(0, emptyNote.length, 4));
        }
        fixture(path, true, LE, emptyNote, views, List.of(), false);
        require(ElfBuildId.read(path).hex().isEmpty(), "exact view limit rejected");
        views.add(section(0, emptyNote.length, 4));
        fixture(path, true, LE, emptyNote, views, List.of(), false);
        rejectUnchanged(path);

        byte[] many = new byte[(ElfBuildId.MAX_NOTE_VISITS + 1) * 12];
        fixture(path, true, LE, many, List.of(section(0, many.length - 12, 4)), List.of(), false);
        require(ElfBuildId.read(path).hex().isEmpty(), "exact visit limit rejected");
        fixture(path, true, LE, many, List.of(section(0, many.length, 4)), List.of(), false);
        rejectUnchanged(path);

        // Header12 + owner-terminator1 + exact-owner4 + descriptor = 1 MiB per visit.
        id = ElfBuildIdFixtures.note(LE, 4, GNU, 3, new byte[1024 * 1024 - 17]);
        views = new ArrayList<>();
        for (int index = 0; index < 16; index++) {
            views.add(section(0, id.length, 4));
        }
        fixture(path, true, LE, id, views, List.of(), false);
        require(ElfBuildId.read(path).occurrences().get(0).containers().size() == 16,
            "exact read-byte limit rejected");
        views.add(section(0, id.length, 4));
        fixture(path, true, LE, id, views, List.of(), false);
        rejectUnchanged(path);
    }

    private static void checkCancellation(Path path) throws Exception {
        Path absent = path.resolveSibling("does-not-exist");
        expect(CancellationException.class, () -> ElfBuildId.read(absent, () -> true));
        require(!Files.exists(absent), "cancelled-before-open created input");
        byte[] id = ElfBuildIdFixtures.note(LE, 4, GNU, 3, new byte[200000]);
        fixture(path, true, LE, id, List.of(section(0, id.length, 4)), List.of(), false);
        byte[] before = hash(path);
        AtomicInteger count = new AtomicInteger();
        ElfBuildId.read(path, () -> { count.incrementAndGet(); return false; });
        for (int cancelAt : new int[] { 2, 5, count.get() - 2, count.get() }) {
            AtomicInteger current = new AtomicInteger();
            expect(CancellationException.class,
                () -> ElfBuildId.read(path, () -> current.incrementAndGet() == cancelAt));
            require(current.get() == cancelAt, "cancel probe was vacuous");
        }
        RuntimeException failure = new IllegalStateException("supplier failure");
        AtomicInteger current = new AtomicInteger();
        Throwable caught = expect(IllegalStateException.class, () -> ElfBuildId.read(path, () -> {
            if (current.incrementAndGet() == 8) {
                throw failure;
            }
            return false;
        }));
        require(caught == failure, "supplier exception identity lost");
        require(Arrays.equals(before, hash(path)), "cancelled input changed");
        Path moved = path.resolveSibling("after-cancel.elf");
        Files.move(path, moved);
        Files.delete(moved);
    }

    private static void checkRelationships(Path path) throws Exception {
        ElfBuildId.Observation absent = new ElfBuildId.Observation(Optional.empty(), List.of());
        byte[] id = ElfBuildIdFixtures.note(LE, 4, GNU, 3, ID);
        fixture(path, true, LE, id, List.of(section(0, id.length, 4)), List.of(), true);
        var first = ElfBuildId.read(path);
        var second = ElfBuildId.read(path);
        id = ElfBuildIdFixtures.note(LE, 4, GNU, 3, new byte[] { 42 });
        fixture(path, false, ByteOrder.BIG_ENDIAN,
            ElfBuildIdFixtures.note(ByteOrder.BIG_ENDIAN, 4, GNU, 3, new byte[] { 42 }),
            List.of(section(0, id.length, 4)), List.of(), false);
        var different = ElfBuildId.read(path);
        require(ElfBuildId.compare(first, second) == ElfBuildId.Relationship.SAME_BUILD_ID &&
            ElfBuildId.compare(first, different) == ElfBuildId.Relationship.DIFFERENT_BUILD_IDS &&
            ElfBuildId.compare(absent, absent) == ElfBuildId.Relationship.ABSENT_BOTH &&
            ElfBuildId.compare(first, absent) == ElfBuildId.Relationship.MISSING_FROM_SIDECAR &&
            ElfBuildId.compare(absent, first) == ElfBuildId.Relationship.MISSING_FROM_ORIGINAL,
            "relationship semantics differ");
        expect(NullPointerException.class, () -> ElfBuildId.read(path, null));
        expect(NullPointerException.class, () -> ElfBuildId.compare(null, first));
        // Equal bytes still compare equal across different ELF metadata: no identity claim.
        byte[] other = ElfBuildIdFixtures.note(ByteOrder.BIG_ENDIAN, 8, GNU, 3, ID);
        fixture(path, false, ByteOrder.BIG_ENDIAN, other, List.of(section(0, other.length, 8)), List.of(), false);
        require(ElfBuildId.compare(first, ElfBuildId.read(path)) == ElfBuildId.Relationship.SAME_BUILD_ID,
            "relationship silently became ELF identity policy");
    }

    private static void checkChangedSource(Path path) throws Exception {
        byte[] id = ElfBuildIdFixtures.note(LE, 4, GNU, 3, ID);
        fixture(path, true, LE, id, List.of(section(0, id.length, 4)), List.of(), false);
        byte[] before = hash(path);
        FileTime time = Files.getLastModifiedTime(path);
        AtomicInteger count = new AtomicInteger();
        expect(IOException.class, () -> ElfBuildId.read(path, () -> {
            if (count.incrementAndGet() == 8) {
                try {
                    Files.setLastModifiedTime(path, FileTime.fromMillis(time.toMillis() + 10000));
                }
                catch (IOException failure) {
                    throw new AssertionError("controlled metadata change failed", failure);
                }
            }
            return false;
        }));
        require(count.get() == 8, "source-change control did not reach read boundary");
        Files.setLastModifiedTime(path, time);
        require(Arrays.equals(before, hash(path)), "source-change control altered bytes");
        Files.delete(path);
    }

    private static ElfBuildIdFixtures.Fixture fixture(Path path, boolean elf64, ByteOrder order,
            byte[] payload, List<ElfBuildIdFixtures.View> sections,
            List<ElfBuildIdFixtures.View> segments, boolean names) throws IOException {
        return ElfBuildIdFixtures.create(path, elf64, order, payload, sections, segments, names,
            false, false, 0);
    }

    private static void rejectUnchanged(Path path) throws Exception {
        byte[] before = hash(path);
        var time = Files.getLastModifiedTime(path);
        expect(IOException.class, () -> ElfBuildId.read(path));
        require(Arrays.equals(before, hash(path)) && time.equals(Files.getLastModifiedTime(path)),
            "rejected input changed");
    }

    private static byte[] hash(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] bytes = new byte[65536];
            for (int count; (count = input.read(bytes)) != -1;) {
                digest.update(bytes, 0, count);
            }
        }
        return digest.digest();
    }

    private static byte[] readRange(Path path, long offset, int size) throws IOException {
        ByteBuffer result = ByteBuffer.allocate(size);
        try (FileChannel input = FileChannel.open(path, StandardOpenOption.READ)) {
            while (result.hasRemaining()) {
                if (input.read(result, offset + result.position()) <= 0) {
                    throw new IOException("fixture read failed");
                }
            }
        }
        return result.array();
    }

    private interface Checked {
        void run() throws Exception;
    }

    private static Throwable expect(Class<? extends Throwable> type, Checked action) throws Exception {
        try {
            action.run();
        }
        catch (Throwable caught) {
            require(type.isInstance(caught), "wrong failure type: " + caught);
            return caught;
        }
        throw new AssertionError("expected " + type.getName());
    }

    private static void require(boolean condition, String description) {
        if (!condition) {
            throw new AssertionError(description);
        }
    }
}
