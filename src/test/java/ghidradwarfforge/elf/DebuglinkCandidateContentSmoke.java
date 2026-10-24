package ghidradwarfforge.elf;

import ghidradwarfforge.elf.DebuglinkCandidateContent.AllocationStatus;
import ghidradwarfforge.elf.DebuglinkCandidateContent.DebuglinkStatus;
import ghidradwarfforge.elf.DebuglinkCandidateContentFixtures.Pair;
import ghidradwarfforge.output.FileDigests;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import static ghidradwarfforge.elf.DebuglinkCandidateContentFixtures.*;

/** Native-free independent ELF bytes and observable composition boundaries. */
public final class DebuglinkCandidateContentSmoke {
    private static int checks;
    private static final byte[] BASENAME = {'o', 'w', 'n', 'e', 'd', '.', 'd', 'b', 'g'};

    private DebuglinkCandidateContentSmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        Path root = Files.createTempDirectory("forge-candidate-content-");
        try {
            for (boolean wide : new boolean[] {false, true}) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    Pair pair = create(root.resolve(wide + "-" + order), wide, order, BASENAME);
                    positive(pair);
                    allocationFields(pair);
                    associationFields(pair);
                    layouts(pair);
                    rawNames(pair);
                    independentFailures(pair);
                    basenameCases(root.resolve("basenames-" + wide + order), wide, order);
                }
            }
            pathsAndFailures(root.resolve("paths"));
            rereadLimits(root.resolve("reread"));
            invariants();
            if (Arrays.asList(arguments).contains("--large")) {
                large(root.resolve("large"));
            }
            System.out.println("debuglink-candidate-content-smoke=PASS checks=" + checks);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }

    private static void positive(Pair pair) throws Exception {
        var result = observe(pair);
        require(result.programBytes().status() == ExecutableProgramBytes.Status.MATCHING_PROGRAM_BYTES,
            "program positive");
        require(result.allocatedSections().status() == AllocationStatus.MATCHING, "allocation positive");
        require(result.newDebuglink().status() == DebuglinkStatus.MATCHING, "link positive");
        require(result.sidecarDigest().equals(FileDigests.read(pair.sidecar())), "digest observation");
        require(!Arrays.equals(Arrays.copyOf(Files.readAllBytes(pair.sidecar()), 4),
            new byte[] {0x7f, 'E', 'L', 'F'}), "plain sidecar counterexample disappeared");
        require(result.equals(observe(pair)), "repeat changed result");
    }

    private static void allocationFields(Pair pair) throws Exception {
        String[] names = {"type", "flags", "address", "offset", "size", "link", "info", "alignment", "entrySize"};
        long[] values = {7, 2, 0x401001, 0x1001, 0x17f, 3, 1, 8, 1};
        for (int i = 0; i < names.length; i++) {
            int index = i;
            changed(pair, () -> field(pair, true, TEXT, names[index], values[index]), result -> {
                require(result.allocatedSections().status() == AllocationStatus.DIFFERENT, "field " + names[index]);
                require(result.allocatedSections().issue().orElseThrow().candidateIndex() == TEXT, "indexed issue");
                require(result.newDebuglink().status() == DebuglinkStatus.MATCHING, "allocation hid link");
                require(result.programBytes().status() == ExecutableProgramBytes.Status.MATCHING_PROGRAM_BYTES,
                    "active metadata changed program predicate");
            });
        }
        changed(pair, () -> field(pair, true, RELOC, "type", 8), result ->
            require(result.allocatedSections().status() == AllocationStatus.DIFFERENT, "sidecar REL neutralization accepted"));
        changed(pair, () -> field(pair, true, NAMES, "flags", 2), result ->
            require(result.allocatedSections().status() == AllocationStatus.DIFFERENT, "extra allocation accepted"));
        changed(pair, () -> field(pair, true, TEXT, "flags", 0), result -> {
            var issue = result.allocatedSections().issue().orElseThrow();
            require(result.allocatedSections().status() == AllocationStatus.DIFFERENT &&
                issue.originalIndex() == TEXT && issue.candidateIndex() == TEXT &&
                issue.field().equals("allocation"), "allocated section demotion");
            require(result.newDebuglink().status() == DebuglinkStatus.MATCHING &&
                result.programBytes().status() == ExecutableProgramBytes.Status.MATCHING_PROGRAM_BYTES,
                "demotion hid other predicates");
        });
        changed(pair, () -> {
            byte[] original = Files.readAllBytes(pair.original());
            byte[] expanded = Arrays.copyOf(original, ORIGINAL_TABLE + 7 * pair.size());
            System.arraycopy(original, (int) pair.header(false, TEXT), expanded,
                ORIGINAL_TABLE + 6 * pair.size(), pair.size());
            ByteBuffer.wrap(expanded).order(pair.order()).putShort(pair.wide() ? 60 : 48, (short) 7);
            Files.write(pair.original(), expanded);
        }, result -> {
            var issue = result.allocatedSections().issue().orElseThrow();
            require(result.allocatedSections().status() == AllocationStatus.DIFFERENT &&
                issue.originalIndex() == 6 && issue.candidateIndex() == -1 && issue.field().equals("section"),
                "missing allocated index");
            require(result.newDebuglink().status() == DebuglinkStatus.MATCHING &&
                result.programBytes().status() == ExecutableProgramBytes.Status.MATCHING_PROGRAM_BYTES,
                "missing index hid other predicates");
        });
        changed(pair, () -> {
            field(pair, false, TEXT, "offset", 0x1700);
            field(pair, true, TEXT, "offset", 0x1700);
        }, result -> {
            require(result.allocatedSections().status() == AllocationStatus.UNSUPPORTED, "uncovered allocation accepted");
            require(result.programBytes().status() == ExecutableProgramBytes.Status.MATCHING_PROGRAM_BYTES,
                "uncovered control program mismatch");
            require(result.newDebuglink().status() == DebuglinkStatus.MATCHING, "coverage hid link");
        });
        changed(pair, () -> {
            field(pair, false, TEXT, "size", 0);
            field(pair, true, TEXT, "size", 0);
        }, result -> require(result.allocatedSections().status() == AllocationStatus.MATCHING, "zero allocation"));
        changed(pair, () -> {
            for (int index : new int[] {TEXT, BSS, RELOC}) {
                field(pair, false, index, "flags", 0);
                field(pair, true, index, "flags", 0);
            }
        }, result -> {
            require(result.allocatedSections().status() == AllocationStatus.NO_ALLOCATION_EVIDENCE, "no allocation");
            require(result.newDebuglink().status() == DebuglinkStatus.MATCHING, "no allocation hid link");
        });
    }

    private static void associationFields(Pair pair) throws Exception {
        String[] names = {"type", "flags", "address", "link", "info", "alignment", "entrySize", "size", "name"};
        long[] values = {8, 2, 0x1234, 1, 1, 8, 1, 15, 47};
        for (int i = 0; i < names.length; i++) {
            int index = i;
            changed(pair, () -> field(pair, true, LINK, names[index], values[index]), result ->
                require(result.newDebuglink().status() == DebuglinkStatus.DIFFERENT, "link field " + names[index]));
        }
        for (int offset : new int[] {0, BASENAME.length, BASENAME.length + 1, 15}) {
            changed(pair, () -> flip(pair.candidate(), LINK_BYTES + offset), result -> {
                require(result.newDebuglink().status() == DebuglinkStatus.DIFFERENT, "payload byte " + offset);
                require(result.allocatedSections().status() == AllocationStatus.MATCHING, "payload hid allocation");
            });
        }
        changed(pair, () -> {
            byte[] data = Files.readAllBytes(pair.candidate());
            byte[] crc = Arrays.copyOfRange(data, LINK_BYTES + 12, LINK_BYTES + 16);
            for (int i = 0; i < 4; i++) { data[LINK_BYTES + 12 + i] = crc[3 - i]; }
            Files.write(pair.candidate(), data);
        }, result -> require(result.newDebuglink().status() == DebuglinkStatus.DIFFERENT, "CRC endian"));
        changed(pair, () -> Files.write(pair.sidecar(), new byte[] {9}), result ->
            require(result.newDebuglink().status() == DebuglinkStatus.DIFFERENT, "changed sidecar"));
        changed(pair, () -> field(pair, true, TEXT, "name", 32), result ->
            require(result.newDebuglink().issue().orElseThrow().field().equals(".gnu_debuglink count"), "duplicate link"));
        changed(pair, () -> field(pair, false, TEXT, "name", 32), result ->
            require(result.newDebuglink().status() == DebuglinkStatus.UNSUPPORTED, "existing initial link"));
        changed(pair, () -> {
            field(pair, false, TEXT, "name", 32);
            field(pair, false, BSS, "name", 32);
        }, result -> require(result.newDebuglink().status() == DebuglinkStatus.UNSUPPORTED, "duplicate existing link"));
    }

    private static void layouts(Pair pair) throws Exception {
        changed(pair, () -> {
            for (Path p : List.of(pair.original(), pair.candidate())) {
                write(p, pair.wide() ? 62 : 50, new byte[2]);
            }
        }, result -> {
            require(result.allocatedSections().status() == AllocationStatus.UNSUPPORTED, "nameless allocation");
            require(result.newDebuglink().status() == DebuglinkStatus.UNSUPPORTED, "nameless link");
        });
        changed(pair, () -> {
            for (Path p : List.of(pair.original(), pair.candidate())) {
                write(p, pair.wide() ? 40 : 32, new byte[pair.wide() ? 8 : 4]);
                write(p, pair.wide() ? 60 : 48, new byte[4]);
            }
        }, result -> require(result.newDebuglink().status() == DebuglinkStatus.UNSUPPORTED, "sectionless layout"));
        changed(pair, () -> {
            byte[] old = Files.readAllBytes(pair.candidate());
            int width = pair.size() + 8;
            int at = 0x4000;
            byte[] next = Arrays.copyOf(old, at + width * 6);
            for (int index = 0; index < 6; index++) {
                System.arraycopy(old, (int) pair.header(true, index), next, at + width * index, pair.size());
            }
            ByteBuffer b = ByteBuffer.wrap(next).order(pair.order());
            word(b, pair.wide() ? 40 : 32, at, pair.wide());
            b.putShort(pair.wide() ? 58 : 46, (short) width);
            Files.write(pair.candidate(), next);
        }, result -> require(result.allocatedSections().status() == AllocationStatus.UNSUPPORTED, "extended SHT width"));
    }

    private static void rawNames(Pair pair) throws Exception {
        // Invalid UTF-8 bytes are legal raw names; no decoded replacement equality.
        changed(pair, () -> {
            write(pair.original(), NAME_BYTES + 1, new byte[] {(byte) 0xff});
            write(pair.candidate(), NAME_BYTES + 1, new byte[] {(byte) 0xff});
        }, result -> require(result.allocatedSections().status() == AllocationStatus.MATCHING, "equal raw names"));
        changed(pair, () -> {
            write(pair.original(), NAME_BYTES + 1, new byte[] {(byte) 0xff});
            write(pair.candidate(), NAME_BYTES + 1, new byte[] {(byte) 0xfe});
        }, result -> require(result.allocatedSections().status() == AllocationStatus.DIFFERENT, "replacement name collision"));
        changed(pair, () -> {
            // Used suffix slices and duplicate names preserve index identity.
            for (boolean candidate : new boolean[] {false, true}) {
                field(pair, candidate, TEXT, "name", 2);
                field(pair, candidate, RELOC, "name", 2);
            }
        }, result -> require(result.allocatedSections().status() == AllocationStatus.MATCHING, "suffix/duplicate names"));
        changed(pair, () -> {
            byte[] table = Arrays.copyOf(NAMES_BYTES, NAMES_BYTES.length + 6);
            System.arraycopy(NAMES_BYTES, 1, table, NAMES_BYTES.length, 6);
            write(pair.candidate(), NAME_BYTES, table);
            field(pair, true, NAMES, "size", table.length);
            field(pair, true, TEXT, "name", NAMES_BYTES.length);
        }, result -> require(result.allocatedSections().status() == AllocationStatus.MATCHING, "relocated raw name"));
        for (boolean shorter : new boolean[] {false, true}) {
            changed(pair, () -> {
                byte[] table = Arrays.copyOf(NAMES_BYTES, NAMES_BYTES.length + 97);
                Arrays.fill(table, NAMES_BYTES.length, table.length - 1, (byte) 'q');
                for (boolean candidate : new boolean[] {false, true}) {
                    if (candidate) {
                        table[NAMES_BYTES.length + 80] = shorter ? 0 : (byte) 0xfe;
                    }
                    write(candidate ? pair.candidate() : pair.original(), NAME_BYTES, table);
                    field(pair, candidate, NAMES, "size", table.length);
                    field(pair, candidate, TEXT, "name", NAMES_BYTES.length);
                }
            }, result -> {
                var issue = result.allocatedSections().issue().orElseThrow();
                require(result.allocatedSections().status() == AllocationStatus.DIFFERENT &&
                    issue.field().equals("sh_name") && issue.originalIndex() == TEXT &&
                    issue.candidateIndex() == TEXT, "raw suffix issue");
                require(issue.expected().equals("name byte 80=0x71 length=96") &&
                    issue.observed().equals(shorter ? "name byte 80=<end> length=80" :
                        "name byte 80=0xfe length=96"), "bounded name issue hides difference");
            });
        }
    }

    private static void independentFailures(Pair pair) throws Exception {
        changed(pair, () -> {
            flip(pair.candidate(), 0x1000);
            field(pair, true, TEXT, "address", 0x700000);
            flip(pair.candidate(), LINK_BYTES + 15);
        }, result -> {
            require(result.programBytes().status() == ExecutableProgramBytes.Status.DIFFERENT_PROGRAM_BYTES, "program difference");
            require(result.allocatedSections().status() == AllocationStatus.DIFFERENT, "allocation short circuit");
            require(result.newDebuglink().status() == DebuglinkStatus.DIFFERENT, "link short circuit");
        });
    }

    private static void basenameCases(Path root, boolean wide, ByteOrder order) throws Exception {
        byte[][] names = {new byte[] {'x'}, new byte[] {'a', 'b', 'c'}, new byte[] {'a', 'b', 'c', 'd'},
            new byte[] {(byte) 0xff, '\\', (byte) 0x80, 'A'}, new byte[65536]};
        Arrays.fill(names[4], (byte) 'z');
        for (int index = 0; index < names.length; index++) {
            Pair pair = create(root.resolve(Integer.toString(index)), wide, order, names[index]);
            require(observe(pair).newDebuglink().status() == DebuglinkStatus.MATCHING, "literal basename boundary");
        }
    }

    private static void pathsAndFailures(Path root) throws Exception {
        Pair pair = create(root, true, ByteOrder.LITTLE_ENDIAN, BASENAME);
        for (byte[] invalid : new byte[][] {new byte[0], new byte[65537], {'.'}, {'.', '.'}, {'a', 0}, {'a', '/'}}) {
            expect(IllegalArgumentException.class, () -> DebuglinkCandidateContent.observe(
                root.resolve("missing"), pair.candidate(), pair.sidecar(), invalid));
        }
        byte[] supplied = BASENAME.clone();
        var cloned = DebuglinkCandidateContent.observe(pair.original(), pair.candidate(), pair.sidecar(), supplied, () -> {
            Arrays.fill(supplied, (byte) 0);
            return false;
        });
        require(cloned.newDebuglink().status() == DebuglinkStatus.MATCHING, "basename not cloned before first poll");
        expect(CancellationException.class, () -> DebuglinkCandidateContent.observe(root.resolve("missing"),
            pair.candidate(), pair.sidecar(), BASENAME, () -> true));
        Path invalid = root.resolve("invalid.elf");
        Files.write(invalid, new byte[] {1});
        IOException precheck = (IOException) expect(IOException.class, () ->
            DebuglinkCandidateContent.observe(invalid, pair.candidate(), root, BASENAME));
        require(precheck.getCause() == null && precheck.getMessage().contains(root.toString()), "regular precheck ordering");
        expect(IOException.class, () -> DebuglinkCandidateContent.observe(invalid, pair.candidate(), pair.sidecar(), BASENAME));
        AtomicInteger polls = new AtomicInteger();
        DebuglinkCandidateContent.observe(pair.original(), pair.candidate(), pair.sidecar(), BASENAME,
            () -> { polls.incrementAndGet(); return false; });
        for (int stop : new int[] {4, 10, polls.get() - 1, polls.get()}) {
            AtomicInteger calls = new AtomicInteger();
            expect(CancellationException.class, () -> DebuglinkCandidateContent.observe(pair.original(),
                pair.candidate(), pair.sidecar(), BASENAME, () -> calls.incrementAndGet() == stop));
            positive(pair);
        }
        RuntimeException marker = new RuntimeException("owned supplier failure");
        require(expect(RuntimeException.class, () -> DebuglinkCandidateContent.observe(pair.original(),
            pair.candidate(), pair.sidecar(), BASENAME, () -> { throw marker; })) == marker, "supplier failure identity");
        IllegalArgumentException afterParse = new IllegalArgumentException("supplier after parser");
        AtomicInteger parsedPolls = new AtomicInteger();
        require(expect(IllegalArgumentException.class, () -> DebuglinkCandidateContent.observe(pair.original(),
            pair.candidate(), pair.sidecar(), BASENAME, () -> {
                if (parsedPolls.incrementAndGet() == 5) { throw afterParse; }
                return false;
            })) == afterParse, "supplier failure must not become malformed ELF");
        // Same-file aliases are observations, not a requirement for distinct attachment paths.
        var same = DebuglinkCandidateContent.observe(pair.original(), pair.original(), pair.sidecar(), BASENAME);
        require(same.programBytes().status() == ExecutableProgramBytes.Status.MATCHING_PROGRAM_BYTES &&
            same.allocatedSections().status() == AllocationStatus.MATCHING &&
            same.newDebuglink().status() == DebuglinkStatus.DIFFERENT, "same-file observation");
        if (!System.getProperty("os.name").startsWith("Windows")) {
            Path fifo = root.resolve("fifo");
            Process process = new ProcessBuilder("mkfifo", fifo.toString()).start();
            require(process.waitFor() == 0, "FIFO setup");
            expect(IOException.class, () -> DebuglinkCandidateContent.observe(invalid, pair.candidate(), fifo, BASENAME));
            Path real = root.resolve("actual/child");
            Files.createDirectories(real);
            Path link = root.resolve("directory-link");
            Files.createSymbolicLink(link, real);
            Path actual = real.getParent().resolve("original");
            Files.copy(pair.original(), actual);
            Files.write(root.resolve("original"), new byte[] {0});
            Path traversal = link.resolve("../original");
            require(Files.isSameFile(traversal, actual), "host traversal setup");
            require(DebuglinkCandidateContent.observe(traversal, pair.candidate(), pair.sidecar(), BASENAME)
                .newDebuglink().status() == DebuglinkStatus.MATCHING, "actual traversal changed");
            Path leaf = root.resolve("leaf-link");
            Files.createSymbolicLink(leaf, pair.original());
            require(DebuglinkCandidateContent.observe(leaf, pair.candidate(), pair.sidecar(), BASENAME)
                .allocatedSections().status() == AllocationStatus.MATCHING, "input leaf link");
        }
    }

    private static void rereadLimits(Path root) throws Exception {
        for (boolean aggregate : new boolean[] {false, true}) {
            Pair pair = create(root.resolve(Boolean.toString(aggregate)), true, ByteOrder.LITTLE_ENDIAN, BASENAME);
            int count = aggregate ? 300 : 5;
            int namesAt = 0x10000;
            int namesLength = 65540;
            byte[] data = Arrays.copyOf(Files.readAllBytes(pair.original()), namesAt + namesLength);
            ByteBuffer b = ByteBuffer.wrap(data).order(pair.order());
            b.putShort(60, (short) count);
            for (int index = 0; index < count; index++) {
                b.putInt(ORIGINAL_TABLE + index * 64, index);
            }
            b.putInt(ORIGINAL_TABLE, 0);
            b.putLong(ORIGINAL_TABLE + NAMES * 64 + 24, namesAt);
            b.putLong(ORIGINAL_TABLE + NAMES * 64 + 32, namesLength);
            Files.write(pair.original(), data);
            ElfImage.read(pair.original()); // Valid small names before the second read.
            FileTime time = Files.getLastModifiedTime(pair.original());
            boolean[] changed = {false};
            IOException failure = (IOException) expect(IOException.class, () -> DebuglinkCandidateContent.observe(
                pair.original(), pair.candidate(), pair.sidecar(), BASENAME, () -> {
                    boolean namesConstructor = StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                        frame.getClassName().equals(DebuglinkCandidateContent.class.getName() + "$Names") &&
                        frame.getMethodName().equals("<init>")));
                    if (namesConstructor && !changed[0]) {
                        byte[] altered = new byte[namesLength];
                        Arrays.fill(altered, 1, aggregate ? 65537 : 65538, (byte) 'a');
                        try {
                            write(pair.original(), namesAt, altered);
                            Files.setLastModifiedTime(pair.original(), time);
                            changed[0] = true;
                        }
                        catch (IOException problem) { throw new AssertionError(problem); }
                    }
                    return false;
                }));
            require(changed[0] && Files.size(pair.original()) == data.length &&
                Files.getLastModifiedTime(pair.original()).equals(time), "reread mutation was vacuous");
            require(failure.getCause() == null && failure.getMessage().equals(aggregate ?
                "raw used names exceed 16 MiB aggregate limit" : "raw section name exceeds 65536-byte limit"),
                "wrong raw reread failure: " + failure);
        }
    }

    private static void invariants() throws Exception {
        expect(IllegalArgumentException.class, () -> new DebuglinkCandidateContent.Issue(-2, -1, "f", "e", "o"));
        var issue = new DebuglinkCandidateContent.Issue(-1, 2, "f", "e", "o");
        expect(IllegalArgumentException.class, () -> new DebuglinkCandidateContent.AllocationObservation(
            AllocationStatus.MATCHING, Optional.of(issue), "diagnostic"));
        expect(IllegalArgumentException.class, () -> new DebuglinkCandidateContent.DebuglinkObservation(
            DebuglinkStatus.DIFFERENT, Optional.empty(), "diagnostic"));
    }

    private static void large(Path root) throws Exception {
        Pair pair = create(root, false, ByteOrder.BIG_ENDIAN, BASENAME);
        long size = (1L << 31) + 65537;
        try (FileChannel output = FileChannel.open(pair.sidecar(), StandardOpenOption.WRITE)) {
            output.write(ByteBuffer.wrap(new byte[] {91}), size - 1);
        }
        FileTime time = Files.getLastModifiedTime(pair.sidecar());
        var digest = FileDigests.read(pair.sidecar());
        ByteBuffer crc = ByteBuffer.allocate(4).order(pair.order()).putInt((int) digest.gnuDebuglinkCrc32());
        write(pair.candidate(), LINK_BYTES + 12, crc.array());
        var result = DebuglinkCandidateContent.observe(pair.original(), pair.candidate(), pair.sidecar(), BASENAME);
        require(result.newDebuglink().status() == DebuglinkStatus.MATCHING && result.sidecarDigest().equals(digest),
            "large sidecar streamed observation");
        require(Files.size(pair.sidecar()) == size && Files.getLastModifiedTime(pair.sidecar()).equals(time),
            "large sidecar changed");
        System.out.println("large-sidecar-bytes=" + size + " crc32=" + digest.gnuDebuglinkCrc32());
    }

    private static DebuglinkCandidateContent.Result observe(Pair pair) throws Exception {
        return DebuglinkCandidateContent.observe(pair.original(), pair.candidate(), pair.sidecar(), pair.basename());
    }

    private record Snapshot(Path path, byte[] bytes, FileTime time) {
        Snapshot(Path path) throws IOException { this(path, Files.readAllBytes(path), Files.getLastModifiedTime(path)); }
        void verify() throws IOException {
            require(Arrays.equals(bytes, Files.readAllBytes(path)) && time.equals(Files.getLastModifiedTime(path)),
                "observer changed " + path);
        }
        void restore() throws IOException { Files.write(path, bytes); Files.setLastModifiedTime(path, time); }
    }

    private static void changed(Pair pair, Action mutation, Check check) throws Exception {
        List<Snapshot> original = List.of(new Snapshot(pair.original()), new Snapshot(pair.candidate()), new Snapshot(pair.sidecar()));
        try {
            mutation.run();
            List<Snapshot> inputs = List.of(new Snapshot(pair.original()), new Snapshot(pair.candidate()), new Snapshot(pair.sidecar()));
            check.run(observe(pair));
            for (Snapshot input : inputs) { input.verify(); }
        }
        finally {
            for (Snapshot input : original) { input.restore(); }
        }
    }

    private static void flip(Path path, long offset) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        bytes[Math.toIntExact(offset)] ^= 1;
        Files.write(path, bytes);
    }

    @FunctionalInterface private interface Action { void run() throws Exception; }
    @FunctionalInterface private interface Check { void run(DebuglinkCandidateContent.Result result) throws Exception; }

    private static Throwable expect(Class<? extends Throwable> type, Action action) throws Exception {
        try { action.run(); }
        catch (Throwable failure) {
            require(type.isInstance(failure), "expected " + type + ", got " + failure);
            return failure;
        }
        throw new AssertionError("expected " + type);
    }

    private static void require(boolean value, String diagnostic) {
        if (!value) { throw new AssertionError(diagnostic); }
        checks++;
    }
}
