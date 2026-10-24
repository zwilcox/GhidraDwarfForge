package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.elf.MatchedElfAllocations.Result;
import ghidradwarfforge.elf.MatchedElfAllocations.Status;
import ghidradwarfforge.elf.MatchedElfAllocationsFixtures.Pair;
import ghidradwarfforge.elf.MatchedElfPrefixFixtures.Shape;

/** Native-free controls for the conservative relationship, not a DWARF test. */
public final class MatchedElfAllocationsSmoke {
    private static int checks;

    private MatchedElfAllocationsSmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        Path root = Files.createTempDirectory("forge-allocations-");
        try {
            for (boolean wide : new boolean[] {false, true}) {
                for (ByteOrder order : new ByteOrder[] {ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN}) {
                    Path group = root.resolve((wide ? "64" : "32") + "-" + order);
                    for (Shape shape : Shape.values()) {
                        Pair pair = MatchedElfAllocationsFixtures.create(group.resolve(shape.name()), wide, order, shape);
                        unchangedMatch(pair);
                    }
                    fields(group.resolve("fields"), wide, order);
                    transformed(group.resolve("transformed"), wide, order);
                    notes(group.resolve("notes"), wide, order);
                    names(group.resolve("names"), wide, order);
                    empty(group.resolve("empty"), wide, order);
                }
            }
            failures(root.resolve("failures"));
            noteLimit(root.resolve("note-limit"));
            rawNameReread(root.resolve("raw-name-reread"));
            if (arguments.length == 1 && arguments[0].equals("--large")) {
                large(root.resolve("large"));
            }
            else if (arguments.length != 0) {
                throw new IllegalArgumentException("optional argument is --large");
            }
            System.out.println("matched-elf-allocations-smoke=PASS checks=" + checks);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
    }

    private static Pair named(Path path, boolean wide, ByteOrder order) throws IOException {
        return MatchedElfAllocationsFixtures.create(path, wide, order, Shape.NAMED);
    }

    private static Result observe(Pair pair) throws IOException {
        return MatchedElfAllocations.compare(pair.original(), pair.candidate());
    }

    private static void unchangedMatch(Pair pair) throws Exception {
        byte[] original = digest(pair.original()), candidate = digest(pair.candidate());
        FileTime originalTime = Files.getLastModifiedTime(pair.original());
        FileTime candidateTime = Files.getLastModifiedTime(pair.candidate());
        Result first = observe(pair);
        require(first.status() == Status.MATCHING_ALLOCATED_METADATA && first.issue().isEmpty(), "normal relationship");
        require(first.equals(observe(pair)), "nondeterministic observation");
        require(Arrays.equals(original, digest(pair.original())) && Arrays.equals(candidate, digest(pair.candidate())) &&
            originalTime.equals(Files.getLastModifiedTime(pair.original())) &&
            candidateTime.equals(Files.getLastModifiedTime(pair.candidate())), "input changed");
    }

    private static void fields(Path root, boolean wide, ByteOrder order) throws Exception {
        Pair pair = named(root, wide, order);
        String[] fields = {"type", "flags", "address", "offset", "size", "link", "info", "alignment", "entrySize"};
        String[] expectedFields = {"sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size", "sh_link", "sh_info", "sh_addralign", "sh_entsize"};
        long[] values = {8, 4, 0x500240, 0x241, 31, 1, 1, 1, 1};
        for (int index = 0; index < fields.length; index++) {
            Path copy = MatchedElfAllocationsFixtures.copy(pair.candidate(), "changed-" + fields[index]);
            MatchedElfAllocationsFixtures.field(copy, 1, fields[index], values[index]);
            Result result = MatchedElfAllocations.compare(pair.original(), copy);
            issue(result, Status.DIFFERENT_METADATA, expectedFields[index]);
            require(result.issue().orElseThrow().originalIndex() == 1 && result.issue().orElseThrow().candidateIndex() == 1,
                "physical index absent");
            require(MatchedElfPrefix.compare(pair.original(), copy).status() == MatchedElfPrefix.Status.MATCHING_COPIED_PREFIX,
                "active metadata accidentally entered prefix proof");
        }
        Path code = MatchedElfAllocationsFixtures.copy(pair.original(), "changed-code");
        MatchedElfAllocationsFixtures.put(code, 0x240, 1, 99, order);
        require(MatchedElfAllocations.compare(code, pair.candidate()).status() == Status.MATCHING_ALLOCATED_METADATA,
            "allocation comparison claimed copied content");
        require(MatchedElfPrefix.compare(code, pair.candidate()).status() == MatchedElfPrefix.Status.DIFFERENT_PREFIX,
            "code mutation did not differ");
        Path extra = MatchedElfAllocationsFixtures.copy(pair.candidate(), "extra-allocation");
        int debug = ElfImage.read(extra).sections().stream().filter(s -> s.name.equals(".debug_info")).findFirst().orElseThrow().originalIndex;
        MatchedElfAllocationsFixtures.field(extra, debug, "flags", 2);
        issue(MatchedElfAllocations.compare(pair.original(), extra), Status.DIFFERENT_METADATA, "sh_flags");
        int[][] offsets = {{7,1}, {8,1}, {16,2}, {18,2}, {wide ? 48 : 36,4}, {24,wide ? 8 : 4}};
        String[] headerFields = {"EI_OSABI", "EI_ABIVERSION", "e_type", "e_machine", "e_flags", "e_entry"};
        for (int index = 0; index < offsets.length; index++) {
            Path copy = MatchedElfAllocationsFixtures.copy(pair.candidate(), "header-" + index);
            MatchedElfAllocationsFixtures.put(copy, offsets[index][0], offsets[index][1], 1, order);
            issue(MatchedElfAllocations.compare(pair.original(), copy), Status.DIFFERENT_METADATA, headerFields[index]);
        }
        issue(MatchedElfAllocations.compare(pair.original(), pair.original()), Status.DIFFERENT_METADATA, "program table");
        Path wrongName = MatchedElfAllocationsFixtures.copy(pair.candidate(), "wrong-name");
        MatchedElfAllocationsFixtures.field(wrongName, 1, "name", 0);
        issue(MatchedElfAllocations.compare(pair.original(), wrongName), Status.DIFFERENT_METADATA, "sh_name");
        Path phSize = MatchedElfAllocationsFixtures.copy(pair.candidate(), "ph-size");
        MatchedElfAllocationsFixtures.put(phSize, wide ? 54 : 42, 2, 1, order);
        issue(MatchedElfAllocations.compare(pair.original(), phSize), Status.DIFFERENT_METADATA, "program table");
        Path noNames = MatchedElfAllocationsFixtures.copy(pair.candidate(), "no-candidate-names");
        MatchedElfAllocationsFixtures.put(noNames, wide ? 62 : 50, 2, 0, order);
        issue(MatchedElfAllocations.compare(pair.original(), noNames), Status.DIFFERENT_METADATA, "section table");
        // A multiset-only comparison cannot see this change in physical identity.
        Path swapped = MatchedElfAllocationsFixtures.copy(pair.candidate(), "swapped");
        byte[] bytes = Files.readAllBytes(swapped);
        var header = java.nio.ByteBuffer.wrap(bytes).order(order);
        int table = wide ? (int) header.getLong(40) : header.getInt(32);
        int size = wide ? 64 : 40;
        byte[] first = Arrays.copyOfRange(bytes, table + size, table + 2 * size);
        System.arraycopy(bytes, table + 2 * size, bytes, table + size, size);
        System.arraycopy(first, 0, bytes, table + 2 * size, size);
        Files.write(swapped, bytes);
        issue(MatchedElfAllocations.compare(pair.original(), swapped), Status.DIFFERENT_METADATA, "sh_name");
        require(MatchedElfPrefix.compare(pair.original(), swapped).status() == MatchedElfPrefix.Status.MATCHING_COPIED_PREFIX,
            "swapped allocation records changed prefix");
    }

    private static void transformed(Path root, boolean wide, ByteOrder order) throws Exception {
        for (long type : new long[] {4, 9, 8, 0x70000001L}) {
            Pair pair = named(root.resolve("type-" + type), wide, order);
            MatchedElfAllocationsFixtures.field(pair.original(), 1, "type", type);
            MatchedElfAllocationsFixtures.field(pair.original(), 1, "flags", 0x406);
            if (type == 8) {
                MatchedElfAllocationsFixtures.field(pair.original(), 1, "offset", 0x40000000);
                MatchedElfAllocationsFixtures.field(pair.original(), 1, "size", 0x20000000);
            }
            MatchedElfAllocationsFixtures.rewrite(pair);
            unchangedMatch(pair);
            if (type == 4 || type == 9) {
                var section = ElfImage.read(pair.candidate()).sections().get(1);
                require(section.type == 8 && section.flags == 2, "nonvacuous relocation placeholder");
                Path bad = MatchedElfAllocationsFixtures.copy(pair.candidate(), "bad-relocation");
                MatchedElfAllocationsFixtures.field(bad, 1, "flags", 3);
                issue(MatchedElfAllocations.compare(pair.original(), bad), Status.DIFFERENT_METADATA, "sh_flags");
            }
        }
        for (String name : new String[] {".debug_info", ".zdebug_info", ".gnu_debuglink", ".rel.debug_info"}) {
            Pair pair = named(root.resolve(name), wide, order);
            MatchedElfAllocationsFixtures.appendName(pair.original(), 1, name);
            MatchedElfAllocationsFixtures.rewrite(pair);
            issue(observe(pair), Status.UNSUPPORTED_CASE, "sh_flags/sh_name");
            if (name.equals(".debug_info")) {
                require(ElfImage.read(pair.candidate()).sections().get(1).flags == 0, "replacement did not lose allocation");
            }
        }
        Pair names = named(root.resolve("allocated-names"), wide, order);
        MatchedElfAllocationsFixtures.field(names.original(), 3, "flags", 2);
        MatchedElfAllocationsFixtures.field(names.original(), 3, "address", 0x400280);
        MatchedElfAllocationsFixtures.rewrite(names);
        issue(observe(names), Status.UNSUPPORTED_CASE, "sh_name");

        Pair absent = MatchedElfAllocationsFixtures.create(root.resolve("memory-only"), wide, order, Shape.SECTIONLESS);
        MatchedElfAllocationsFixtures.program(absent.original(), 0, "fileSize", 0);
        MatchedElfAllocationsFixtures.program(absent.original(), 0, "memorySize", 0x1234);
        MatchedElfAllocationsFixtures.rewrite(absent);
        unchangedMatch(absent);
        var load = ElfImage.read(absent.candidate()).sections().get(1);
        require(load.type == 8 && load.size == 0x1234, "memory-only load size");
        Path changed = MatchedElfAllocationsFixtures.copy(absent.candidate(), "changed-load");
        MatchedElfAllocationsFixtures.field(changed, 1, "size", 0x1233);
        issue(MatchedElfAllocations.compare(absent.original(), changed), Status.DIFFERENT_METADATA, "sh_size");
        if (!wide) {
            MatchedElfAllocationsFixtures.program(absent.original(), 0, "address", 0xfffff000L);
            MatchedElfAllocationsFixtures.program(absent.original(), 0, "memorySize", 0x1000);
            MatchedElfAllocationsFixtures.rewrite(absent);
            unchangedMatch(absent);
            MatchedElfAllocationsFixtures.program(absent.original(), 0, "memorySize", 0x1001);
            issue(observe(absent), Status.UNSUPPORTED_CASE, "p_vaddr/p_memsz");
        }
        else {
            MatchedElfAllocationsFixtures.program(absent.original(), 0, "address", Long.MAX_VALUE - 7);
            MatchedElfAllocationsFixtures.program(absent.original(), 0, "memorySize", 8);
            issue(observe(absent), Status.UNSUPPORTED_CASE, "p_vaddr/p_memsz");
        }
        Pair zero = MatchedElfAllocationsFixtures.create(root.resolve("zero-load"), wide, order, Shape.SECTIONLESS);
        MatchedElfAllocationsFixtures.program(zero.original(), 0, "fileSize", 0);
        MatchedElfAllocationsFixtures.program(zero.original(), 0, "memorySize", 0);
        MatchedElfAllocationsFixtures.rewrite(zero);
        unchangedMatch(zero);
        require(ElfImage.read(zero.candidate()).sections().stream().noneMatch(s -> s.name.startsWith(".forge.load.")),
            "zero-sized load generated an allocation");
        Pair nullOnly = named(root.resolve("null-only"), wide, order);
        MatchedElfAllocationsFixtures.put(nullOnly.original(), wide ? 60 : 48, 2, 1, order);
        MatchedElfAllocationsFixtures.put(nullOnly.original(), wide ? 62 : 50, 2, 0, order);
        MatchedElfAllocationsFixtures.rewrite(nullOnly);
        unchangedMatch(nullOnly);
        require(ElfImage.read(nullOnly.candidate()).sections().stream().noneMatch(s -> s.name.startsWith(".forge.load.")),
            "present NULL-only table was treated as absent");
    }

    private static void notes(Path root, boolean wide, ByteOrder order) throws Exception {
        Pair partial = named(root.resolve("partial"), wide, order);
        MatchedElfAllocationsFixtures.program(partial.original(), 1, "fileSize", 48);
        MatchedElfAllocationsFixtures.program(partial.original(), 1, "memorySize", 48);
        MatchedElfAllocationsFixtures.rewrite(partial);
        unchangedMatch(partial);
        var added = ElfImage.read(partial.candidate()).sections().get(4);
        require(added.name.equals(".note.forge.0") && added.offset == 0x224 && added.size == 12 && added.address == 0x400224,
            "partial coverage did not reconstruct expected gap");
        Path bad = MatchedElfAllocationsFixtures.copy(partial.candidate(), "bad-note");
        MatchedElfAllocationsFixtures.field(bad, 4, "address", 0x400225);
        issue(MatchedElfAllocations.compare(partial.original(), bad), Status.DIFFERENT_METADATA, "sh_addr");

        Pair nonallocated = named(root.resolve("nonallocated"), wide, order);
        MatchedElfAllocationsFixtures.field(nonallocated.original(), 2, "flags", 0);
        MatchedElfAllocationsFixtures.rewrite(nonallocated);
        issue(observe(nonallocated), Status.UNSUPPORTED_CASE, "note address mapping");
        Pair inconsistent = named(root.resolve("section-address"), wide, order);
        MatchedElfAllocationsFixtures.field(inconsistent.original(), 2, "address", 0x900200);
        MatchedElfAllocationsFixtures.rewrite(inconsistent);
        issue(observe(inconsistent), Status.UNSUPPORTED_CASE, "note address mapping");
        for (boolean same : new boolean[] {true, false}) {
            Pair pair = MatchedElfAllocationsFixtures.create(root.resolve("duplicate-" + same), wide, order, Shape.SECTIONLESS);
            MatchedElfAllocationsFixtures.thirdNote(pair, same ? 0x400200 : 0x900200);
            MatchedElfAllocationsFixtures.rewrite(pair);
            require(ElfImage.read(pair.candidate()).sections().stream().filter(s -> s.type == 7).count() == 1,
                "physical note duplicate was not suppressed");
            if (same) {
                unchangedMatch(pair);
            }
            else {
                issue(observe(pair), Status.UNSUPPORTED_CASE, "note address mapping");
            }
        }
        Pair shortGap = named(root.resolve("short-gap"), wide, order);
        MatchedElfAllocationsFixtures.program(shortGap.original(), 1, "fileSize", 40);
        issue(observe(shortGap), Status.UNSUPPORTED_CASE, "note gap");
        Pair misaligned = named(root.resolve("misaligned-gap"), wide, order);
        MatchedElfAllocationsFixtures.program(misaligned.original(), 1, "fileSize", 48);
        MatchedElfAllocationsFixtures.program(misaligned.original(), 1, "alignment", 8);
        issue(observe(misaligned), Status.UNSUPPORTED_CASE, "note gap");
        if (wide) {
            Pair overflow = named(root.resolve("note-address-overflow"), true, order);
            MatchedElfAllocationsFixtures.field(overflow.original(), 2, "address", Long.MAX_VALUE - 16);
            MatchedElfAllocationsFixtures.field(overflow.candidate(), 2, "address", Long.MAX_VALUE - 16);
            MatchedElfAllocationsFixtures.program(overflow.original(), 1, "address", Long.MAX_VALUE - 16);
            MatchedElfAllocationsFixtures.program(overflow.original(), 1, "fileSize", 48);
            issue(observe(overflow), Status.UNSUPPORTED_CASE, "p_vaddr");
        }
    }

    private static void names(Path root, boolean wide, ByteOrder order) throws Exception {
        Pair valid = named(root.resolve("valid-replacement-character"), wide, order);
        byte[] name = {(byte)0xef,(byte)0xbf,(byte)0xbd,'x','y',0};
        MatchedElfAllocationsFixtures.name(valid.original(), 1, name);
        MatchedElfAllocationsFixtures.rewrite(valid);
        unchangedMatch(valid);
        Path badCandidate = MatchedElfAllocationsFixtures.copy(valid.candidate(), "bad-raw-name");
        MatchedElfAllocationsFixtures.name(badCandidate, 1, new byte[] {(byte)0xff,'x','y',0});
        require(ElfImage.read(valid.original()).sections().get(1).name.equals(ElfImage.read(badCandidate).sections().get(1).name),
            "raw-name collision control is vacuous");
        issue(MatchedElfAllocations.compare(valid.original(), badCandidate), Status.DIFFERENT_METADATA, "sh_name");
        Pair invalid = named(root.resolve("nonroundtrip"), wide, order);
        MatchedElfAllocationsFixtures.name(invalid.original(), 1, new byte[] {(byte)0xff});
        MatchedElfAllocationsFixtures.rewrite(invalid);
        issue(observe(invalid), Status.UNSUPPORTED_CASE, "sh_name");
        Pair duplicate = named(root.resolve("duplicate"), wide, order);
        MatchedElfAllocationsFixtures.field(duplicate.original(), 2, "name", 1);
        MatchedElfAllocationsFixtures.rewrite(duplicate);
        unchangedMatch(duplicate);
    }

    private static void empty(Path root, boolean wide, ByteOrder order) throws Exception {
        Pair pair = named(root, wide, order);
        MatchedElfAllocationsFixtures.field(pair.original(), 1, "flags", 0);
        MatchedElfAllocationsFixtures.field(pair.original(), 2, "type", 1);
        MatchedElfAllocationsFixtures.field(pair.original(), 2, "flags", 0);
        MatchedElfAllocationsFixtures.program(pair.original(), 1, "type", 0);
        MatchedElfAllocationsFixtures.rewrite(pair);
        Result result = observe(pair);
        require(result.status() == Status.NO_ALLOCATION_EVIDENCE && result.issue().isEmpty(), "empty evidence was green");
    }

    private static void failures(Path root) throws Exception {
        Pair pair = named(root, true, ByteOrder.LITTLE_ENDIAN);
        Path missing = root.resolve("missing");
        expect(CancellationException.class, () -> MatchedElfAllocations.compare(missing, missing, () -> true));
        expect(IOException.class, () -> MatchedElfAllocations.compare(pair.original(), missing));
        Path invalid = root.resolve("invalid");
        Files.write(invalid, new byte[] {1,2,3});
        expect(IOException.class, () -> MatchedElfAllocations.compare(invalid, pair.candidate()));
        expect(IOException.class, () -> MatchedElfAllocations.compare(pair.original(), invalid));
        Pair otherClass = named(root.resolve("other-class"), false, ByteOrder.LITTLE_ENDIAN);
        issue(MatchedElfAllocations.compare(pair.original(), otherClass.candidate()), Status.DIFFERENT_METADATA, "EI_CLASS");
        Pair otherOrder = named(root.resolve("other-order"), true, ByteOrder.BIG_ENDIAN);
        issue(MatchedElfAllocations.compare(pair.original(), otherOrder.candidate()), Status.DIFFERENT_METADATA, "EI_DATA");
        AtomicInteger checksSeen = new AtomicInteger();
        MatchedElfAllocations.compare(pair.original(), pair.candidate(), () -> { checksSeen.incrementAndGet(); return false; });
        for (int boundary : new int[] {1,2,3,5,checksSeen.get()/2,checksSeen.get()}) {
            AtomicInteger count = new AtomicInteger();
            expect(CancellationException.class, () -> MatchedElfAllocations.compare(pair.original(), pair.candidate(),
                () -> count.incrementAndGet() == boundary));
        }
        IllegalStateException supplierFailure = new IllegalStateException("supplier sentinel");
        Exception caught = expect(IllegalStateException.class, () -> MatchedElfAllocations.compare(pair.original(), pair.candidate(), () -> { throw supplierFailure; }));
        require(caught == supplierFailure, "supplier exception replaced");
        // Deletion/rename after failed parsing/cancellation also runs on native
        // Windows, where a leaked metadata channel would prevent this cleanup.
        Path renamed = root.resolve("renamed-original");
        Files.move(pair.original(), renamed);
        Files.move(renamed, pair.original());
        FileTime old = Files.getLastModifiedTime(pair.original());
        AtomicInteger count = new AtomicInteger();
        expect(IOException.class, () -> MatchedElfAllocations.compare(pair.original(), pair.candidate(), () -> {
            if (count.incrementAndGet() == 5) {
                try { Files.setLastModifiedTime(pair.original(), FileTime.fromMillis(old.toMillis() + 10000)); }
                catch (IOException failure) { throw new AssertionError(failure); }
            }
            return false;
        }));
        Files.setLastModifiedTime(pair.original(), old);
        expect(IllegalArgumentException.class, () -> new Result(Status.MATCHING_ALLOCATED_METADATA,
            Optional.of(new MatchedElfAllocations.Issue(MatchedElfAllocations.Origin.HEADER,-1,-1,"x","x","x","x")),"x"));
        expect(IllegalArgumentException.class, () -> new MatchedElfAllocations.Issue(MatchedElfAllocations.Origin.HEADER,-2,-1,"x","x","x","x"));
    }

    private static void large(Path root) throws Exception {
        Pair pair = MatchedElfAllocationsFixtures.sparse(root);
        long length = Files.size(pair.original());
        require(length > Integer.MAX_VALUE, "large fixture is not large");
        require(observe(pair).status() == Status.MATCHING_ALLOCATED_METADATA, "large metadata did not match");
        MatchedElfAllocationsFixtures.field(pair.candidate(), 1, "address", 0x80010000L);
        issue(observe(pair), Status.DIFFERENT_METADATA, "sh_addr");
        System.out.println("large-allocation-metadata=PASS original-bytes=" + length);
    }

    private static void noteLimit(Path root) throws Exception {
        Pair pair = MatchedElfAllocationsFixtures.manyNotes(root);
        require(observe(pair).status() == Status.MATCHING_ALLOCATED_METADATA, "exact note-view limit failed");
        MatchedElfAllocationsFixtures.program(pair.original(), 65534, "offset", 0x200);
        MatchedElfAllocationsFixtures.program(pair.original(), 65534, "address", 0x400200);
        MatchedElfAllocationsFixtures.program(pair.original(), 65534, "fileSize", 36);
        MatchedElfAllocationsFixtures.program(pair.original(), 65534, "memorySize", 36);
        MatchedElfAllocationsFixtures.program(pair.original(), 65534, "alignment", 4);
        MatchedElfAllocationsFixtures.program(pair.original(), 65534, "type", 4);
        IOException failure = (IOException) expect(IOException.class, () -> observe(pair));
        require(failure.getMessage().contains("65536") && failure.getCause() == null,
            "view-limit failure was a different parse/IO error");
    }

    private static void rawNameReread(Path root) throws Exception {
        for (boolean aggregate : new boolean[] {false, true}) {
            Pair pair = MatchedElfAllocationsFixtures.longRawNames(root.resolve(Boolean.toString(aggregate)), aggregate);
            unchangedMatch(pair);
            ElfImage image = ElfImage.read(pair.original());
            var table = image.sections().get(image.sectionNameIndex());
            byte[] before = Files.readAllBytes(pair.original());
            FileTime time = Files.getLastModifiedTime(pair.original());
            byte[] mutated = new byte[(int) table.size];
            Arrays.fill(mutated, (byte)'a');
            mutated[0] = 0;
            mutated[mutated.length - 1] = 0;
            AtomicInteger polls = new AtomicInteger();
            boolean[] written = {false};
            try {
                IOException failure = (IOException) expect(IOException.class,
                    () -> MatchedElfAllocations.compare(pair.original(), pair.candidate(), () -> {
                        // Poll6 is immediately before the first raw name-table
                        // reread, after BOTH ElfImage parses closed their handles.
                        if (polls.incrementAndGet() == 6) {
                            try {
                                MatchedElfAllocationsFixtures.write(pair.original(), table.offset, mutated);
                                Files.setLastModifiedTime(pair.original(), time);
                                written[0] = true;
                            }
                            catch (IOException problem) {
                                throw new AssertionError(problem);
                            }
                        }
                        return false;
                    }));
                require(written[0] && Files.size(pair.original()) == before.length &&
                    Files.getLastModifiedTime(pair.original()).equals(time), "between-read rewrite did not occur");
                String expected = aggregate ? "raw section names exceed aggregate reread limit 16777216"
                    : "raw section name exceeds reread limit 65536";
                require(failure.getMessage().equals(expected) && failure.getCause() == null,
                    "raw resource control failed for another reason: " + failure);
                require(!Arrays.equals(before, Files.readAllBytes(pair.original())), "rewrite control is vacuous");
            }
            finally {
                Files.write(pair.original(), before);
                Files.setLastModifiedTime(pair.original(), time);
            }
            unchangedMatch(pair);
        }
    }

    private static void issue(Result result, Status status, String field) {
        require(result.status() == status && result.issue().isPresent() && result.issue().get().field().equals(field),
            "wrong result: " + result + " expected " + status + "/" + field);
    }

    private static byte[] digest(Path path) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path));
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) {
            throw new AssertionError(message);
        }
    }

    @FunctionalInterface
    private interface Checked {
        void run() throws Exception;
    }

    private static Exception expect(Class<? extends Exception> type, Checked action) throws Exception {
        try {
            action.run();
        }
        catch (Exception failure) {
            require(type.isInstance(failure), "wrong exception: " + failure);
            return failure;
        }
        throw new AssertionError("expected " + type.getName());
    }
}
