package ghidradwarfforge.elf;

import ghidradwarfforge.output.FileDigests;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.zip.CRC32;

import static ghidradwarfforge.elf.OwnedDebuglinkCandidateFixtures.*;

/** Native-free raw layout, preserved input and exact owned-lifecycle controls. */
public final class OwnedDebuglinkCandidateSmoke {
    private static final byte[] BASENAME = {'f', 'o', 'r', 'g', 'e', '.', 'd', 'b', 'g'};
    private static int checks;

    private OwnedDebuglinkCandidateSmoke() { }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-owned-candidate-test-");
        try {
            for (boolean wide : new boolean[] {false, true}) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    Input input = create(root.resolve(wide + "-" + order), wide, order);
                    positive(input, BASENAME);
                    changed(input, () -> write(input.original(), 16, shortBytes(3, order)), () -> positive(input, BASENAME));
                    changed(input, () -> field(input, 4, 8, 8, 2, true), () -> positive(input, BASENAME));
                    byte[] raw = {(byte) 0xff, '\\', (byte) 0x80};
                    positive(input, raw);
                    byte[] maximum = new byte[65536];
                    Arrays.fill(maximum, (byte) 'x');
                    positive(input, maximum);
                    negatives(input);
                    for (int count : new int[] {0xfefe, 0xfeff}) {
                        changed(input, () -> extendSections(input, count), () -> positive(input, BASENAME));
                    }
                    changed(input, () -> extendedPrograms(input), () -> positive(input, BASENAME));
                }
            }
            arithmetic();
            Input input = create(root.resolve("lifecycle"), true, ByteOrder.LITTLE_ENDIAN);
            lifecycle(input);
            metadataRaces(input);
            aggregateNames(input);
            paths(input);
            if (Arrays.asList(args).contains("--large")) { large(root.resolve("large")); }
            System.out.println("owned-debuglink-candidate-smoke=PASS checks=" + checks);
        }
        finally { removeTree(root); }
    }

    private static void positive(Input input, byte[] basename) throws Exception {
        byte[] old = Files.readAllBytes(input.original());
        byte[] sidecar = Files.readAllBytes(input.sidecar());
        FileTime originalTime = Files.getLastModifiedTime(input.original());
        FileTime sidecarTime = Files.getLastModifiedTime(input.sidecar());
        var a = OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), basename, input.parent());
        var b = OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), basename, input.parent());
        try {
            require(!a.directory().equals(b.directory()), "scratch directories reused");
            require(a.directory().getParent().equals(input.parent().toRealPath()), "wrong workspace parent");
            require(a.candidate().equals(a.directory().resolve("candidate.elf")), "wrong fixed leaf");
            require(Files.mismatch(a.candidate(), b.candidate()) == -1, "candidate bytes nondeterministic");
            require(a.content().equals(b.content()), "construction observations nondeterministic");
            checkRaw(input, old, basename, a.candidate());
            require(Arrays.equals(old, Files.readAllBytes(input.original())), "original changed");
            require(Arrays.equals(sidecar, Files.readAllBytes(input.sidecar())), "sidecar changed");
            require(originalTime.equals(Files.getLastModifiedTime(input.original())), "original time changed");
            require(sidecarTime.equals(Files.getLastModifiedTime(input.sidecar())), "sidecar time changed");
        }
        finally { remove(a); remove(b); }
    }

    private static void checkRaw(Input input, byte[] original, byte[] basename, Path candidate) throws Exception {
        byte[] data = Files.readAllBytes(candidate);
        boolean wide = input.wide();
        ByteBuffer old = ByteBuffer.wrap(original).order(input.order());
        ByteBuffer b = ByteBuffer.wrap(data).order(input.order());
        int e = input.entrySize();
        int oldTable = (int) value(old, wide ? 40 : 32, wide);
        int oldCount = Short.toUnsignedInt(old.getShort(wide ? 60 : 48));
        if (oldCount == 0) { oldCount = (int) value(old, oldTable + (wide ? 32 : 20), wide); }
        int oldNameIndex = Short.toUnsignedInt(old.getShort(wide ? 62 : 50));
        if (oldNameIndex == 0xffff) { oldNameIndex = old.getInt(oldTable + (wide ? 40 : 24)); }
        int oldNameRow = oldTable + oldNameIndex * e;
        int oldNamesOffset = (int) value(old, oldNameRow + (wide ? 24 : 16), wide);
        int oldNamesLength = (int) value(old, oldNameRow + (wide ? 32 : 20), wide);
        int linkOffset = (original.length + 3) & ~3;
        int linkSize = ((basename.length + 4) & ~3) + 4;
        byte[] literals = ".gnu_debuglink\0.shstrtab\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        int namesOffset = linkOffset + linkSize;
        int namesSize = oldNamesLength + literals.length;
        int tableOffset = (namesOffset + namesSize + (wide ? 7 : 3)) & ~(wide ? 7 : 3);
        require(value(b, wide ? 40 : 32, wide) == tableOffset, "wrong appended SHT offset");
        require(data.length == tableOffset + (oldCount + 2) * e, "wrong final size");
        require(Short.toUnsignedInt(b.getShort(wide ? 58 : 46)) == e, "e_shentsize changed");
        require(Short.toUnsignedInt(b.getShort(wide ? 60 : 48)) == (oldCount + 2 >= 0xff00 ? 0 : oldCount + 2), "count escape");
        require(Short.toUnsignedInt(b.getShort(wide ? 62 : 50)) == (oldCount + 1 >= 0xff00 ? 0xffff : oldCount + 1), "name escape");
        for (int at = 0; at < original.length; at++) {
            boolean masked = wide ? (at >= 40 && at < 48) || (at >= 60 && at < 64) :
                (at >= 32 && at < 36) || (at >= 48 && at < 52);
            if (!masked && original[at] != data[at]) { throw new AssertionError("prefix byte " + at); }
        }
        checks++;
        byte[] expectedRows = Arrays.copyOfRange(original, oldTable, oldTable + oldCount * e);
        ByteBuffer zero = ByteBuffer.wrap(expectedRows).order(input.order());
        word(zero, wide ? 32 : 20, oldCount + 2 >= 0xff00 ? oldCount + 2 : 0, wide);
        zero.putInt(wide ? 40 : 24, oldCount + 1 >= 0xff00 ? oldCount + 1 : 0);
        require(Arrays.equals(expectedRows, Arrays.copyOfRange(data, tableOffset, tableOffset + expectedRows.length)), "old raw records not retained");
        require(Arrays.equals(Arrays.copyOfRange(original, oldNamesOffset, oldNamesOffset + oldNamesLength),
            Arrays.copyOfRange(data, namesOffset, namesOffset + oldNamesLength)), "raw old names changed");
        require(Arrays.equals(literals, Arrays.copyOfRange(data, namesOffset + oldNamesLength, namesOffset + namesSize)), "new raw literals");
        byte[] link = Arrays.copyOf(basename, linkSize);
        CRC32 crc = new CRC32();
        crc.update(Files.readAllBytes(input.sidecar()));
        ByteBuffer.wrap(link).order(input.order()).putInt(linkSize - 4, (int) crc.getValue());
        require(Arrays.equals(link, Arrays.copyOfRange(data, linkOffset, linkOffset + linkSize)), "literal link payload");
        for (int at = original.length; at < linkOffset; at++) { require(data[at] == 0, "link alignment pad"); }
        for (int at = namesOffset + namesSize; at < tableOffset; at++) { require(data[at] == 0, "SHT alignment pad"); }
        byte[] last = new byte[2 * e];
        ByteBuffer rows = ByteBuffer.wrap(last).order(input.order());
        section(rows, 0, wide, oldNamesLength, 1, 0, 0, linkOffset, linkSize, 0, 0, 4, 0);
        section(rows, e, wide, oldNamesLength + 15, 3, 0, 0, namesOffset, namesSize, 0, 0, 1, 0);
        require(Arrays.equals(last, Arrays.copyOfRange(data, tableOffset + oldCount * e, data.length)), "new record fields");
        require(value(b, tableOffset + (wide ? 44 : 28), false) == value(old, oldTable + (wide ? 44 : 28), false), "PN_XNUM sh_info changed");
    }

    private static void negatives(Input input) throws Exception {
        changed(input, () -> write(input.original(), 16, shortBytes(1, input.order())), () -> rejected(input));
        changed(input, () -> write(input.original(), NAMES, new byte[] {1}), () -> rejected(input));
        changed(input, () -> write(input.original(), NAMES + NAME_BYTES.length - 1, new byte[] {1}), () -> rejected(input));
        changed(input, () -> field(input, 4, 32, 20, 0, true), () -> rejected(input));
        changed(input, () -> write(input.original(), input.wide() ? 62 : 50, shortBytes(0, input.order())), () -> rejected(input));
        for (int[] positions : new int[][] {{32, 20}, {40, 24}, {44, 28}}) {
            changed(input, () -> field(input, 0, positions[0], positions[1], 1, positions[0] == 32), () -> rejected(input));
        }
        changed(input, () -> write(input.original(), input.wide() ? 58 : 46, shortBytes(input.entrySize() + 8, input.order())), () -> rejected(input));
        changed(input, () -> {
            write(input.original(), input.wide() ? 40 : 32, new byte[input.wide() ? 8 : 4]);
            write(input.original(), input.wide() ? 60 : 48, new byte[4]);
            require(ElfImage.read(input.original()).sections().isEmpty(), "sectionless control is malformed");
        }, () -> rejected(input));
        changed(input, () -> field(input, 1, 24, 16, 0x810, true), () -> rejected(input));
        changed(input, () -> {
            byte[] name = ".gnu_debuglink\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            write(input.original(), NAMES + 1, name);
        }, () -> rejected(input));
        changed(input, () -> {
            for (int index : new int[] {1, 2, 3}) { field(input, index, 8, 8, 0, true); }
        }, () -> rejected(input));
        changed(input, () -> write(input.original(), 0x100, ByteBuffer.allocate(4).order(input.order()).putInt(4).array()), () -> rejected(input));
        for (byte[] name : new byte[][] {new byte[0], {0}, {'/'}, {'.'}, {'.', '.'}, new byte[65537]}) {
            Throwable failure = failure(() -> OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), name, input.parent()));
            require(failure instanceof IllegalArgumentException, "basename argument classification");
            empty(input.parent());
        }
    }

    private static void arithmetic() throws Exception {
        for (boolean wide : new boolean[] {false, true}) {
            var small = OwnedDebuglinkCandidate.layout(wide, 0, 1, 1, 1);
            require(small.end() > 0, "zero input arithmetic");
            for (long size : new long[] {-1, Long.MAX_VALUE, Long.MAX_VALUE - 7}) {
                require(failure(() -> OwnedDebuglinkCandidate.layout(wide, size, 1, 1, 1)) instanceof IOException, "long overflow classification");
            }
            require(failure(() -> OwnedDebuglinkCandidate.layout(wide, 100, 1, 262143, 1)) instanceof IOException, "count limit");
            require(failure(() -> OwnedDebuglinkCandidate.layout(wide, 100, 16 * 1024 * 1024, 1, 1)) instanceof IOException, "names limit");
            var maximum = OwnedDebuglinkCandidate.layout(wide, 100, 16 * 1024 * 1024 - 25, 262142, 65536);
            require(maximum.count() == 262144 && maximum.namesSize() == 16 * 1024 * 1024, "exact metadata limits");
        }
        // Independent end equation: align4(input)+8+26, align4, plus3*40.
        long exactInput = 0x1_0000_0000L - 156;
        var exact = OwnedDebuglinkCandidate.layout(false, exactInput, 1, 1, 1);
        require(exact.end() == 0x1_0000_0000L, "exact 4GiB planning boundary");
        require(failure(() -> OwnedDebuglinkCandidate.layout(false, exactInput + 1, 1, 1, 1)) instanceof IOException, "over 4GiB planning boundary");
        require(OwnedDebuglinkCandidate.layout(true, exactInput + 1, 1, 1, 1).end() > 0x1_0000_0000L, "64-bit planning boundary");
    }

    private static void lifecycle(Input input) throws Exception {
        byte[] original = Files.readAllBytes(input.original());
        byte[] sidecar = Files.readAllBytes(input.sidecar());
        require(failure(() -> OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), BASENAME, input.parent(), () -> true)) instanceof CancellationException, "early cancellation");
        empty(input.parent());
        IOException open = new IOException("open marker");
        Tracking ops = new Tracking();
        ops.openFailure = open;
        require(failure(() -> call(input, () -> false, ops)) == open, "open exception identity");
        empty(input.parent());
        for (String phase : List.of("write", "read", "close")) {
            Tracking io = new Tracking();
            IOException marker = new IOException(phase + " marker");
            io.phase = phase;
            io.primary = marker;
            require(failure(() -> call(input, () -> false, io)) == marker, phase + " exception identity");
            require(io.channel != null && !io.channel.isOpen(), phase + " channel leaked");
            empty(input.parent());
        }
        Tracking both = new Tracking();
        both.phase = "write";
        both.primary = new IOException("write primary");
        both.closeFailure = new IOException("close suppressed");
        Throwable problem = failure(() -> call(input, () -> false, both));
        require(problem == both.primary && problem.getSuppressed().length == 1 && problem.getSuppressed()[0] == both.closeFailure, "read/close suppression");
        empty(input.parent());
        Tracking zeroWrite = new Tracking();
        zeroWrite.phase = "zero-write";
        require(failure(() -> call(input, () -> false, zeroWrite)) instanceof IOException && !zeroWrite.channel.isOpen(), "zero-progress write closure");
        empty(input.parent());
        Tracking zeroRead = new Tracking();
        zeroRead.phase = "zero-read";
        require(failure(() -> call(input, () -> false, zeroRead)) instanceof IOException && !zeroRead.channel.isOpen(), "zero-progress read closure");
        empty(input.parent());
        Tracking shortWrites = new Tracking();
        shortWrites.phase = "short-write";
        var shortResult = call(input, () -> false, shortWrites);
        checkRaw(input, original, BASENAME, shortResult.candidate());
        require(!shortWrites.channel.isOpen(), "short-write success left channel open");
        remove(shortResult);
        Tracking undefinedGaps = new Tracking();
        undefinedGaps.phase = "poison-gaps";
        var padded = call(input, () -> false, undefinedGaps);
        checkRaw(input, original, BASENAME, padded.candidate());
        remove(padded);
        Tracking collisionAtOpen = new Tracking();
        collisionAtOpen.collide = true;
        Throwable collide = failure(() -> call(input, () -> false, collisionAtOpen));
        require(collide instanceof java.nio.file.FileAlreadyExistsException && collide.getSuppressed().length == 1, "exclusive create failure identity");
        require(Arrays.equals(Files.readAllBytes(collisionAtOpen.path), new byte[] {91}), "unowned conflicting leaf deleted");
        Files.delete(collisionAtOpen.path); Files.delete(collisionAtOpen.path.getParent());
        Tracking cleanup = new Tracking();
        cleanup.phase = "write";
        cleanup.primary = new IOException("write primary");
        cleanup.deleteFailure = new IOException("delete marker");
        problem = failure(() -> call(input, () -> false, cleanup));
        require(problem == cleanup.primary && problem.getSuppressed().length == 2, "cleanup suppression count");
        require(problem.getSuppressed()[0].getCause() == cleanup.deleteFailure &&
            problem.getSuppressed()[0].getMessage().contains(cleanup.path.toString()), "cleanup retained-path evidence");
        require(Files.exists(cleanup.path), "failed cleanup lost owned evidence");
        Files.delete(cleanup.path); Files.delete(cleanup.path.getParent());
        Tracking callback = new Tracking();
        IllegalArgumentException callbackFailure = new IllegalArgumentException("supplier marker");
        require(failure(() -> call(input, () -> {
            if (callback.channel != null) { throw callbackFailure; }
            return false;
        }, callback)) == callbackFailure, "supplier exception identity");
        require(!callback.channel.isOpen(), "callback channel leaked");
        empty(input.parent());
        for (String predicate : List.of("program", "allocation", "debuglink")) {
            Tracking corrupt = new Tracking();
            corrupt.afterClose = () -> {
                byte[] bytes = Files.readAllBytes(corrupt.path);
                ByteBuffer header = ByteBuffer.wrap(bytes).order(input.order());
                long table = header.getLong(40);
                if (predicate.equals("program")) { write(corrupt.path, 0x200, new byte[] {77}); }
                else if (predicate.equals("allocation")) {
                    write(corrupt.path, table + 64 + 16, ByteBuffer.allocate(8).order(input.order()).putLong(0x400201).array());
                }
                else {
                    long payload = header.getLong((int) table + 8 * 64 + 24);
                    write(corrupt.path, payload, new byte[] {77});
                }
            };
            Throwable mismatch = failure(() -> call(input, () -> false, corrupt));
            require(mismatch instanceof IOException && mismatch.getMessage().contains(predicate), "construction predicate not enforced: " + predicate);
            require(!corrupt.channel.isOpen(), "postcondition channel leaked");
            empty(input.parent());
        }
        Tracking beforeFile = new Tracking();
        AtomicBoolean directorySeen = new AtomicBoolean();
        require(failure(() -> call(input, () -> {
            try (var paths = Files.list(input.parent())) {
                if (paths.findAny().isPresent()) { directorySeen.set(true); return true; }
            }
            catch (IOException error) { throw new AssertionError(error); }
            return false;
        }, beforeFile)) instanceof CancellationException && directorySeen.get() && beforeFile.channel == null, "directory-before-file cancellation");
        empty(input.parent());
        Tracking cancelled = new Tracking();
        require(failure(() -> call(input, () -> cancelled.channel != null, cancelled)) instanceof CancellationException, "copy cancellation");
        require(!cancelled.channel.isOpen(), "cancel channel leaked");
        empty(input.parent());
        Tracking late = new Tracking();
        AtomicBoolean finalPoll = new AtomicBoolean();
        require(failure(() -> call(input, () -> {
            boolean direct = StackWalker.getInstance().walk(s -> s.filter(f -> f.getClassName().equals(OwnedDebuglinkCandidate.class.getName()))
                .map(StackWalker.StackFrame::getMethodName).limit(2).toList()).equals(List.of("checkCancelled", "create"));
            if (late.channel != null && !late.channel.isOpen() && direct) { finalPoll.set(true); return true; }
            return false;
        }, late)) instanceof CancellationException && finalPoll.get(), "final postcondition cancellation");
        empty(input.parent());
        Tracking foreign = new Tracking();
        Throwable aborted = failure(() -> call(input, () -> {
            if (foreign.path != null) {
                try { Files.write(foreign.path.getParent().resolve("caller-evidence"), new byte[] {7}); }
                catch (IOException io) { throw new AssertionError(io); }
                return true;
            }
            return false;
        }, foreign));
        require(aborted instanceof CancellationException && aborted.getSuppressed().length == 1, "nonempty directory cleanup must be suppressed");
        require(!Files.exists(foreign.path) && Files.readAllBytes(foreign.path.getParent().resolve("caller-evidence"))[0] == 7, "cleanup recursively removed foreign file");
        Files.delete(foreign.path.getParent().resolve("caller-evidence")); Files.delete(foreign.path.getParent());
        // Two independently derived equal-length CRC32 collisions: link alone
        // would pass, but full selected digest must reject a changed sidecar.
        byte[] first = HexFormat.of().parseHex("fa3cfb3f1bb823aa");
        byte[] second = HexFormat.of().parseHex("af84d31d6d078015");
        CRC32 c1 = new CRC32(); c1.update(first);
        CRC32 c2 = new CRC32(); c2.update(second);
        require(c1.getValue() == c2.getValue() && !Arrays.equals(first, second), "CRC collision fixture vacuous");
        Files.write(input.sidecar(), first);
        Tracking collision = new Tracking();
        collision.afterClose = () -> Files.write(input.sidecar(), second);
        problem = failure(() -> call(input, () -> false, collision));
        require(problem instanceof IOException && problem.getMessage().equals("selected sidecar digest changed during candidate construction"), "full digest consistency not enforced");
        empty(input.parent());
        Files.write(input.sidecar(), sidecar);
        require(Arrays.equals(original, Files.readAllBytes(input.original())), "failure paths changed original");
        positive(input, BASENAME);
    }

    private static void metadataRaces(Input input) throws Exception {
        byte[] original = Files.readAllBytes(input.original());
        FileTime time = Files.getLastModifiedTime(input.original());
        Tracking changed = new Tracking();
        changed.beforeOpen = () -> {
            field(input, 5, 40, 24, 7, false);
            Files.setLastModifiedTime(input.original(), time);
        };
        try {
            Throwable mismatch = failure(() -> call(input, () -> false, changed));
            require(mismatch instanceof IOException && mismatch.getMessage().startsWith("copied original metadata differs from construction plan at "), "stale raw table plan accepted");
            require(!changed.channel.isOpen(), "stale plan leaked channel");
            empty(input.parent());
        }
        finally { Files.write(input.original(), original); Files.setLastModifiedTime(input.original(), time); }
        // Control the exact after-parse/before-plan poll, then replace a valid
        // short name with a >64KiB raw slice without changing size/mtime.
        byte[] larger = Arrays.copyOf(original, 0x18010);
        int namesLength = 65540;
        int namesOffset = 0x8000;
        ByteBuffer b = ByteBuffer.wrap(larger).order(input.order());
        word(b, TABLE + 4 * input.entrySize() + 24, namesOffset, true);
        word(b, TABLE + 4 * input.entrySize() + 32, namesLength, true);
        System.arraycopy(NAME_BYTES, 0, larger, namesOffset, NAME_BYTES.length);
        Files.write(input.original(), larger);
        FileTime largerTime = Files.getLastModifiedTime(input.original());
        AtomicBoolean mutated = new AtomicBoolean();
        try {
            Throwable bounds = failure(() -> OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), BASENAME, input.parent(), () -> {
                boolean inPlan = StackWalker.getInstance().walk(s -> s.anyMatch(f ->
                    f.getClassName().equals(OwnedDebuglinkCandidate.class.getName()) && f.getMethodName().equals("plan")));
                if (inPlan && mutated.compareAndSet(false, true)) {
                    byte[] corrupt = new byte[namesLength];
                    Arrays.fill(corrupt, (byte) 'x'); corrupt[0] = 0; corrupt[corrupt.length - 1] = 0;
                    try { write(input.original(), namesOffset, corrupt); Files.setLastModifiedTime(input.original(), largerTime); }
                    catch (IOException error) { throw new AssertionError(error); }
                }
                return false;
            }));
            require(mutated.get() && bounds instanceof IOException && bounds.getMessage().equals("raw section name exceeds 65536-byte safety limit"), "raw reread bound was not enforced directly");
            empty(input.parent());
        }
        finally { Files.write(input.original(), original); Files.setLastModifiedTime(input.original(), time); }
        // Post-parse cancellation callback exceptions are not malformed-ELF errors.
        IllegalArgumentException marker = new IllegalArgumentException("post-parse callback marker");
        java.util.concurrent.atomic.AtomicInteger polls = new java.util.concurrent.atomic.AtomicInteger();
        Throwable postParse = failure(() -> OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), BASENAME, input.parent(), () -> {
            boolean inRead = StackWalker.getInstance().walk(s -> s.anyMatch(f ->
                f.getClassName().equals(OwnedDebuglinkCandidate.class.getName()) && f.getMethodName().equals("read")));
            if (inRead && polls.incrementAndGet() == 2) { throw marker; }
            return false;
        }));
        require(postParse == marker && polls.get() == 2, "post-parse callback reclassified");
        empty(input.parent());
    }

    private static void paths(Input input) throws Exception {
        Path absent = input.parent().resolve("missing");
        require(failure(() -> OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), BASENAME, absent)) instanceof IOException, "missing parent");
        require(!Files.exists(absent), "parent created");
        require(failure(() -> OwnedDebuglinkCandidate.create(input.parent(), input.sidecar(), BASENAME, input.parent())) instanceof IOException, "directory input");
        require(failure(() -> OwnedDebuglinkCandidate.create(input.original(), input.parent(), BASENAME, input.parent())) instanceof IOException, "directory sidecar");
        var alias = OwnedDebuglinkCandidate.create(input.original(), input.original(), BASENAME, input.parent());
        remove(alias); // Read-only input aliases are allowed, never interpreted as identity.
        byte[] supplied = BASENAME.clone();
        AtomicBoolean changed = new AtomicBoolean();
        var cloned = OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), supplied, input.parent(), () -> {
            if (changed.compareAndSet(false, true)) { Arrays.fill(supplied, (byte) 'X'); }
            return false;
        });
        checkRaw(input, Files.readAllBytes(input.original()), BASENAME, cloned.candidate());
        remove(cloned);
        if (!System.getProperty("os.name").startsWith("Windows")) {
            Path actual = Files.createDirectories(input.parent().resolve("real/child"));
            Path link = input.parent().resolve("link");
            Files.createSymbolicLink(link, actual);
            Path inputLink = actual.getParent().resolve("alias.elf");
            Files.createSymbolicLink(inputLink, input.original());
            Path traversed = link.resolve("../alias.elf");
            require(Files.isSameFile(traversed, input.original()), "host traversal fixture");
            var result = OwnedDebuglinkCandidate.create(traversed, input.sidecar(), BASENAME, link.resolve(".."));
            require(result.directory().getParent().equals(link.resolve("..").toRealPath()), "parent lexical normalization");
            remove(result);
            Files.delete(inputLink); Files.delete(link); Files.delete(actual); Files.delete(actual.getParent());
        }
        empty(input.parent());
    }

    private static void aggregateNames(Input input) throws Exception {
        byte[] original = Files.readAllBytes(input.original());
        FileTime time = Files.getLastModifiedTime(input.original());
        int names = 0x10000;
        int nameSize = 65538;
        byte[] data = Arrays.copyOf(original, names + nameSize);
        ByteBuffer b = ByteBuffer.wrap(data).order(input.order());
        word(b, TABLE + 4 * input.entrySize() + 24, names, true);
        word(b, TABLE + 4 * input.entrySize() + 32, nameSize, true);
        Arrays.fill(data, names + 1, data.length - 1, (byte) 'x');
        Files.write(input.original(), data);
        try {
            positive(input, BASENAME); // First used raw slice has exactly65536 bytes.
            b.putShort(60, (short) 512);
            Arrays.fill(data, TABLE + 8 * input.entrySize(), TABLE + 512 * input.entrySize(), (byte) 0);
            for (int i = 0; i < 512; i++) {
                b.putInt(TABLE + i * input.entrySize(), i == 0 ? 0 : i * 2 - 1);
            }
            for (int at = 1; at < nameSize - 1; at++) { data[names + at] = (byte) ((at & 1) == 0 ? 0 : 'x'); }
            Files.write(input.original(), data);
            require(ElfImage.read(input.original()).sections().size() == 512, "aggregate precondition not parseable");
            FileTime stamp = Files.getLastModifiedTime(input.original());
            AtomicBoolean mutated = new AtomicBoolean();
            Throwable rejected = failure(() -> OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), BASENAME, input.parent(), () -> {
                boolean inPlan = StackWalker.getInstance().walk(s -> s.anyMatch(f ->
                    f.getClassName().equals(OwnedDebuglinkCandidate.class.getName()) && f.getMethodName().equals("plan")));
                if (inPlan && mutated.compareAndSet(false, true)) {
                    byte[] raw = new byte[nameSize];
                    Arrays.fill(raw, (byte) 'x'); raw[0] = 0; raw[raw.length - 1] = 0;
                    try { write(input.original(), names, raw); Files.setLastModifiedTime(input.original(), stamp); }
                    catch (IOException error) { throw new AssertionError(error); }
                }
                return false;
            }));
            require(mutated.get() && rejected instanceof IOException && rejected.getMessage().equals("appended decoded-name aggregate exceeds safety limit"), "direct aggregate reread guard vacuous");
            require(Files.getLastModifiedTime(input.original()).equals(stamp) && Files.size(input.original()) == data.length, "aggregate mutation metadata differs");
            empty(input.parent());
        }
        finally { Files.write(input.original(), original); Files.setLastModifiedTime(input.original(), time); }
    }

    private static void large(Path root) throws Exception {
        Input input = create(root, false, ByteOrder.BIG_ENDIAN);
        long length = 0x80010001L;
        write(input.original(), length - 1, new byte[] {(byte) 0xad});
        long sidecarLength = 0x80000011L;
        write(input.sidecar(), sidecarLength - 1, new byte[] {(byte) 0xf1});
        var before = FileDigests.read(input.original());
        var selected = FileDigests.read(input.sidecar());
        var result = OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), BASENAME, input.parent());
        try {
            require(Files.size(result.candidate()) > length, "large candidate missing tail");
            try (FileChannel file = FileChannel.open(result.candidate(), StandardOpenOption.READ)) {
                ByteBuffer tail = ByteBuffer.allocate(1);
                require(file.read(tail, length - 1) == 1 && tail.array()[0] == (byte) 0xad, "large copy high byte");
            }
            require(before.equals(FileDigests.read(input.original())), "large original changed");
            require(selected.equals(result.content().sidecarDigest()) && selected.equals(FileDigests.read(input.sidecar())), "large sidecar digest/preservation");
            require(prefixDifference(input, result.candidate(), length) == -1, "large full prefix differs");
            write(result.candidate(), length - 1, new byte[] {(byte) 0xae});
            require(prefixDifference(input, result.candidate(), length) == length - 1, "large high-offset negative vacuous");
            System.out.println("large-original-bytes=" + length + " candidate-bytes=" + Files.size(result.candidate()) + " sidecar-bytes=" + sidecarLength);
        }
        finally { remove(result); }
    }

    private static long prefixDifference(Input input, Path candidate, long length) throws IOException {
        try (FileChannel original = FileChannel.open(input.original(), StandardOpenOption.READ);
                FileChannel output = FileChannel.open(candidate, StandardOpenOption.READ)) {
            ByteBuffer a = ByteBuffer.allocate(65536);
            ByteBuffer b = ByteBuffer.allocate(65536);
            for (long at = 0; at < length;) {
                int count = (int) Math.min(a.capacity(), length - at);
                a.clear().limit(count); b.clear().limit(count);
                while (a.hasRemaining()) { if (original.read(a, at + a.position()) <= 0) { throw new IOException("original EOF"); } }
                while (b.hasRemaining()) { if (output.read(b, at + b.position()) <= 0) { throw new IOException("candidate EOF"); } }
                for (int i = 0; i < count; i++) {
                    long offset = at + i;
                    boolean exempt = input.wide() ? offset >= 40 && offset < 48 || offset >= 60 && offset < 64 :
                        offset >= 32 && offset < 36 || offset >= 48 && offset < 52;
                    if (!exempt && a.get(i) != b.get(i)) { return offset; }
                }
                at += count;
            }
            return -1;
        }
    }

    private static OwnedDebuglinkCandidate.Result call(Input input, BooleanSupplier cancelled, Tracking files) throws IOException {
        return OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), BASENAME, input.parent(), cancelled, files);
    }

    private static void rejected(Input input) throws Exception {
        byte[] before = Files.readAllBytes(input.original());
        require(failure(() -> OwnedDebuglinkCandidate.create(input.original(), input.sidecar(), BASENAME, input.parent())) instanceof IOException, "unsupported/malformed classification");
        require(Arrays.equals(before, Files.readAllBytes(input.original())), "rejected input changed");
        empty(input.parent());
    }

    private static void changed(Input input, Action mutation, Action test) throws Exception {
        byte[] original = Files.readAllBytes(input.original());
        try { mutation.run(); test.run(); }
        finally { Files.write(input.original(), original); }
    }

    private static long value(ByteBuffer b, int at, boolean wide) {
        return wide ? b.getLong(at) : Integer.toUnsignedLong(b.getInt(at));
    }
    private static byte[] shortBytes(int value, ByteOrder order) { return ByteBuffer.allocate(2).order(order).putShort((short) value).array(); }
    private static void empty(Path parent) throws IOException { try (var entries = Files.list(parent)) { require(entries.findAny().isEmpty(), "unexpected owned leftovers"); } }
    private static void remove(OwnedDebuglinkCandidate.Result result) throws IOException { Files.delete(result.candidate()); Files.delete(result.directory()); }
    private static void removeTree(Path root) throws IOException { try (var paths = Files.walk(root)) { for (Path p : paths.sorted(Comparator.reverseOrder()).toList()) { Files.deleteIfExists(p); } } }
    private static void require(boolean truth, String message) { if (!truth) { throw new AssertionError(message); } checks++; }
    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static Throwable failure(Action action) throws Exception {
        try { action.run(); } catch (IOException | RuntimeException failure) { return failure; }
        throw new AssertionError("expected failure");
    }

    private static final class Tracking implements OwnedDebuglinkCandidate.FileOperations {
        Path path;
        Tracked channel;
        String phase;
        IOException primary;
        IOException openFailure;
        IOException closeFailure;
        IOException deleteFailure;
        Action afterClose;
        Action beforeOpen;
        boolean collide;
        public FileChannel create(Path target) throws IOException {
            if (openFailure != null) { throw openFailure; }
            path = target;
            if (beforeOpen != null) {
                try { beforeOpen.run(); } catch (IOException error) { throw error; } catch (Exception error) { throw new IOException(error); }
            }
            if (collide) { Files.write(target, new byte[] {91}, StandardOpenOption.CREATE_NEW); }
            channel = new Tracked(FileChannel.open(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE), this);
            return channel;
        }
        public void delete(Path target) throws IOException {
            if (deleteFailure != null) { throw deleteFailure; }
            Files.deleteIfExists(target);
        }
    }

    private static final class Tracked extends FileChannel {
        final FileChannel delegate;
        final Tracking state;
        Tracked(FileChannel delegate, Tracking state) { this.delegate = delegate; this.state = state; }
        public int read(ByteBuffer b) throws IOException { return read(b, delegate.position()); }
        public int read(ByteBuffer b, long at) throws IOException { if ("read".equals(state.phase)) { throw state.primary; } if ("zero-read".equals(state.phase)) { return 0; } return delegate.read(b, at); }
        public long read(ByteBuffer[] b, int at, int count) throws IOException { return delegate.read(b, at, count); }
        public int write(ByteBuffer b) throws IOException { return written(b, null); }
        public int write(ByteBuffer b, long at) throws IOException { return written(b, at); }
        private int written(ByteBuffer b, Long at) throws IOException {
            if ("write".equals(state.phase)) { throw state.primary; }
            if ("zero-write".equals(state.phase)) { return 0; }
            if ("poison-gaps".equals(state.phase) && at != null && at > delegate.size()) {
                long gap = at - delegate.size();
                if (gap > 16) { throw new AssertionError("unexpected large append gap"); }
                byte[] poison = new byte[(int) gap]; Arrays.fill(poison, (byte) 0x5a);
                ByteBuffer fill = ByteBuffer.wrap(poison);
                long start = delegate.size();
                while (fill.hasRemaining()) { delegate.write(fill, start + fill.position()); }
            }
            int limit = b.limit();
            if ("short-write".equals(state.phase)) { b.limit(b.position() + Math.min(7, b.remaining())); }
            try { return at == null ? delegate.write(b) : delegate.write(b, at); }
            finally { b.limit(limit); }
        }
        public long write(ByteBuffer[] b, int at, int count) throws IOException { return delegate.write(b, at, count); }
        public long position() throws IOException { return delegate.position(); }
        public FileChannel position(long at) throws IOException { delegate.position(at); return this; }
        public long size() throws IOException { return delegate.size(); }
        public FileChannel truncate(long size) throws IOException { delegate.truncate(size); return this; }
        public void force(boolean metadata) throws IOException { delegate.force(metadata); }
        public long transferTo(long at, long count, WritableByteChannel target) throws IOException { return delegate.transferTo(at, count, target); }
        public long transferFrom(ReadableByteChannel source, long at, long count) throws IOException { return delegate.transferFrom(source, at, count); }
        public MappedByteBuffer map(MapMode mode, long at, long size) throws IOException { return delegate.map(mode, at, size); }
        public FileLock lock(long at, long size, boolean shared) throws IOException { return delegate.lock(at, size, shared); }
        public FileLock tryLock(long at, long size, boolean shared) throws IOException { return delegate.tryLock(at, size, shared); }
        protected void implCloseChannel() throws IOException {
            delegate.close();
            if (state.afterClose != null) {
                try { state.afterClose.run(); } catch (IOException e) { throw e; } catch (Exception e) { throw new IOException(e); }
            }
            if (state.closeFailure != null) { throw state.closeFailure; }
            if ("close".equals(state.phase)) { throw state.primary; }
        }
    }
}
