package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Independent mapping record/byte binding and inherited-symbol rejection controls. */
public final class Arm32SectionModesSmoke {
    public static final long START = 0x10100;
    public static final String CODE = "030080e204308fe2013083e213ff2fe1053000bf00a31847070080e204209fe5020080e01eff2fe134120000";
    private static int checks;

    public static byte[] fixture() {
        byte[] bytes = Arm32ModeSymbolsSmoke.fixture(1);
        var buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(0x300 + 40 + 20, 44);
        System.arraycopy(HexFormat.of().parseHex(CODE), 0, bytes, 0x100, 44);
        return bytes;
    }

    public static Arm32SectionModes.Evidence evidence() throws Exception {
        return new Arm32SectionModes.Evidence(1, START, 44,
            HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(HexFormat.of().parseHex(CODE))),
            List.of(new Arm32SectionModes.Boundary(0, 0), new Arm32SectionModes.Boundary(16, 1),
                new Arm32SectionModes.Boundary(24, 0), new Arm32SectionModes.Boundary(40, 2)));
    }

    public static void main(String[] args) throws Exception {
        evidenceBoundaries();
        Path root = Files.createTempDirectory("arm-section-modes-");
        Path input = root.resolve("input");
        byte[] bytes = fixture();
        Files.write(input, bytes);
        var image = ElfImage.read(input);
        var evidence = evidence();
        var messages = new ArrayList<String>();
        var symbols = Arm32SectionModes.plan(image, List.of(evidence), List.of(), () -> false, messages::add);
        require(symbols.size() == 4 && messages.isEmpty(), "complete mode/data sequence planned: " + messages);
        profileAndAllocations(root.resolve("profiles"), bytes, evidence, symbols);
        int[] visits = {0};
        require(Arm32SectionModes.plan(image, List.of(evidence), List.of(), () -> { visits[0]++; return false; },
            messages::add).equals(symbols), "counted mapping changed output");
        for (int stop = 1; stop <= visits[0]; stop++) {
            int selected = stop;
            int[] current = {0};
            try {
                Arm32SectionModes.plan(image, List.of(evidence), List.of(), () -> ++current[0] == selected, messages::add);
                throw new AssertionError("mapping ignored cancellation at " + stop);
            }
            catch (CancellationException expected) { checks++; }
            require(Arrays.equals(bytes, Files.readAllBytes(input)), "cancelled mapping changed original ELF");
        }
        require(Arm32SectionModes.plan(image, List.of(evidence), List.of(), () -> false, messages::add).equals(symbols),
            "cancelled mapping poisoned retry");
        var output = root.resolve("output.dbg");
        new MatchedElfSidecarWriter().write(image, output, Map.of(".debug_info", new byte[] { 1, 2, 3 }), symbols, () -> false);
        var parsed = ElfImage.read(output);
        var table = parsed.sections().stream().filter(s -> s.type == 2).findFirst().orElseThrow();
        var rows = ByteBuffer.wrap(parsed.sectionData(table)).order(ByteOrder.LITTLE_ENDIAN);
        require(table.info == 5 && rows.limit() == 80, "null plus four locals");
        for (int i = 0; i < 4; i++) {
            int at = (i + 1) * 16;
            require(Integer.toUnsignedLong(rows.getInt(at + 4)) == symbols.get(i).value() &&
                rows.getInt(at + 8) == 0 && rows.get(at + 12) == 0 && rows.get(at + 13) == 0 &&
                rows.getShort(at + 14) == 1, "zero-sized local NOTYPE with ordinary untagged address");
        }
        var repeat = root.resolve("repeat.dbg");
        new MatchedElfSidecarWriter().write(image, repeat, Map.of(".debug_info", new byte[] { 1, 2, 3 }), symbols, () -> false);
        require(Arrays.equals(Files.readAllBytes(output), Files.readAllBytes(repeat)), "deterministic writer output");
        require(Arrays.equals(bytes, Files.readAllBytes(input)), "original preserved");
        require(Arm32SectionModes.plan(parsed, List.of(evidence), List.of(), () -> false, messages::add).isEmpty()
            && messages.isEmpty(), "consistent original mappings retained without duplicates");
        var forged = new Arm32SectionModes.Evidence(1, START, 44, "0".repeat(64), evidence.boundaries());
        reject(image, List.of(forged), List.of(), "listing bytes differ");
        reject(image, List.of(evidence, evidence), List.of(), "duplicate section evidence");
        reject(image, List.of(new Arm32SectionModes.Evidence(1, START, 40, evidence.sha256(),
            evidence.boundaries().subList(0, 3))), List.of(), "extent or file backing");
        reject(image, List.of(evidence), List.of(new ElfLocalFunctionSymbol("wrong", START + 17, 4, 1),
            new ElfLocalFunctionSymbol("wrong_arm", START + 20, 4, 1)), "supplemental function tag");
        byte[] overlapping = bytes.clone();
        var overlapBytes = ByteBuffer.wrap(overlapping).order(ByteOrder.LITTLE_ENDIAN);
        overlapBytes.putInt(0x300 + 2 * 40 + 8, 2); // allocated data, not executable
        overlapBytes.putInt(0x300 + 2 * 40 + 12, (int) START + 8);
        Path overlap = root.resolve("overlap"); Files.write(overlap, overlapping);
        reject(ElfImage.read(overlap), List.of(evidence), List.of(), "overlapping allocated sections");
        var altered = new Arm32SectionModes.Evidence(1, START, 44, evidence.sha256(),
            List.of(new Arm32SectionModes.Boundary(0, 0), new Arm32SectionModes.Boundary(16, 2)));
        reject(parsed, List.of(altered), List.of(), "inherited mapping");
        byte[] malformed = Files.readAllBytes(output);
        malformed[(int) table.offset + 16 + 12] = 2;
        Path bad = root.resolve("bad"); Files.write(bad, malformed);
        reject(ElfImage.read(bad), List.of(evidence), List.of(), "malformed mapping symbol");
        var unaligned = new Arm32SectionModes.Evidence(1, START, 44, evidence.sha256(),
            List.of(new Arm32SectionModes.Boundary(0, 0), new Arm32SectionModes.Boundary(15, 2)));
        reject(image, List.of(unaligned), List.of(), "unaligned");
        for (int stop : new int[] { 1, 3, 10, 20 }) {
            var polls = new AtomicInteger();
            try {
                Arm32SectionModes.plan(image, List.of(evidence), List.of(), () -> polls.incrementAndGet() == stop, messages::add);
                throw new AssertionError("cancellation not observed at " + stop);
            }
            catch (CancellationException expected) { checks++; }
        }
        byte[] sentinel = { 7, 8, 9 }; Files.write(repeat, sentinel);
        try {
            new MatchedElfSidecarWriter().write(image, repeat, Map.of(),
                List.of(new ElfLocalMappingSymbol("$t.outside", START + 44, 1)), () -> false);
            throw new AssertionError("outside mapping accepted");
        }
        catch (IllegalArgumentException expected) { checks++; }
        require(Arrays.equals(Files.readAllBytes(repeat), sentinel), "invalid mapping preserves previous output");
        try { new ElfLocalFunctionSymbol("zero", START, 0, 1); throw new AssertionError("zero-sized function accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
        var failure = new IllegalArgumentException("diagnostic marker");
        try {
            Arm32SectionModes.plan(image, List.of(forged), List.of(), () -> false, message -> { throw failure; });
            throw new AssertionError("diagnostic callback swallowed");
        }
        catch (IllegalArgumentException actual) { require(actual == failure, "diagnostic failure identity"); }
        System.out.println("arm32-section-modes-smoke=PASS checks=" + checks);
    }

    private static void evidenceBoundaries() throws Exception {
        String hash = evidence().sha256();
        var one = List.of(new Arm32SectionModes.Boundary(0, 2));
        for (long[] extent : new long[][] {{0, 1}, {0xffffffffL, 1}, {1, 0xffffffffL}}) {
            try {
                var accepted = new Arm32SectionModes.Evidence(1, extent[0], extent[1], hash, one);
                require(accepted.address() == extent[0] && accepted.size() == extent[1], "32-bit extent changed");
            }
            catch (IllegalArgumentException failure) { throw new AssertionError("valid 32-bit extent rejected", failure); }
        }
        for (long[] invalid : new long[][] {{0, START, 44}, {-1, START, 44}, {1, -1, 44},
                {1, START, 0}, {1, START, -1}, {1, 0x1_0000_0000L, 1}, {1, 0xffffffffL, 2},
                {1, START, Long.MAX_VALUE}}) {
            invalidEvidence((int) invalid[0], invalid[1], invalid[2], hash, one, "invalid complete ARM section evidence");
        }
        for (String bad : Arrays.asList(null, "", "0".repeat(63), "0".repeat(65), "g".repeat(64), hash.toUpperCase(java.util.Locale.ROOT))) {
            invalidEvidence(1, START, 44, bad, one, "invalid complete ARM section evidence");
        }
        invalidEvidence(1, START, 44, hash, List.of(), "invalid complete ARM section evidence");
        invalidEvidence(1, START, 44, hash, List.of(new Arm32SectionModes.Boundary(1, 2)),
            "invalid complete ARM section evidence");
        for (long[] second : new long[][] {{0, 1}, {-1, 1}, {44, 1}, {45, 1}, {4, -1}, {4, 3}, {4, 2}}) {
            invalidEvidence(1, START, 44, hash, List.of(one.getFirst(), new Arm32SectionModes.Boundary(second[0], (int) second[1])),
                "invalid ARM section boundary sequence");
        }
        var boundaries = new ArrayList<Arm32SectionModes.Boundary>();
        for (int index = 0; index < 65536; index++) boundaries.add(new Arm32SectionModes.Boundary(2L * index, 1 + (index & 1)));
        Arm32SectionModes.Evidence maximum;
        try { maximum = new Arm32SectionModes.Evidence(1, START, 131074, hash, boundaries); }
        catch (IllegalArgumentException failure) { throw new AssertionError("exact boundary-count limit rejected", failure); }
        boundaries.add(new Arm32SectionModes.Boundary(131072, 1));
        invalidEvidence(1, START, 131074, hash, boundaries, "invalid complete ARM section evidence");
        boundaries.clear();
        require(maximum.boundaries().size() == 65536 && maximum.boundaries().getLast().offset() == 131070,
            "caller mutation changed retained boundary evidence");
        try { maximum.boundaries().clear(); throw new AssertionError("mutable boundary inventory"); }
        catch (UnsupportedOperationException expected) { checks++; }
    }

    private static void invalidEvidence(int section, long address, long size, String hash,
            List<Arm32SectionModes.Boundary> boundaries, String diagnostic) {
        try {
            new Arm32SectionModes.Evidence(section, address, size, hash, boundaries);
            throw new AssertionError("invalid mapping evidence accepted");
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().equals(diagnostic), "wrong evidence rejection: " + expected);
        }
    }

    private static void profileAndAllocations(Path input, byte[] original, Arm32SectionModes.Evidence evidence,
            List<ElfLocalMappingSymbol> expected) throws Exception {
        for (int[] profile : new int[][] {{18, 3}, {18, 183}, {16, 1}, {16, 4},
                {36, 0}, {36, 0x04000400}, {36, 0x06000400}, {36, 0x05800400}, {16, 3}}) {
            byte[] bytes = original.clone();
            var fields = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            if (profile[0] == 36) fields.putInt(36, profile[1]);
            else fields.putShort(profile[0], (short) profile[1]);
            Files.write(input, bytes);
            var image = ElfImage.read(input);
            var messages = new ArrayList<String>();
            require(Arm32SectionModes.plan(image, List.of(), List.of(), () -> false, messages::add).isEmpty()
                && messages.isEmpty(), "empty evidence acquired mappings or diagnostics");
            if (profile[0] == 16 && profile[1] == 3) {
                require(Arm32SectionModes.plan(image, List.of(evidence), List.of(), () -> false, messages::add).equals(expected)
                    && messages.isEmpty(), "ET_DYN mapping changed address or mode");
            }
            else reject(image, List.of(evidence), List.of(), "requires little-endian ELF32 EABI5");
            require(Arrays.equals(bytes, Files.readAllBytes(input)), "profile inspection changed ELF");
        }
        for (int[] allocation : new int[][] {{8, 0}, {8, 2}, {8, 4}, {8, 0x806}, {20, 0}, {4, 8}}) {
            byte[] bytes = original.clone();
            ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(0x300 + 40 + allocation[0], allocation[1]);
            Files.write(input, bytes);
            var image = ElfImage.read(input);
            var selected = Arm32SectionModes.allocations(image, () -> false);
            boolean noBacking = allocation[0] == 4;
            require(noBacking ? selected.size() == 1 && selected.getFirst().fileSize() == 0 : selected.isEmpty(),
                "incorrect executable allocation admission");
            reject(image, List.of(evidence), List.of(), noBacking ? "extent or file backing" : "missing unique executable allocation");
            require(Arrays.equals(bytes, Files.readAllBytes(input)), "allocation inspection changed ELF");
        }
    }

    private static void reject(ElfImage image, List<Arm32SectionModes.Evidence> evidence,
            List<ElfLocalFunctionSymbol> reserved, String reason) throws Exception {
        var messages = new ArrayList<String>();
        require(Arm32SectionModes.plan(image, evidence, reserved, () -> false, messages::add).isEmpty(), reason);
        require(messages.stream().anyMatch(m -> m.contains(reason)), reason + ": " + messages);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
