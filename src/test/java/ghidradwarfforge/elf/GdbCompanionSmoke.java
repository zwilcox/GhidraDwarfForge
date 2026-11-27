package ghidradwarfforge.elf;

import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.ArrayList;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Compiler DWARF in the production matched writer; not Ghidra extraction. */
public final class GdbCompanionSmoke {
    private GdbCompanionSmoke() {
    }

    public static void main(String[] args) throws Exception {
        identityBoundaries();
        if (args.length == 0) return;
        if (args.length != 5) {
            throw new IllegalArgumentException("original reference source sidecar companion required");
        }
        Path original = Path.of(args[0]);
        Path reference = Path.of(args[1]);
        Path source = Path.of(args[2]);
        Path sidecar = Path.of(args[3]);
        Path companion = Path.of(args[4]);
        if (Files.exists(sidecar) || Files.exists(companion)) {
            throw new IllegalArgumentException("smoke output paths must be new");
        }
        ElfImage compiler = ElfImage.read(reference);
        Map<String, byte[]> sections = new LinkedHashMap<>();
        for (var section : compiler.sections()) {
            if (section.name.startsWith(".debug_")) {
                sections.put(section.name, compiler.sectionData(section));
            }
        }
        new MatchedElfSidecarWriter().write(original, sidecar, sections);
        String first = GdbCompanion.render(original, sidecar, source, sidecar, source, () -> false);
        String second = GdbCompanion.render(original, sidecar, source, sidecar, source, () -> false);
        if (!first.equals(second)) {
            throw new AssertionError("companion is not deterministic");
        }
        Map<Path, byte[]> protectedFiles = new LinkedHashMap<>();
        for (Path path : new Path[] {original, reference, source, sidecar}) {
            protectedFiles.put(path, Files.readAllBytes(path));
        }
        var checkpoints = new AtomicInteger();
        String counted = GdbCompanion.render(original, sidecar, source, sidecar, source, () -> {
            checkpoints.incrementAndGet();
            return false;
        });
        if (!first.equals(counted) || checkpoints.get() < 2) {
            throw new AssertionError("missing successful cancellation-check baseline");
        }
        for (int stop = 1; stop <= checkpoints.get(); stop++) {
            final int selected = stop;
            var observed = new AtomicInteger();
            try {
                GdbCompanion.render(original, sidecar, source, sidecar, source,
                    () -> observed.incrementAndGet() == selected);
                throw new AssertionError("companion ignored cancellation at checkpoint " + stop);
            }
            catch (CancellationException expected) {
                if (observed.get() != stop) throw new AssertionError("cancellation was not prompt");
            }
            unchanged(protectedFiles, companion);
        }
        for (char unsafe : new char[] {'\n', '\r', '\t', 127}) {
            for (boolean invalidSidecar : new boolean[] {true, false}) {
                Path invalid = sidecar.resolveSibling("unsafe" + unsafe + "name");
                try {
                    GdbCompanion.render(original, sidecar, source,
                        invalidSidecar ? invalid : sidecar, invalidSidecar ? source : invalid, () -> false);
                    throw new AssertionError("unsafe final pathname accepted");
                }
                catch (java.io.IOException expected) {
                    if (!expected.getMessage().contains("unsupported pathname")) throw expected;
                }
                if (Files.exists(invalid)) throw new AssertionError("invalid destination was created");
                unchanged(protectedFiles, companion);
            }
        }
        try {
            GdbCompanion.render(original, reference, source, sidecar, source, () -> false);
            throw new AssertionError("unmatched compiler reference accepted as Forge sidecar");
        }
        catch (java.io.IOException expected) {
            // A matching machine or copied DWARF alone is not a matched sidecar.
        }
        unchanged(protectedFiles, companion);
        if (!first.equals(GdbCompanion.render(original, sidecar, source, sidecar, source, () -> false))) {
            throw new AssertionError("failed attempts changed the successful retry");
        }
        Files.writeString(companion, first, StandardCharsets.UTF_8);
        System.out.println("gdb-companion-smoke=PASS cancellation-checkpoints=" + checkpoints.get() + " invalid-paths=8");
    }

    private record Load(long offset, long address, int size, int flags) { }

    /** Independent ELF metadata fixtures; these are identity-policy tests, not runnable programs. */
    private static void identityBoundaries() throws Exception {
        Path root = Files.createTempDirectory("forge-companion-identity-");
        try {
            for (boolean wide : new boolean[] {false, true}) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    Path directory = Files.createDirectory(root.resolve(wide + "-" + order));
                    int header = wide ? 64 : 52;
                    // The header is mapped read-only, and independent immutable payload bytes are executable.
                    var loads = List.of(new Load(0, 0x10000, header, 4), new Load(256, 0x20100, 16, 5));
                    String manifest = identityCase(directory, "ordinary", wide, order, loads, null);
                    byte[] original = Files.readAllBytes(directory.resolve("ordinary"));
                    String expected = "\"checks\":[" + probe(original, 0, 0x10000, wide ? 40 : 32) + "," +
                        probe(original, wide ? 48 : 36, wide ? 0x10030 : 0x10024, 10) + "," +
                        probe(original, 256, 0x20100, 16) + "]";
                    if (!manifest.contains(expected)) throw new AssertionError("incorrect immutable header/payload probes " + manifest);
                    if (!manifest.contains("\"address_bits\":" + (wide ? 64 : 32))) throw new AssertionError("wrong manifest pointer width");
                    if (wide) {
                        String upper = identityCase(directory, "upper", true, order,
                            List.of(new Load(0, Long.MAX_VALUE - 31, header, 4), new Load(256, -16L, 16, 5)), null);
                        if (!upper.contains("[256,18446744073709551600,16,16]") ||
                                !upper.contains("\"address\":9223372036854775824,") ||
                                !upper.contains("\"address\":18446744073709551600,")) {
                            throw new AssertionError("incorrect unsigned LOAD or runtime probe address: " + upper);
                        }
                    }
                    // With neither sections nor LOADs, correspondence refuses missing allocation evidence first.
                    identityCase(directory, "no-loads", wide, order, List.of(), "matched Forge sidecar");
                    identityCase(directory, "data-only", wide, order,
                        List.of(new Load(256, 0x20100, 16, 4)), "bounded immutable executable identity evidence");
                    identityCase(directory, "empty-executable", wide, order,
                        List.of(new Load(0, 0x10000, header, 4), new Load(256, 0x20100, 0, 5)),
                        "bounded immutable executable identity evidence");
                    identityCase(directory, "writable-executable", wide, order,
                        List.of(new Load(256, 0x20100, 16, 7)), "writable executable LOAD bytes");
                    // Both accepted and refused bounds use only kilobytes; no giant file or sparse allocation.
                    var bounded = new ArrayList<Load>();
                    bounded.add(new Load(65536, 0x20000, 1, 5));
                    for (int i = 1; i < 1024; i++) bounded.add(new Load(65536, 0x20000, 0, 4));
                    identityCase(directory, "maximum-loads", wide, order, bounded, null);
                    bounded.add(new Load(65536, 0x20000, 0, 4));
                    identityCase(directory, "too-many-loads", wide, order, bounded, "bounded ELF LOAD table");
                    // Two independent immutable header spans per view: exactly 1024 probes, then 1026.
                    var probes = new ArrayList<Load>();
                    for (int i = 0; i < 512; i++) probes.add(new Load(0, 0x10000, header, 5));
                    identityCase(directory, "maximum-probes", wide, order, probes, null);
                    probes.add(new Load(0, 0x10000, header, 5));
                    identityCase(directory, "too-many-probes", wide, order, probes,
                        "bounded immutable executable identity evidence");
                    System.out.println("gdb-companion-identity=PASS elf64=" + wide + " order=" + order);
                }
            }
            // Repeated views exceed the runtime hash budget using a two-MiB owned file.
            var oversized = new ArrayList<Load>();
            for (int i = 0; i < 513; i++) oversized.add(new Load(65536, 0x20000, 2 * 1024 * 1024, 5));
            identityCase(root, "runtime-budget", true, ByteOrder.LITTLE_ENDIAN, oversized, "runtime identity checks exceed 1 GiB");
            System.out.println("gdb-companion-identity-budget=PASS");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static String identityCase(Path root, String name, boolean wide, ByteOrder order,
            List<Load> loads, String refusal) throws Exception {
        int header = wide ? 64 : 52;
        int stride = wide ? 56 : 32;
        int size = header + stride * loads.size();
        for (Load load : loads) size = Math.max(size, Math.toIntExact(load.offset() + load.size()));
        byte[] bytes = new byte[size];
        for (int i = header + stride * loads.size(); i < size; i++) bytes[i] = (byte) (i * 13 + 7);
        ByteBuffer fields = ByteBuffer.wrap(bytes).order(order);
        fields.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1});
        fields.putShort(16, (short) 2).putShort(18, (short) (wide ? 62 : 3)).putInt(20, 1);
        word(fields, wide ? 32 : 28, loads.isEmpty() ? 0 : header, wide);
        fields.putShort(wide ? 52 : 40, (short) header).putShort(wide ? 54 : 42, (short) stride)
            .putShort(wide ? 56 : 44, (short) loads.size()).putShort(wide ? 58 : 46, (short) (wide ? 64 : 40));
        for (int i = 0; i < loads.size(); i++) {
            Load load = loads.get(i);
            int at = header + stride * i;
            fields.putInt(at, 1);
            fields.putInt(at + (wide ? 4 : 24), load.flags());
            word(fields, at + (wide ? 8 : 4), load.offset(), wide);
            word(fields, at + (wide ? 16 : 8), load.address(), wide);
            word(fields, at + (wide ? 24 : 12), load.address(), wide);
            word(fields, at + (wide ? 32 : 16), load.size(), wide);
            word(fields, at + (wide ? 40 : 20), load.size(), wide);
            word(fields, at + (wide ? 48 : 28), 1, wide);
        }
        Path target = root.resolve(name), sidecar = root.resolve(name + ".dbg"), source = root.resolve(name + ".c");
        Files.write(target, bytes);
        Files.writeString(source, "/* Synthetic identity-policy fixture. */\n");
        new MatchedElfSidecarWriter().write(target, sidecar, Map.of(".debug_str", new byte[] {0}));
        byte[] sidecarBefore = Files.readAllBytes(sidecar), sourceBefore = Files.readAllBytes(source);
        String rendered = null;
        try {
            rendered = GdbCompanion.render(target, sidecar, source, sidecar, source, () -> false);
            if (refusal != null) throw new AssertionError("accepted unsafe identity layout: " + name);
        }
        catch (java.io.IOException failure) {
            if (refusal == null || !failure.getMessage().contains(refusal)) throw failure;
        }
        if (!Arrays.equals(bytes, Files.readAllBytes(target)) || !Arrays.equals(sidecarBefore, Files.readAllBytes(sidecar)) ||
                !Arrays.equals(sourceBefore, Files.readAllBytes(source))) throw new AssertionError("identity check changed input: " + name);
        if (rendered == null) return null;
        String prefix = "manifest = json.loads(base64.b64decode('";
        int start = rendered.indexOf(prefix) + prefix.length();
        if (start < prefix.length()) throw new AssertionError("missing companion manifest");
        return new String(Base64.getDecoder().decode(rendered.substring(start, rendered.indexOf("'", start))), StandardCharsets.UTF_8);
    }

    private static void word(ByteBuffer fields, int offset, long value, boolean wide) {
        if (wide) fields.putLong(offset, value); else fields.putInt(offset, (int) value);
    }

    private static String probe(byte[] original, int offset, long address, int size) throws Exception {
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(Arrays.copyOfRange(original, offset, offset + size)));
        return "{\"address\":" + address + ",\"size\":" + size + ",\"sha256\":\"" + hash + "\"}";
    }

    private static void unchanged(Map<Path, byte[]> protectedFiles, Path companion) throws Exception {
        for (var entry : protectedFiles.entrySet()) {
            if (!Arrays.equals(entry.getValue(), Files.readAllBytes(entry.getKey()))) {
                throw new AssertionError("companion attempt modified " + entry.getKey());
            }
        }
        if (Files.exists(companion)) throw new AssertionError("failed attempt published a companion");
    }
}
