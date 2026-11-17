package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Frame diagnostics need exact independent original-image and byte corroboration. */
public final class InheritedFrameBytesSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-inherited-frame-");
        try {
            for (boolean wide : List.of(false, true)) {
                for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) check(root, wide, order);
            }
        }
        finally { Files.delete(root); }
        System.out.println("inherited-frame-bytes=PASS checks=" + checks);
    }

    static void check(Path root, boolean wide, ByteOrder order) throws Exception {
        Path original = root.resolve("inherited-original"), sidecar = root.resolve("inherited-sidecar");
        byte[] sectionless = SectionlessUnwindSmoke.fixture(wide, order, 0x3b);
        byte[] named = named(sectionless, wide, order);
        byte[] matched = named.clone();
        var fields = ByteBuffer.wrap(matched).order(order);
        if (wide) fields.putLong(32, 0).putShort(54, (short) 0).putShort(56, (short) 0);
        else fields.putInt(28, 0).putShort(42, (short) 0).putShort(44, (short) 0);
        System.arraycopy(matched, 0x300, matched, 0x600, 44);
        section(fields, wide, "offset", 0x600);
        try {
            for (boolean missingHeaders : List.of(false, true)) {
                byte[] input = missingHeaders ? sectionless : named;
                // The named section includes its four-byte terminator; program
                // headers prove only the CIE/FDE records ending at byte 40.
                int extent = missingHeaders ? 40 : 44;
                section(fields, wide, "size", extent);
                Files.write(original, input); Files.write(sidecar, matched);
                var polls = new AtomicInteger();
                var evidence = InheritedFrameBytes.compare(original, sidecar, () -> { polls.incrementAndGet(); return false; });
                String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Arrays.copyOfRange(input, 0x300, 0x300 + extent)));
                require(evidence.address() == 0x4300 && evidence.bytes() == extent && evidence.originalOffset() == 0x300 &&
                    evidence.fromProgramHeaders() == missingHeaders && evidence.sha256().equals(hash), "exact original evidence and discovery path");
                for (int stop = 1; stop <= polls.get(); stop++) {
                    int at = stop;
                    var current = new AtomicInteger();
                    try {
                        InheritedFrameBytes.compare(original, sidecar, () -> current.incrementAndGet() == at);
                        throw new AssertionError("frame corroboration ignored cancellation");
                    }
                    catch (CancellationException expected) { require(current.get() == at, "cancel promptly"); }
                    unchanged(original, input, sidecar, matched);
                }
                require(InheritedFrameBytes.compare(original, sidecar, () -> false).equals(evidence), "cancellation poisoned subsequent evidence");
                for (String fault : List.of("ident", "type", "machine", "flags", "address", "section-flags", "extent", "payload",
                        "missing", "duplicate", "section-type", "empty")) {
                    byte[] bad = matched.clone();
                    var b = ByteBuffer.wrap(bad).order(order);
                    String diagnostic = "section identities differ";
                    switch (fault) {
                        case "ident" -> { bad[7] ^= 1; diagnostic = "ELF identities differ"; }
                        case "type" -> { b.putShort(16, (short) 3); diagnostic = "ELF identities differ"; }
                        case "machine" -> { b.putShort(18, (short) (b.getShort(18) + 1)); diagnostic = "ELF identities differ"; }
                        case "flags" -> { b.putInt(wide ? 48 : 36, b.getInt(wide ? 48 : 36) ^ 1); diagnostic = "ELF identities differ"; }
                        case "address" -> section(b, wide, "address", 0x4301);
                        case "section-flags" -> section(b, wide, "flags", 3);
                        case "extent" -> section(b, wide, "size", extent - 1);
                        case "payload" -> { bad[0x610] ^= 1; diagnostic = "frame bytes differ"; }
                        case "missing" -> { section(b, wide, "name", 0); diagnostic = "one bounded nonempty"; }
                        case "duplicate" -> {
                            int stride = wide ? 64 : 40;
                            System.arraycopy(bad, 0x900 + stride, bad, 0x900 + 3 * stride, stride);
                            b.putShort(wide ? 60 : 48, (short) 4);
                            diagnostic = "one bounded nonempty";
                        }
                        case "section-type" -> { section(b, wide, "type", 8); diagnostic = "one bounded nonempty"; }
                        case "empty" -> { section(b, wide, "size", 0); diagnostic = "one bounded nonempty"; }
                        default -> throw new AssertionError(fault);
                    }
                    Files.write(sidecar, bad);
                    reject(original, sidecar, diagnostic);
                    unchanged(original, input, sidecar, bad);
                }
                Files.write(sidecar, matched);
                require(InheritedFrameBytes.compare(original, sidecar, () -> false).equals(evidence), "restored sidecar changed corroboration");
            }
            // No section table and no program-header frame source is not evidence.
            byte[] undiscovered = sectionless.clone();
            var b = ByteBuffer.wrap(undiscovered).order(order);
            if (wide) b.putLong(32, 0).putShort(54, (short) 0).putShort(56, (short) 0);
            else b.putInt(28, 0).putShort(42, (short) 0).putShort(44, (short) 0);
            Files.write(original, undiscovered);
            reject(original, sidecar, "program headers do not establish frame records");
            unchanged(original, undiscovered, sidecar, matched);
        }
        finally { Files.deleteIfExists(original); Files.deleteIfExists(sidecar); }
    }

    private static byte[] named(byte[] input, boolean wide, ByteOrder order) {
        byte[] result = Arrays.copyOf(input, 0x1000);
        var b = ByteBuffer.wrap(result).order(order);
        byte[] names = "\0.eh_frame\0.shstrtab\0".getBytes(StandardCharsets.US_ASCII);
        b.position(0xb00); b.put(names);
        if (wide) b.putLong(40, 0x900).putShort(58, (short) 64).putShort(60, (short) 3).putShort(62, (short) 2);
        else b.putInt(32, 0x900).putShort(46, (short) 40).putShort(48, (short) 3).putShort(50, (short) 2);
        section(b, wide, "name", 1); section(b, wide, "type", 1); section(b, wide, "flags", 2);
        section(b, wide, "address", 0x4300); section(b, wide, "offset", 0x300); section(b, wide, "size", 44);
        int at = 0x900 + 2 * (wide ? 64 : 40);
        b.putInt(at, 11).putInt(at + 4, 3);
        if (wide) b.putLong(at + 24, 0xb00).putLong(at + 32, names.length);
        else b.putInt(at + 16, 0xb00).putInt(at + 20, names.length);
        return result;
    }

    private static void section(ByteBuffer b, boolean wide, String field, long value) {
        int index = List.of("name", "type", "flags", "address", "offset", "size").indexOf(field);
        int at = 0x900 + (wide ? 64 : 40) + (index < 2 ? index * 4 : 8 + (index - 2) * (wide ? 8 : 4));
        if (wide && index >= 2) b.putLong(at, value); else b.putInt(at, (int) value);
    }
    private static void reject(Path original, Path sidecar, String diagnostic) throws Exception {
        try {
            InheritedFrameBytes.compare(original, sidecar, () -> false);
            throw new AssertionError("uncorroborated frame accepted: " + diagnostic);
        }
        catch (IOException expected) { require(expected.getMessage().contains(diagnostic), "wrong frame refusal: " + expected); }
    }
    private static void unchanged(Path original, byte[] before, Path sidecar, byte[] after) throws Exception {
        require(Arrays.equals(before, Files.readAllBytes(original)) && Arrays.equals(after, Files.readAllBytes(sidecar)),
            "corroboration changed input or sidecar");
    }
    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
