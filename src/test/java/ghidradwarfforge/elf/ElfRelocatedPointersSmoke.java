package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CancellationException;

/** Candidate metadata is not proof of runtime immutability. */
public final class ElfRelocatedPointersSmoke {
    private static int checks;
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
    private static ByteBuffer buffer(byte[] bytes) { return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN); }
    private static void segment(ByteBuffer b, int index, int type, int flags, long offset, long address, long file, long memory) {
        int at = 64 + 56 * index;
        b.putInt(at, type).putInt(at + 4, flags).putLong(at + 8, offset).putLong(at + 16, address)
            .putLong(at + 24, address).putLong(at + 32, file).putLong(at + 40, memory).putLong(at + 48, 1);
    }
    private static byte[] fixture(int machine, int type) {
        var b = ByteBuffer.allocate(0x1000).order(ByteOrder.LITTLE_ENDIAN);
        b.put(new byte[] {0x7f, 'E', 'L', 'F', 2, 1, 1, 0});
        b.putShort(16, (short) 3).putShort(18, (short) machine).putInt(20, 1).putLong(32, 64)
            .putShort(52, (short) 64).putShort(54, (short) 56).putShort(56, (short) 3).putShort(58, (short) 64);
        segment(b, 0, 1, 6, 0, 0x1000, 0x1000, 0x2000);
        segment(b, 1, 2, 6, 0x200, 0x1200, 64, 64);
        segment(b, 2, 0x6474e552, 4, 0x800, 0x1800, 8, 8);
        b.putLong(0x200, 7).putLong(0x208, 0x1400).putLong(0x210, 8).putLong(0x218, 24)
            .putLong(0x220, 9).putLong(0x228, 24);
        b.putLong(0x400, 0x1800).putLong(0x408, type).putLong(0x410, 0x2100);
        b.putLong(0x800, 0xdeadbeef); // RELA uses its explicit addend, not these initial bytes.
        return b.array();
    }
    private static List<ElfRelocatedPointers.Pointer> inspect(Path path, byte[] bytes) throws Exception {
        Files.write(path, bytes);
        var before = Files.readAttributes(path, BasicFileAttributes.class);
        try { return ElfRelocatedPointers.inspect(ElfImage.read(path), () -> false); }
        finally {
            var after = Files.readAttributes(path, BasicFileAttributes.class);
            require(Arrays.equals(bytes, Files.readAllBytes(path)) &&
                java.util.Objects.equals(before.fileKey(), after.fileKey()) &&
                before.lastModifiedTime().equals(after.lastModifiedTime()), "pointer inspection modified the original ELF");
        }
    }
    private static String digest(byte[] bytes, int offset) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Arrays.copyOfRange(bytes, offset, offset + 8)));
    }
    private static void admissionBoundaries(Path path, int machine, int type) throws Exception {
        byte[] original = fixture(machine, type);
        var expected = inspect(path, original);
        for (long base : new long[] {Long.MAX_VALUE - 0x807, 0xffff_ffff_8100_0000L, -0x2000L}) {
            byte[] bytes = original.clone();
            var b = buffer(bytes);
            segment(b, 0, 1, 6, 0, base, 0x1000, 0x2000);
            segment(b, 1, 2, 6, 0x200, base + 0x200, 64, 64);
            segment(b, 2, 0x6474e552, 4, 0x800, base + 0x800, 16, 16);
            b.putLong(0x208, base + 0x400).putLong(0x218, 48);
            b.putLong(0x400, base + 0x808).putLong(0x410, base + 0x1fff);
            b.putLong(0x418, base + 0x800).putLong(0x420, type).putLong(0x428, base);
            require(inspect(path, bytes).equals(List.of(
                new ElfRelocatedPointers.Pointer(base + 0x800, base, 0x418, 0x800, digest(bytes, 0x800)),
                new ElfRelocatedPointers.Pointer(base + 0x808, base + 0x1fff, 0x400, 0x808, digest(bytes, 0x808)))),
                "relocated slots lost unsigned order, target values or file coordinates");
        }
        for (String shape : List.of("rel", "relr", "none", "absolute", "relro-after-slot", "duplicate-relro",
                "write-only-slot", "target-before-load", "ambiguous-target", "unreadable-target", "bss-slot")) {
            byte[] bytes = original.clone(); var b = buffer(bytes);
            switch (shape) {
                case "rel" -> b.putLong(0x200, 17).putLong(0x210, 18).putLong(0x218, 16)
                    .putLong(0x220, 19).putLong(0x228, 16);
                case "relr" -> b.putLong(0x200, 36).putLong(0x210, 35).putLong(0x218, 8)
                    .putLong(0x220, 37).putLong(0x228, 8);
                case "none" -> b.putLong(0x408, 0);
                case "absolute" -> b.putLong(0x408, machine == 62 ? 1 : 257);
                case "relro-after-slot" -> segment(b, 2, 0x6474e552, 4, 0x801, 0x1801, 8, 8);
                case "duplicate-relro" -> {
                    b.putShort(56, (short) 4);
                    segment(b, 3, 0x6474e552, 4, 0x800, 0x1800, 8, 8);
                }
                case "write-only-slot" -> {
                    b.putInt(68, 2).putLong(104, 0x1000).putShort(56, (short) 4);
                    segment(b, 3, 1, 4, 0, 0x2100, 0, 0x100);
                }
                case "target-before-load" -> b.putLong(0x410, 0xfff);
                case "ambiguous-target" -> {
                    b.putShort(56, (short) 4);
                    segment(b, 3, 1, 4, 0, 0x2100, 0, 0x100);
                }
                case "unreadable-target" -> {
                    b.putLong(104, 0x1000).putShort(56, (short) 4);
                    segment(b, 3, 1, 2, 0, 0x2100, 0, 0x100);
                }
                case "bss-slot" -> {
                    b.putLong(0x400, 0x2100);
                    segment(b, 2, 0x6474e552, 4, 0, 0x2100, 0, 8);
                }
                default -> throw new AssertionError(shape);
            }
            require(inspect(path, bytes).isEmpty(), "unqualified pointer admitted: " + shape);
        }
        for (long target : new long[] {0x1000, 0x1fff, 0x2000, 0x2fff}) {
            byte[] bytes = original.clone(); buffer(bytes).putLong(0x410, target);
            require(inspect(path, bytes).equals(List.of(new ElfRelocatedPointers.Pointer(
                0x1800, target, 0x400, 0x800, digest(bytes, 0x800)))), "target load/BSS boundary lost: " + target);
        }
        for (long neighbor : new long[] {0x17f8, 0x1808}) {
            byte[] bytes = original.clone(); var b = buffer(bytes);
            b.putLong(0x218, 48).putLong(0x418, neighbor).putLong(0x420, type).putLong(0x428, 0x2100);
            require(inspect(path, bytes).equals(expected), "adjacent non-overlapping writer rejected");
        }
        for (int count : new int[] {1, 63, 64, 65}) {
            byte[] bytes = Arrays.copyOf(original, 0x4000); var b = buffer(bytes);
            segment(b, 0, 1, 6, 0, 0x1000, bytes.length, 0x5000);
            segment(b, 2, 0x6474e552, 4, 0x2000, 0x3000, count * 8L, count * 8L);
            b.putLong(0x218, count * 24L);
            for (int index = 0; index < count; index++) {
                int ordinal = count - index - 1;
                int record = 0x400 + index * 24;
                b.putLong(record, 0x3000 + ordinal * 8L).putLong(record + 8, type)
                    .putLong(record + 16, 0x5100 + ordinal * 8L);
                b.putLong(0x2000 + ordinal * 8, 0x12345678abcdef00L + ordinal);
            }
            if (count > 64) {
                try { inspect(path, bytes); throw new AssertionError("65 relative pointers accepted"); }
                catch (IllegalArgumentException expectedFailure) {
                    require(expectedFailure.getMessage().contains("candidate budget exceeded"), expectedFailure.toString());
                }
                continue;
            }
            List<ElfRelocatedPointers.Pointer> actual;
            try { actual = inspect(path, bytes); }
            catch (IllegalArgumentException invalid) {
                throw new AssertionError("valid bounded pointer inventory was rejected: " + count, invalid);
            }
            require(actual.size() == count, "exact pointer budget rejected");
            for (int index = 0; index < count; index++) {
                require(actual.get(index).equals(new ElfRelocatedPointers.Pointer(0x3000 + index * 8L,
                    0x5100 + index * 8L, 0x400 + (count - index - 1) * 24L, 0x2000 + index * 8L,
                    digest(bytes, 0x2000 + index * 8))), "pointer order/addend/source-byte identity mismatch");
            }
            try { actual.add(actual.getFirst()); throw new AssertionError("pointer inventory is mutable"); }
            catch (UnsupportedOperationException expectedFailure) { checks++; }
        }
    }
    public static void main(String[] args) throws Exception {
        Path path = Files.createTempFile("forge-pointer-inventory-", ".elf");
        try {
            for (int machine : List.of(62, 183)) {
                int type = machine == 62 ? 8 : 1027;
                admissionBoundaries(path, machine, type);
                byte[] original = fixture(machine, type);
                var pointers = inspect(path, original);
                require(pointers.size() == 1, "qualified relative slot lost");
                var pointer = pointers.getFirst();
                require(pointer.address() == 0x1800 && pointer.value() == 0x2100 && pointer.recordOffset() == 0x400 &&
                    pointer.fileOffset() == 0x800 && pointer.storedSha256().length() == 64, "pointer coordinates/addend wrong");
                for (String fault : List.of("no-relro", "short-relro", "outside-target", "negative-addend", "executable-slot", "partial-file")) {
                    byte[] changed = original.clone(); var b = buffer(changed);
                    switch (fault) {
                        case "no-relro" -> b.putShort(56, (short) 2);
                        case "short-relro" -> b.putLong(64 + 112 + 40, 7).putLong(64 + 112 + 32, 7);
                        case "outside-target" -> b.putLong(0x410, 0x3000);
                        case "negative-addend" -> b.putLong(0x410, -1);
                        case "executable-slot" -> b.putInt(68, 7);
                        case "partial-file" -> b.putLong(96, 0x804);
                        default -> throw new AssertionError(fault);
                    }
                    require(inspect(path, changed).isEmpty(), "unqualified candidate accepted: " + fault);
                }
                byte[] duplicate = original.clone(); var b = buffer(duplicate);
                b.putLong(0x218, 48).putLong(0x418, 0x1800).putLong(0x420, type).putLong(0x428, 0x2100);
                try { inspect(path, duplicate); throw new AssertionError("overlapping loader writes accepted"); }
                catch (IllegalArgumentException expected) { require(expected.getMessage().contains("overlapping loader writes"), expected.toString()); }
                Files.write(path, original); var image = ElfImage.read(path); int[] polls = {0};
                require(ElfRelocatedPointers.inspect(image, () -> { polls[0]++; return false; }).equals(pointers), "counting changed inventory");
                for (int stop = 1; stop <= polls[0]; stop++) {
                    int selected = stop; int[] count = {0};
                    try {
                        ElfRelocatedPointers.inspect(image, () -> ++count[0] == selected);
                        throw new AssertionError("pointer inventory ignored cancellation");
                    }
                    catch (CancellationException expected) { checks++; }
                }
                require(ElfRelocatedPointers.inspect(image, () -> false).equals(pointers), "cancelled inventory poisoned retry");
            }
        }
        finally { Files.delete(path); }
        System.out.println("elf-relocated-pointers=PASS checks=" + checks);
    }
}
