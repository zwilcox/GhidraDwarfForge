package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
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
        return ElfRelocatedPointers.inspect(ElfImage.read(path), () -> false);
    }
    public static void main(String[] args) throws Exception {
        Path path = Files.createTempFile("forge-pointer-inventory-", ".elf");
        try {
            for (int machine : List.of(62, 183)) {
                int type = machine == 62 ? 8 : 1027;
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
