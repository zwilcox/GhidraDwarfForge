package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.CancellationException;

/** Independent ELF carriers and recorded GCC attributes, including contradictory inputs. */
public final class CortexM3ProfileSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path path = Files.createTempFile("forge-cortex-profile-", ".elf");
        try {
            byte[] gcc = HexFormat.of().parseHex(
                "412e000000616561626900012400000005436f727465782d4d3300060a074d0902120414011501170318011a012201");
            accept(path, image(gcc, 0x05000200));
            for (int thumb : new int[] {2, 3}) {
                accept(path, image(attributes(6, 10, 7, 77, 9, thumb), 0x05000000));
            }
            for (int arch : new int[] {0, 9, 11, 12, 13, 16, 17, 21}) {
                reject(path, image(attributes(6, arch, 7, 77, 9, 2), 0x05000000), "ARMv7-M");
            }
            for (int profile : new int[] {0, 65, 82, 83}) {
                reject(path, image(attributes(6, 10, 7, profile, 9, 2), 0x05000000), "ARMv7-M");
            }
            for (int thumb : new int[] {0, 1, 4}) {
                reject(path, image(attributes(6, 10, 7, 77, 9, thumb), 0x05000000), "Thumb");
            }
            reject(path, image(attributes(6, 10, 7, 77, 9, 2, 8, 1), 0x05000000), "ARM-state");
            for (int tag : new int[] {10, 11, 12, 27, 28, 29, 36, 42, 46, 48, 50, 52, 66, 68, 70}) {
                reject(path, image(attributes(6, 10, 7, 77, 9, 2, tag, 1), 0x05000000), "attribute " + tag);
            }
            reject(path, image(attributes(6, 10, 7, 77, 9, 2, 64, 0), 0x05000000), "nodefaults");
            reject(path, image(attributes(6, 10, 7, 77, 9, 2, 65, 0), 0x05000000), "alternate");
            reject(path, image(attributes(6, 10, 7, 77, 9, 2, 6, 10), 0x05000000), "duplicate");
            reject(path, image(attributes(6, 10, 7, 77, 9, 2, 54, 0), 0x05000000), "mandatory");
            for (int flags : new int[] {0, 0x04000000, 0x05000400, 0x05000600, 0x05800000}) {
                reject(path, image(gcc, flags), "flags");
            }
            for (int length = 0; length < gcc.length; length++) {
                reject(path, image(Arrays.copyOf(gcc, length), 0x05000200), "Cortex-M3");
            }
            byte[] absent = image(gcc, 0x05000200);
            ByteBuffer.wrap(absent).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(32, 0).putShort(46, (short) 0).putShort(48, (short) 0).putShort(50, (short) 0);
            reject(path, absent, "attribute section");
            for (int offset : new int[] {7, 8}) {
                byte[] osabi = image(gcc, 0x05000200);
                osabi[offset] = 3;
                reject(path, osabi, "System V");
            }
            byte[] shared = image(gcc, 0x05000200);
            shared[16] = 3;
            reject(path, shared, "ET_EXEC");
            Files.write(path, image(gcc, 0x05000200));
            try {
                CortexM3Profile.requireImage(ElfImage.read(path), () -> true);
                throw new AssertionError("cancelled profile scan accepted");
            }
            catch (CancellationException expected) { checks++; }
        }
        finally { Files.delete(path); }
        System.out.println("cortex-m3-profile=PASS checks=" + checks);
    }

    private static void accept(Path path, byte[] bytes) throws Exception {
        Files.write(path, bytes);
        CortexM3Profile.requireImage(ElfImage.read(path), () -> false);
        if (!Arrays.equals(bytes, Files.readAllBytes(path))) throw new AssertionError("input changed");
        checks++;
    }

    private static void reject(Path path, byte[] bytes, String reason) throws Exception {
        Files.write(path, bytes);
        ElfImage image = ElfImage.read(path);
        try {
            CortexM3Profile.requireImage(image, () -> false);
            throw new AssertionError("incompatible Cortex-M3 profile accepted: " + reason);
        }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains(reason)) throw new AssertionError(expected);
            checks++;
        }
        if (!Arrays.equals(bytes, Files.readAllBytes(path))) throw new AssertionError("input changed");
    }

    private static byte[] attributes(int... payload) {
        var out = ByteBuffer.allocate(16 + payload.length).order(ByteOrder.LITTLE_ENDIAN);
        out.put((byte) 'A').putInt(15 + payload.length).put("aeabi\0".getBytes(StandardCharsets.US_ASCII));
        out.put((byte) 1).putInt(5 + payload.length);
        for (int value : payload) out.put((byte) value);
        return out.array();
    }

    public static byte[] image(byte[] attributes, int flags) {
        byte[] strings = "\0.shstrtab\0.ARM.attributes\0".getBytes(StandardCharsets.US_ASCII);
        int table = (52 + attributes.length + strings.length + 3) & ~3;
        var out = ByteBuffer.allocate(table + 120).order(ByteOrder.LITTLE_ENDIAN);
        out.put(new byte[] {0x7f, 'E', 'L', 'F', 1, 1, 1});
        out.putShort(16, (short) 2).putShort(18, (short) 40).putInt(20, 1);
        out.putInt(36, flags).putShort(40, (short) 52);
        out.putInt(32, table).putShort(46, (short) 40).putShort(48, (short) 3).putShort(50, (short) 1);
        out.position(52); out.put(attributes).put(strings);
        out.putInt(table + 40, 1).putInt(table + 44, 3).putInt(table + 56, 52 + attributes.length);
        out.putInt(table + 60, strings.length).putInt(table + 72, 1);
        out.putInt(table + 80, 11).putInt(table + 84, 0x70000003).putInt(table + 96, 52);
        out.putInt(table + 100, attributes.length).putInt(table + 112, 1);
        return out.array();
    }
}
