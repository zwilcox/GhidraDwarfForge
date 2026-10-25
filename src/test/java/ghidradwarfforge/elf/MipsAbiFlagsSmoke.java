package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;

/** Independent ELF carriers, metadata disagreement and profile exclusion controls. */
public final class MipsAbiFlagsSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("forge-mips-abi-");
        Path path = directory.resolve("fixture.elf");
        try {
            for (ByteOrder order : List.of(ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN)) {
                for (boolean elf64 : new boolean[] { false, true }) {
                    byte[] record = record(order);
                    for (int carrier = 1; carrier <= 3; carrier++) {
                        fixture(path, elf64, order, record, carrier);
                        var observed = unchanged(path, MipsAbiFlags.Status.AVAILABLE);
                        require(observed.fp32PairContract() == !elf64, "ELF class profile gate");
                        require(observed.fields().orElseThrow().fpAbi() == 1, "FP ABI byte");
                        require(observed.fields().orElseThrow().flags1() == 1, "target-endian word");
                    }
                    for (int byteIndex : new int[] { 2, 3, 4, 5, 6, 7, 8, 12, 20 }) {
                        byte[] changed = record.clone();
                        changed[byteIndex] = (byte) 0x80;
                        fixture(path, elf64, order, changed, 3);
                        require(!unchanged(path, MipsAbiFlags.Status.AVAILABLE).fp32PairContract(),
                            "unknown metadata selected a paired FP profile");
                    }
                    for (int abi : new int[] { 0, 2, 3, 4, 5, 6, 7, 255 }) {
                        byte[] changed = record.clone();
                        changed[7] = (byte) abi;
                        fixture(path, elf64, order, changed, 3);
                        var observed = unchanged(path, MipsAbiFlags.Status.AVAILABLE);
                        require(observed.fields().orElseThrow().fpAbi() == abi &&
                            !observed.fp32PairContract(), "FPXX/FP64/unknown misclassified as FP32");
                    }
                    var f = fixture(path, elf64, order, record, 3);
                    f.patch(f.section(1) + 8, elf64 ? 8 : 4, 0x802);
                    unchanged(path, MipsAbiFlags.Status.UNSUPPORTED);
                    f = fixture(path, elf64, order, record, 3);
                    f.patch(f.dataOffset(), 2, 1);
                    unchanged(path, MipsAbiFlags.Status.UNSUPPORTED);
                    fixture(path, elf64, order, Arrays.copyOf(record, 23), 3);
                    unchanged(path, MipsAbiFlags.Status.UNSUPPORTED);
                    fixture(path, elf64, order, Arrays.copyOf(record, 25), 3);
                    unchanged(path, MipsAbiFlags.Status.UNSUPPORTED);
                    f = fixture(path, elf64, order, record, 3);
                    f.patch(f.segment(0) + (elf64 ? 40 : 20), elf64 ? 8 : 4, 25);
                    unchanged(path, MipsAbiFlags.Status.UNSUPPORTED);
                    f = fixture(path, elf64, order, Arrays.copyOf(record, 48), 3);
                    f.patch(f.section(1) + (elf64 ? 32 : 20), elf64 ? 8 : 4, 24);
                    f.patch(f.segment(0) + (elf64 ? 32 : 16), elf64 ? 8 : 4, 24);
                    f.patch(f.segment(0) + (elf64 ? 40 : 20), elf64 ? 8 : 4, 24);
                    f.patch(f.segment(0) + (elf64 ? 8 : 4), elf64 ? 8 : 4, f.dataOffset() + 24);
                    unchanged(path, MipsAbiFlags.Status.AMBIGUOUS);
                    fixture(path, elf64, order, record, 0);
                    unchanged(path, MipsAbiFlags.Status.ABSENT);
                    f = fixture(path, elf64, order, record, 3);
                    f.patch(18, 2, 40);
                    unchanged(path, MipsAbiFlags.Status.NOT_MIPS);
                    for (long flags : new long[] { 0, 0x70000007, 0x70001027, 0x70001207,
                            0x70002007, 0x90001007, 0xf0001007L }) {
                        f = fixture(path, elf64, order, record, 3);
                        f.patch(elf64 ? 48 : 36, 4, flags);
                        require(!unchanged(path, MipsAbiFlags.Status.AVAILABLE).fp32PairContract(),
                            "unknown/contradictory ELF header selected FP32");
                    }
                    f = fixture(path, elf64, order, record, 3);
                    f.patch(16, 2, 1);
                    require(!unchanged(path, MipsAbiFlags.Status.AVAILABLE).fp32PairContract(),
                        "relocatable object selected executable profile");
                    var section = new ElfBuildIdFixtures.View(0, 24, 8, 0x7000002a, 2);
                    var segment = new ElfBuildIdFixtures.View(0, 24, 8, 0x70000003, 4);
                    for (boolean duplicateSections : new boolean[] { false, true }) {
                        var duplicate = ElfBuildIdFixtures.create(path, elf64, order, record,
                            duplicateSections ? List.of(section, section) : List.of(section),
                            duplicateSections ? List.of(segment) : List.of(segment, segment),
                            false, false, false, 0);
                        duplicate.patch(18, 2, 8);
                        unchanged(path, MipsAbiFlags.Status.AMBIGUOUS);
                    }
                }
            }
            fixture(path, false, ByteOrder.LITTLE_ENDIAN, record(ByteOrder.LITTLE_ENDIAN), 3);
            ElfImage image = ElfImage.read(path);
            try {
                MipsAbiFlags.observe(image, () -> true);
                throw new AssertionError("cancellation ignored");
            }
            catch (CancellationException expected) {
                checks++;
            }
            Files.setLastModifiedTime(path, FileTime.fromMillis(Files.getLastModifiedTime(path).toMillis() + 10000));
            try {
                MipsAbiFlags.observe(image, () -> false);
                throw new AssertionError("changed source read");
            }
            catch (IOException expected) {
                checks++;
            }
            for (String argument : args) {
                var original = ElfImage.read(Path.of(argument));
                var observed = MipsAbiFlags.observe(original, () -> false);
                require(observed.status() == MipsAbiFlags.Status.AVAILABLE, "compiler ABI metadata missing");
                System.out.println("mips-abi-observation=" + argument + " flags=" +
                    Long.toHexString(original.flags()) + " " + observed);
            }
        }
        finally {
            Files.deleteIfExists(path);
            Files.delete(directory);
        }
        System.out.println("mips-abi-flags-smoke=PASS checks=" + checks);
    }

    private static byte[] record(ByteOrder order) {
        return ByteBuffer.allocate(24).order(order).putShort((short) 0)
            .put(new byte[] { 32, 2, 1, 1, 0, 1 }).putInt(0).putInt(0).putInt(1).putInt(0).array();
    }

    private static ElfBuildIdFixtures.Fixture fixture(Path path, boolean elf64,
            ByteOrder order, byte[] bytes, int carrier) throws IOException {
        var f = ElfBuildIdFixtures.create(path, elf64, order, bytes,
            (carrier & 1) != 0 ? List.of(new ElfBuildIdFixtures.View(0, bytes.length, 8, 0x7000002a, 2)) : List.of(),
            (carrier & 2) != 0 ? List.of(new ElfBuildIdFixtures.View(0, bytes.length, 8, 0x70000003, 4)) : List.of(),
            false, false, false, 0);
        f.patch(18, 2, 8);
        f.patch(elf64 ? 48 : 36, 4, 0x70001007);
        return f;
    }

    private static MipsAbiFlags.Observation unchanged(Path path, MipsAbiFlags.Status status) throws IOException {
        byte[] before = Files.readAllBytes(path);
        var time = Files.getLastModifiedTime(path);
        var result = MipsAbiFlags.observe(ElfImage.read(path), () -> false);
        require(result.status() == status, "wrong observation " + result);
        require(result.equals(MipsAbiFlags.observe(ElfImage.read(path), () -> false)), "unstable observation");
        require(Arrays.equals(before, Files.readAllBytes(path)) && time.equals(Files.getLastModifiedTime(path)),
            "input mutated");
        return result;
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
