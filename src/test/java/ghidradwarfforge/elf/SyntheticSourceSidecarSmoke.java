package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Actual producer ELF input; independent Python validators and debuggers consume the output. */
public final class SyntheticSourceSidecarSmoke {
    private SyntheticSourceSidecarSmoke() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("input output source-directory");
        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        String directory = args[2];
        byte[] original = Files.readAllBytes(input);
        AtomicInteger visits = new AtomicInteger();
        var plan = SyntheticSourceSidecar.prepare(input, directory,
            () -> { visits.incrementAndGet(); return false; });
        int prepareChecks = visits.get();
        try (var stage = FileChannel.open(output, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            plan.writeStage(stage, () -> { visits.incrementAndGet(); return false; });
        }
        byte[] result = Files.readAllBytes(output);
        if (result.length != plan.outputSize()) throw new AssertionError("output size mismatch");
        Path scratch = output.resolveSibling(output.getFileName() + ".control");
        Path malformed = output.resolveSibling(output.getFileName() + ".malformed");
        if (Files.exists(scratch) || Files.exists(malformed)) throw new AssertionError("control paths already exist");
        for (int iteration = 0; iteration < 2; iteration++) {
            var repeated = SyntheticSourceSidecar.prepare(iteration == 0 ? input : output, directory, () -> false);
            try (var stage = FileChannel.open(scratch, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                repeated.writeStage(stage, () -> false);
            }
            if (!Arrays.equals(result, Files.readAllBytes(scratch))) throw new AssertionError("non-deterministic/non-idempotent relocation");
            Files.delete(scratch);
        }
        // Every cooperative boundary in planning and writing. The unpublished
        // stage belongs to this harness and is removed after each cancellation.
        for (int stop = 1; stop <= visits.get(); stop++) {
            int selected = stop;
            AtomicInteger current = new AtomicInteger();
            try {
                var candidate = SyntheticSourceSidecar.prepare(input, directory,
                    () -> current.incrementAndGet() == selected);
                try (var stage = FileChannel.open(scratch, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                    candidate.writeStage(stage, () -> current.incrementAndGet() == selected);
                }
                throw new AssertionError("missed cancellation " + stop);
            }
            catch (CancellationException expected) { }
            finally { Files.deleteIfExists(scratch); }
        }
        Files.write(scratch, new byte[] { 37 }, StandardOpenOption.CREATE_NEW);
        try (var stage = FileChannel.open(scratch, StandardOpenOption.WRITE)) {
            try { plan.writeStage(stage, () -> false); throw new AssertionError("nonempty stage accepted"); }
            catch (IllegalArgumentException expected) { }
        }
        if (!Arrays.equals(Files.readAllBytes(scratch), new byte[] { 37 })) throw new AssertionError("nonempty stage modified");
        Files.delete(scratch);
        ElfImage image = ElfImage.read(input);
        var info = image.sections().stream().filter(s -> s.name.equals(".debug_info")).findFirst().orElseThrow();
        var abbrev = image.sections().stream().filter(s -> s.name.equals(".debug_abbrev")).findFirst().orElseThrow();
        var line = image.sections().stream().filter(s -> s.name.equals(".debug_line")).findFirst().orElseThrow();
        ByteBuffer header = ByteBuffer.wrap(original).order(image.byteOrder());
        long table = image.is64Bit() ? header.getLong(40) : Integer.toUnsignedLong(header.getInt(32));
        int stride = Short.toUnsignedInt(header.getShort(image.is64Bit() ? 58 : 46));
        int infoHeader = Math.toIntExact(table + (long) stride * info.originalIndex);
        int otherHeader = Math.toIntExact(table + (long) stride * abbrev.originalIndex);
        List<byte[]> refusals = new ArrayList<>();
        byte[] duplicate = original.clone();
        ByteBuffer.wrap(duplicate).order(image.byteOrder()).putInt(otherHeader, (int) info.nameOffset);
        refusals.add(duplicate);
        byte[] allocated = original.clone();
        ByteBuffer.wrap(allocated).order(image.byteOrder()).putInt(infoHeader + (image.is64Bit() && image.byteOrder() == java.nio.ByteOrder.BIG_ENDIAN ? 12 : 8), (int) info.flags | 2);
        refusals.add(allocated);
        // A different, non-source section avoids an earlier required-section refusal.
        var spare = image.sections().stream().filter(s -> s.type == 1 && !s.name.startsWith(".debug_") && s.size > 0).findFirst().orElseThrow();
        int spareHeader = Math.toIntExact(table + (long) stride * spare.originalIndex);
        byte[] relocation = original.clone();
        ByteBuffer rel = ByteBuffer.wrap(relocation).order(image.byteOrder());
        rel.putInt(spareHeader + 4, 9).putInt(spareHeader + (image.is64Bit() ? 44 : 28), info.originalIndex);
        refusals.add(relocation);
        byte[] overlap = original.clone();
        ByteBuffer overlapFields = ByteBuffer.wrap(overlap).order(image.byteOrder());
        if (image.is64Bit()) overlapFields.putLong(spareHeader + 24, infoHeader + 24).putLong(spareHeader + 32, 1);
        else overlapFields.putInt(spareHeader + 16, infoHeader + 16).putInt(spareHeader + 20, 1);
        refusals.add(overlap);
        if ((line.flags & 0x800) != 0) {
            int payload = Math.toIntExact(line.offset);
            for (int position : new int[] { payload, payload + (image.is64Bit() ? 8 : 4), payload + (image.is64Bit() ? 24 : 12) }) {
                byte[] invalid = original.clone(); invalid[position] ^= 0x40; refusals.add(invalid);
            }
        }
        for (byte[] invalid : refusals) {
            Files.write(malformed, invalid, StandardOpenOption.CREATE_NEW);
            try {
                SyntheticSourceSidecar.prepare(malformed, directory, () -> false);
                throw new AssertionError("malformed sidecar accepted");
            }
            catch (IllegalArgumentException expected) { }
            finally { Files.delete(malformed); }
        }
        if (!Arrays.equals(original, Files.readAllBytes(input))) throw new AssertionError("input changed");
        Files.writeString(output.resolveSibling(output.getFileName() + ".source.json"),
            "{\"scope\":\"unpublished stage only\",\"prepareChecks\":" + prepareChecks + "}\n");
        System.out.printf("source-sidecar-smoke=PASS refusals=%d cancellation=%d%n", refusals.size() + 1, visits.get());
    }
}
