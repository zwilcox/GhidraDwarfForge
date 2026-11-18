package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.io.IOException;
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
        AtomicInteger comparisons = new AtomicInteger();
        plan.requireMatches(output, () -> { comparisons.incrementAndGet(); return false; });
        Path scratch = output.resolveSibling(output.getFileName() + ".control");
        Path malformed = output.resolveSibling(output.getFileName() + ".malformed");
        if (Files.exists(scratch) || Files.exists(malformed)) throw new AssertionError("control paths already exist");
        // A plausible ELF is insufficient: require the exact planned bytes,
        // including inherited contents, patched headers and appended payloads.
        for (int position : new int[] { 0, original.length / 2, result.length - 1 }) {
            byte[] altered = result.clone();
            altered[position] ^= 1;
            Files.write(scratch, altered, StandardOpenOption.CREATE_NEW);
            try {
                plan.requireMatches(scratch, () -> false);
                throw new AssertionError("accepted changed relocation byte " + position);
            }
            catch (IOException expected) {
                if (!expected.getMessage().contains("differs from relocation plan at byte " + position)) throw expected;
            }
            finally { Files.delete(scratch); }
        }
        for (int length : new int[] { result.length - 1, result.length + 1 }) {
            Files.write(scratch, Arrays.copyOf(result, length), StandardOpenOption.CREATE_NEW);
            try {
                plan.requireMatches(scratch, () -> false);
                throw new AssertionError("accepted changed relocation length");
            }
            catch (IOException expected) {
                if (!expected.getMessage().contains("length differs")) throw expected;
            }
            finally { Files.delete(scratch); }
        }
        for (int stop = 1; stop <= comparisons.get(); stop++) {
            int selected = stop;
            AtomicInteger current = new AtomicInteger();
            try {
                plan.requireMatches(output, () -> current.incrementAndGet() == selected);
                throw new AssertionError("missed comparison cancellation " + stop);
            }
            catch (CancellationException expected) { }
            if (!Arrays.equals(result, Files.readAllBytes(output))) throw new AssertionError("comparison modified candidate");
        }
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
        try (var stage = FileChannel.open(scratch, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            stage.position(1);
            try { plan.writeStage(stage, () -> false); throw new AssertionError("nonzero stage position accepted"); }
            catch (IllegalArgumentException expected) {
                if (!expected.getMessage().equals("source relocation needs an empty private stage")) throw expected;
            }
            if (stage.size() != 0 || stage.position() != 1) throw new AssertionError("refused stage was modified");
        }
        Files.delete(scratch);
        for (boolean append : new boolean[] { false, true }) {
            Files.write(scratch, result, StandardOpenOption.CREATE_NEW);
            AtomicInteger polls = new AtomicInteger();
            try {
                plan.requireMatches(scratch, () -> {
                    // The initial size check has passed; change the owned candidate
                    // at the first comparison-loop poll, before any payload read.
                    if (polls.incrementAndGet() == 2) {
                        try (var changed = FileChannel.open(scratch, StandardOpenOption.WRITE)) {
                            if (append) changed.write(ByteBuffer.wrap(new byte[] { 37 }), result.length);
                            else changed.truncate(result.length - 1);
                        }
                        catch (IOException failure) { throw new java.io.UncheckedIOException(failure); }
                    }
                    return false;
                });
                throw new AssertionError("candidate length change during comparison accepted");
            }
            catch (IOException expected) {
                String diagnostic = append ? "derived sidecar length changed during comparison" :
                    "source relocation comparison read made no progress";
                if (!expected.getMessage().equals(diagnostic)) throw expected;
                if (polls.get() < 2 || Files.size(scratch) != result.length + (append ? 1 : -1)) {
                    throw new AssertionError("comparison length-change control did not run");
                }
            }
            finally { Files.delete(scratch); }
        }
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
        int boundaries = metadataBoundaries(original, image, infoHeader, info, malformed, directory);
        if (!Arrays.equals(original, Files.readAllBytes(input))) throw new AssertionError("input changed");
        Files.writeString(output.resolveSibling(output.getFileName() + ".source.json"),
            "{\"scope\":\"unpublished stage only\",\"prepareChecks\":" + prepareChecks + "}\n");
        System.out.printf("source-sidecar-smoke=PASS refusals=%d cancellation=%d comparisonCancellation=%d%n",
            refusals.size() + 4 + boundaries, visits.get(), comparisons.get());
    }

    private record Refusal(byte[] bytes, String diagnostic) { }

    private static int metadataBoundaries(byte[] original, ElfImage image, int header,
            ElfImage.Section section, Path malformed, String directory) throws Exception {
        boolean wide = image.is64Bit();
        List<Refusal> controls = new ArrayList<>();
        for (int offset : new int[] { 4, wide ? 16 : 12, wide ? 40 : 24, wide ? 44 : 28, wide ? 56 : 36 }) {
            byte[] bytes = original.clone();
            ByteBuffer fields = ByteBuffer.wrap(bytes).order(image.byteOrder());
            if (offset == 4) fields.putInt(header + offset, 7); // A note is not a source section.
            else if (wide && (offset == 16 || offset == 56)) fields.putLong(header + offset, 1);
            else fields.putInt(header + offset, 1);
            controls.add(new Refusal(bytes, "unexpected Forge source-section attributes"));
        }
        for (long alignment : new long[] { 0, 3, 16 }) {
            byte[] bytes = original.clone();
            word(bytes, header + (wide ? 48 : 32), alignment, wide, image);
            controls.add(new Refusal(bytes, "unsupported source-section alignment"));
        }
        byte[] empty = original.clone();
        word(empty, header + (wide ? 32 : 20), 0, wide, image);
        controls.add(new Refusal(empty, "source-section stored size exceeds limit"));
        if ((section.flags & 0x800) != 0) {
            int payload = Math.toIntExact(section.offset);
            int headerSize = wide ? 24 : 12;
            byte[] shortHeader = original.clone();
            word(shortHeader, header + (wide ? 32 : 20), headerSize - 1, wide, image);
            controls.add(new Refusal(shortHeader, "truncated compressed source-section header"));
            if (wide) {
                byte[] reserved = original.clone();
                ByteBuffer.wrap(reserved).order(image.byteOrder()).putInt(payload + 4, 1);
                controls.add(new Refusal(reserved, "nonzero compressed source-section reserved field"));
            }
            int sizeOffset = payload + (wide ? 8 : 4);
            for (long size : new long[] { 0, 64 * 1024 * 1024 + 1L }) {
                byte[] bytes = original.clone();
                word(bytes, sizeOffset, size, wide, image);
                controls.add(new Refusal(bytes, "decoded source-section size exceeds limit"));
            }
            for (long alignment : new long[] { 0, 3, 16 }) {
                byte[] bytes = original.clone();
                word(bytes, payload + (wide ? 16 : 8), alignment, wide, image);
                controls.add(new Refusal(bytes, "unsupported decoded source-section alignment"));
            }
            ByteBuffer fields = ByteBuffer.wrap(original).order(image.byteOrder());
            long decoded = wide ? fields.getLong(sizeOffset) : Integer.toUnsignedLong(fields.getInt(sizeOffset));
            for (int delta : new int[] { -1, 1 }) {
                byte[] bytes = original.clone();
                word(bytes, sizeOffset, decoded + delta, wide, image);
                controls.add(new Refusal(bytes, delta < 0 ? "stream exceeds declared size" : "size mismatch or trailing input"));
            }
            byte[] noStream = original.clone();
            word(noStream, header + (wide ? 32 : 20), headerSize, wide, image);
            controls.add(new Refusal(noStream, "truncated, dictionary-dependent or stalled source stream"));
        }
        for (Refusal control : controls) {
            Files.write(malformed, control.bytes(), StandardOpenOption.CREATE_NEW);
            try {
                SyntheticSourceSidecar.prepare(malformed, directory, () -> false);
                throw new AssertionError("accepted " + control.diagnostic());
            }
            catch (IllegalArgumentException expected) {
                if (!expected.getMessage().contains(control.diagnostic())) throw expected;
            }
            finally {
                if (!Arrays.equals(control.bytes(), Files.readAllBytes(malformed))) throw new AssertionError("rejection modified input");
                Files.delete(malformed);
            }
        }
        return controls.size();
    }

    private static void word(byte[] bytes, int offset, long value, boolean wide, ElfImage image) {
        ByteBuffer fields = ByteBuffer.wrap(bytes).order(image.byteOrder());
        if (wide) fields.putLong(offset, value); else fields.putInt(offset, (int) value);
    }
}
