package ghidradwarfforge.dwarf;

import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Exercises real producer sections; the integration driver validates the repackaged ELF. */
public final class SyntheticSourceRelocationSmoke {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) throw new IllegalArgumentException("input-sections output-sections directory little|big");
        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        String directory = args[2];
        ByteOrder order = switch (args[3]) {
            case "little" -> ByteOrder.LITTLE_ENDIAN;
            case "big" -> ByteOrder.BIG_ENDIAN;
            default -> throw new IllegalArgumentException("unknown endian order");
        };
        byte[] info = Files.readAllBytes(input.resolve("info"));
        byte[] abbrev = Files.readAllBytes(input.resolve("abbrev"));
        byte[] strings = Files.readAllBytes(input.resolve("str"));
        byte[] line = Files.readAllBytes(input.resolve("line"));
        AtomicInteger visits = new AtomicInteger();
        var result = SyntheticSourceRelocation.relocate(info, abbrev, strings, line, order, directory,
            () -> { visits.incrementAndGet(); return false; });
        var repeat = SyntheticSourceRelocation.relocate(info, abbrev, strings, line, order, directory, () -> false);
        equal(result.info(), repeat.info());
        equal(result.strings(), repeat.strings());
        equal(result.line(), repeat.line());
        equal(strings, Arrays.copyOf(result.strings(), strings.length));
        if (info.length != result.info().length) throw new AssertionError("DIE offsets moved");
        int firstChanged = -1;
        for (int offset = 0; offset < info.length; offset++) {
            if (info[offset] == result.info()[offset]) continue;
            if (firstChanged < 0) firstChanged = offset;
            if (offset - firstChanged >= 4) throw new AssertionError("more than one CU reference changed");
        }
        // The executable line program starts after the DWARF32/v5 header.
        // Compare its full bytes independently of the production parser.
        int beforeProgram = Math.addExact(12, ByteBuffer.wrap(line).order(order).getInt(8));
        int afterProgram = Math.addExact(12, ByteBuffer.wrap(result.line()).order(order).getInt(8));
        equal(Arrays.copyOfRange(line, beforeProgram, line.length),
            Arrays.copyOfRange(result.line(), afterProgram, result.line().length));
        var again = SyntheticSourceRelocation.relocate(result.info(), abbrev, result.strings(),
            result.line(), order, directory, () -> false);
        equal(result.info(), again.info());
        equal(result.strings(), again.strings());
        equal(result.line(), again.line());
        int refusals = 0;
        for (String invalid : new String[] { "", "relative", "nul\0path", "/bad\ud800", "/" + "x".repeat(65536) }) {
            rejects(() -> SyntheticSourceRelocation.relocate(info, abbrev, strings, line, order, invalid, () -> false));
            refusals++;
        }
        for (int index : new int[] { 0, 4, 6, 7, 8, 12 }) {
            byte[] invalid = info.clone();
            invalid[index] ^= 0x40;
            rejects(() -> SyntheticSourceRelocation.relocate(invalid, abbrev, strings, line, order, directory, () -> false));
            refusals++;
        }
        for (int index : new int[] { 0, 4, 6, 7, 8 }) {
            byte[] invalid = line.clone();
            invalid[index] ^= 0x40;
            rejects(() -> SyntheticSourceRelocation.relocate(info, abbrev, strings, invalid, order, directory, () -> false));
            refusals++;
        }
        rejects(() -> SyntheticSourceRelocation.relocate(info, abbrev, new byte[0], line, order, directory, () -> false));
        rejects(() -> SyntheticSourceRelocation.relocate(info, Arrays.copyOf(abbrev, abbrev.length + 1),
            strings, line, order, directory, () -> false));
        refusals += 2;
        // These actual producer fixtures have one compilation-directory
        // abbreviation and one corresponding pooled directory string.
        int compDir = unique(abbrev, new byte[] { 0x1b, 0x0e });
        byte[] legacy = abbrev.clone();
        legacy[compDir] = 0x5a; // DW_AT_description: a string, but no longer a compilation directory.
        try {
            SyntheticSourceRelocation.relocate(info, legacy, strings, line, order, directory, () -> false);
            throw new AssertionError("missing compilation directory accepted");
        }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains("re-export legacy artifacts")) throw expected;
        }
        byte[] unknown = abbrev.clone();
        unknown[compDir + 1] = 0x16; // DW_FORM_indirect is outside the selected producer contract.
        rejects(() -> SyntheticSourceRelocation.relocate(info, unknown, strings, line, order, directory, () -> false));
        byte[] disagreement = strings.clone();
        disagreement[unique(strings, result.previousDirectory().getBytes(StandardCharsets.UTF_8))] ^= 1;
        rejects(() -> SyntheticSourceRelocation.relocate(info, abbrev, disagreement, line, order, directory, () -> false));
        refusals += 3;
        for (int stop = 1; stop <= visits.get(); stop++) {
            int selected = stop;
            AtomicInteger current = new AtomicInteger();
            try {
                SyntheticSourceRelocation.relocate(info, abbrev, strings, line, order, directory,
                    () -> current.incrementAndGet() == selected);
                throw new AssertionError("cancellation did not propagate at " + stop);
            }
            catch (CancellationException expected) { }
        }
        equal(info, Files.readAllBytes(input.resolve("info")));
        equal(abbrev, Files.readAllBytes(input.resolve("abbrev")));
        equal(strings, Files.readAllBytes(input.resolve("str")));
        equal(line, Files.readAllBytes(input.resolve("line")));
        Files.createDirectory(output);
        Files.write(output.resolve("info"), result.info());
        Files.write(output.resolve("str"), result.strings());
        Files.write(output.resolve("line"), result.line());
        Files.writeString(output.resolve("file-name.txt"), result.fileName());
        Files.writeString(output.resolve("previous-directory.txt"), result.previousDirectory());
        System.out.printf("source-relocation-smoke=PASS refusals=%d cancellation=%d%n", refusals, visits.get());
    }

    private static void equal(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) throw new AssertionError("unexpected byte change");
    }

    private static int unique(byte[] bytes, byte[] selected) {
        int found = -1;
        for (int offset = 0; offset <= bytes.length - selected.length; offset++) {
            if (Arrays.equals(bytes, offset, offset + selected.length, selected, 0, selected.length)) {
                if (found >= 0) throw new AssertionError("fixture pattern is not unique");
                found = offset;
            }
        }
        if (found < 0) throw new AssertionError("fixture pattern missing");
        return found;
    }

    private static void rejects(Runnable operation) {
        try {
            operation.run();
            throw new AssertionError("malformed source metadata accepted");
        }
        catch (IllegalArgumentException expected) { }
    }
}
