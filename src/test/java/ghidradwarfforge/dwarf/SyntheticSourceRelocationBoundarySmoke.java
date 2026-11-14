package ghidradwarfforge.dwarf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

/** Hand-encoded DWARF fixtures: no production writer is used to make the oracle. */
public final class SyntheticSourceRelocationBoundarySmoke {
    private static int cases;
    private static final String OLD = "/old";
    private static final String NEW = "/retained source/\u03bb";

    private record Fixture(byte[] info, byte[] abbrev, byte[] strings, byte[] line,
            ByteOrder order, int width, int directoryStart, int directoryEnd, int programStart) {
        Fixture with(byte[] newInfo, byte[] newAbbrev, byte[] newStrings, byte[] newLine) {
            return new Fixture(newInfo, newAbbrev, newStrings, newLine, order, width,
                directoryStart, directoryEnd, programStart);
        }
    }

    private SyntheticSourceRelocationBoundarySmoke() { }

    public static void main(String[] args) {
        for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            for (int width : new int[] { 4, 8 }) {
                Fixture fixture = fixture(order, width, bytes(), bytes());
                exact(fixture, NEW);
                exact(fixture, "C:/retained source");
                cancellation(fixture);
                malformed(fixture);
                forms(order, width);
            }
        }
        System.out.println("synthetic-source-relocation-boundaries=PASS cases=" + cases);
    }

    private static void exact(Fixture f, String directory) {
        Fixture saved = copy(f);
        var actual = relocate(f, directory, () -> false);
        byte[] expectedInfo = f.info().clone();
        ByteBuffer.wrap(expectedInfo).order(f.order()).putInt(17, f.strings().length);
        byte[] expectedStrings = concat(f.strings(), text(directory));
        byte[] expectedLine = concat(Arrays.copyOf(f.line(), f.directoryStart()), text(directory),
            Arrays.copyOfRange(f.line(), f.directoryEnd(), f.line().length));
        int delta = text(directory).length - text(OLD).length;
        ByteBuffer.wrap(expectedLine).order(f.order()).putInt(0, expectedLine.length - 4)
            .putInt(8, f.programStart() - 12 + delta);
        equal(expectedInfo, actual.info(), "only CU directory reference may change");
        equal(expectedStrings, actual.strings(), "old pooled strings must be retained byte-for-byte");
        equal(expectedLine, actual.line(), "line file table and executable program must be preserved");
        require(actual.previousDirectory().equals(OLD) && actual.fileName().equals("a.c") &&
            actual.sourceFiles().equals(List.of("a.c", "b.c")), "incorrect source identity");
        try { actual.sourceFiles().add("invented.c"); throw new AssertionError("mutable source inventory"); }
        catch (UnsupportedOperationException expected) { }
        Fixture moved = f.with(actual.info(), f.abbrev(), actual.strings(), actual.line());
        var again = relocate(moved, directory, () -> false);
        equal(actual.info(), again.info(), "same-directory info changed");
        equal(actual.strings(), again.strings(), "same-directory strings grew");
        equal(actual.line(), again.line(), "same-directory line changed");
        again.info()[0] ^= 1;
        again.strings()[0] ^= 1;
        again.line()[0] ^= 1;
        equal(expectedInfo, actual.info(), "returned info aliases input");
        equal(expectedStrings, actual.strings(), "returned strings alias input");
        equal(expectedLine, actual.line(), "returned line aliases input");
        unchanged(saved, f);
        cases++;
    }

    private static void cancellation(Fixture f) {
        for (String directory : List.of(OLD, NEW)) {
            AtomicInteger calls = new AtomicInteger();
            relocate(f, directory, () -> { calls.incrementAndGet(); return false; });
            int visits = calls.get();
            for (int stop = 1; stop <= visits; stop++) {
                Fixture saved = copy(f);
                int selected = stop;
                calls.set(0);
                try {
                    relocate(f, directory, () -> calls.incrementAndGet() == selected);
                    throw new AssertionError("ignored cancellation checkpoint " + stop);
                }
                catch (CancellationException expected) {
                    require(expected.getMessage().contains("cancelled"), "missing cancellation diagnostic");
                }
                unchanged(saved, f);
                cases++;
            }
        }
    }

    private static void malformed(Fixture f) {
        for (String directory : List.of("", "relative", "/nul\0tail", "/bad\ud800", "/" + "x".repeat(65535))) {
            reject(f, directory, "directory");
        }
        // Truncation of each required CU or line-header byte, with consistent
        // unit lengths, tests the parser bounds rather than just its first check.
        for (int length = 0; length < 25; length++) {
            byte[] info = Arrays.copyOf(f.info(), length);
            if (length >= 4) put(info, 0, length - 4, f.order());
            reject(f.with(info, f.abbrev(), f.strings(), f.line()), NEW, "CU truncation " + length);
        }
        for (int length = 0; length < f.programStart(); length++) {
            byte[] line = Arrays.copyOf(f.line(), length);
            if (length >= 4) put(line, 0, length - 4, f.order());
            if (length >= 12) put(line, 8, Math.max(0, length - 12), f.order());
            reject(f.with(f.info(), f.abbrev(), f.strings(), line), NEW, "line truncation " + length);
        }
        for (int length = 0; length < f.strings().length; length++) {
            reject(f.with(f.info(), f.abbrev(), Arrays.copyOf(f.strings(), length), f.line()), NEW, "string truncation");
        }
        for (int length = 0; length < f.abbrev().length; length++) {
            reject(f.with(f.info(), Arrays.copyOf(f.abbrev(), length), f.strings(), f.line()), NEW, "abbreviation truncation");
        }
        for (int offset : new int[] { 0, 4, 6, 7, 8, 12, 13, 17, 21 }) {
            byte[] info = f.info().clone();
            info[offset] ^= 0x40;
            reject(f.with(info, f.abbrev(), f.strings(), f.line()), NEW, "CU field " + offset);
        }
        for (int offset : new int[] { 0, 4, 6, 7, 8, 17, 30, 31, 32, 33 }) {
            byte[] line = f.line().clone();
            line[offset] ^= 0x40;
            reject(f.with(f.info(), f.abbrev(), f.strings(), line), NEW, "line field " + offset);
        }
        for (byte[] invalid : List.of(
                bytes(1, 0x12, 0, 0, 0, 0), // root is not a CU
                bytes(1, 0x11, 2, 0, 0, 0), // invalid children flag
                bytes(1, 0x11, 0, 0, 1, 0, 0, 0), // half terminator
                bytes(1, 0x11, 0, 0x80, 0x80, 4, 8, 0, 0, 0), // name > half-width
                bytes(1, 0x11, 0, 3, 0x80, 0x80, 4, 0, 0, 0), // form > half-width
                concat(f.abbrev(), bytes(0)),
                concat(Arrays.copyOf(f.abbrev(), f.abbrev().length - 1), f.abbrev()))) {
            reject(f.with(f.info(), invalid, f.strings(), f.line()), NEW, "abbreviation structure");
        }
        byte[] duplicateName = bytes(1, 0x11, 0, 3, 0x0e, 3, 0x0e, 0x10, 0x17, 0, 0, 0);
        reject(f.with(f.info(), duplicateName, f.strings(), f.line()), NEW, "duplicate CU attribute");
        byte[] missingDirectory = f.abbrev().clone();
        missingDirectory[5] = 0x5a;
        reject(f.with(f.info(), missingDirectory, f.strings(), f.line()), NEW, "missing comp_dir");
        byte[] wrongForm = f.abbrev().clone();
        wrongForm[4] = 8;
        reject(f.with(f.info(), wrongForm, f.strings(), f.line()), NEW, "inline source name");
        byte[] invalidString = f.strings().clone();
        invalidString[0] = (byte) 0xff;
        reject(f.with(f.info(), f.abbrev(), invalidString, f.line()), NEW, "invalid UTF-8");
        for (byte[] strings : List.of(text("/a.c"), text("."), text(".."), text(""), text("a\\c"))) {
            reject(f.with(f.info(), f.abbrev(), concat(strings, text(OLD)), f.line()), NEW, "invalid basename");
        }
        byte[] disagreement = f.strings().clone();
        disagreement[5] = 'X';
        reject(f.with(f.info(), f.abbrev(), disagreement, f.line()), NEW, "CU/line directory disagreement");
        // Change the second filename to the first without changing encoded size.
        byte[] repeatedFile = f.line().clone();
        repeatedFile[f.programStart() - 5] = 'a';
        reject(f.with(f.info(), f.abbrev(), f.strings(), repeatedFile), NEW, "duplicate source file");
        byte[] wrongIndex = f.line().clone();
        wrongIndex[f.programStart() - 1] = 1;
        reject(f.with(f.info(), f.abbrev(), f.strings(), wrongIndex), NEW, "nonzero directory index");
        byte[] wrongName = f.line().clone();
        wrongName[f.programStart() - 10] = 'z';
        reject(f.with(f.info(), f.abbrev(), f.strings(), wrongName), NEW, "CU/line filename disagreement");
        byte[] hugeCode = new byte[10];
        Arrays.fill(hugeCode, (byte) 0x80);
        reject(f.with(f.info(), hugeCode, f.strings(), f.line()), NEW, "ULEB overflow");
    }

    private static void forms(ByteOrder order, int width) {
        int[] forms = { 0x01, 0x05, 0x06, 0x07, 0x0b, 0x0c, 0x0d, 0x0f, 0x19, 0x21 };
        int[] sizes = { width, 2, 4, 8, 1, 1, 2, 2, 0, 0 };
        for (int index = 0; index < forms.length; index++) {
            byte[] value = new byte[sizes[index]];
            if (forms[index] == 0x0d || forms[index] == 0x0f) { value[0] = (byte) 0x81; value[1] = 1; }
            byte[] attribute = concat(bytes(0x25, forms[index]), forms[index] == 0x21 ? bytes(0x7f) : bytes());
            Fixture f = fixture(order, width, attribute, value);
            exact(f, NEW);
        }
        Fixture unknown = fixture(order, width, bytes(0x25, 0x16), bytes(8, 0));
        reject(unknown, NEW, "unreviewed CU form");
        byte[] unterminated = new byte[11];
        Arrays.fill(unterminated, (byte) 0x80);
        reject(fixture(order, width, bytes(0x25, 0x0d), unterminated), NEW, "SLEB overflow");
    }

    private static Fixture fixture(ByteOrder order, int width, byte[] extraAttributes, byte[] extraValues) {
        byte[] strings = concat(text("a.c"), text(OLD));
        byte[] abbrev = concat(bytes(1, 0x11, 0, 3, 0x0e, 0x1b, 0x0e, 0x10, 0x17), extraAttributes, bytes(0, 0, 0));
        byte[] info = concat(new byte[12], bytes(1), number(0, 4, order), number(4, 4, order),
            number(0, 4, order), extraValues);
        ByteBuffer.wrap(info).order(order).putInt(info.length - 4).putShort((short) 5)
            .put((byte) 1).put((byte) width).putInt(0);
        // DWARF5 fixed line header, standard opcode operand counts and explicit
        // directory/file format descriptors. Two files, one directory.
        byte[] prefix = concat(new byte[12], bytes(1, 1, 1, 0xfb, 14, 13),
            bytes(0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1), bytes(1, 1, 8, 1));
        byte[] header = concat(prefix, text(OLD), bytes(2, 1, 8, 2, 15, 2),
            text("a.c"), bytes(0), text("b.c"), bytes(0));
        byte[] program = concat(bytes(0, width + 1, 2), number(0x401000, width, order), bytes(1, 0, 1, 1));
        byte[] line = concat(header, program);
        ByteBuffer.wrap(line).order(order).putInt(line.length - 4).putShort((short) 5)
            .put((byte) width).put((byte) 0).putInt(header.length - 12);
        return new Fixture(info, abbrev, strings, line, order, width, prefix.length,
            prefix.length + text(OLD).length, header.length);
    }

    private static SyntheticSourceRelocation.Result relocate(Fixture f, String directory, BooleanSupplier cancelled) {
        return SyntheticSourceRelocation.relocate(f.info(), f.abbrev(), f.strings(), f.line(), f.order(), directory, cancelled);
    }

    private static void reject(Fixture f, String directory, String label) {
        Fixture saved = copy(f);
        try { relocate(f, directory, () -> false); throw new AssertionError("accepted " + label); }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage() != null && !expected.getMessage().isBlank(), "missing refusal diagnostic");
        }
        unchanged(saved, f);
        cases++;
    }

    private static Fixture copy(Fixture f) { return f.with(f.info().clone(), f.abbrev().clone(), f.strings().clone(), f.line().clone()); }

    private static void unchanged(Fixture expected, Fixture actual) {
        equal(expected.info(), actual.info(), "input info mutated");
        equal(expected.abbrev(), actual.abbrev(), "input abbrev mutated");
        equal(expected.strings(), actual.strings(), "input strings mutated");
        equal(expected.line(), actual.line(), "input line mutated");
    }

    private static byte[] number(long value, int size, ByteOrder order) {
        ByteBuffer b = ByteBuffer.allocate(size).order(order);
        if (size == 8) b.putLong(value); else b.putInt((int) value);
        return b.array();
    }

    private static void put(byte[] data, int offset, int value, ByteOrder order) { ByteBuffer.wrap(data).order(order).putInt(offset, value); }

    private static byte[] text(String text) { return concat(text.getBytes(StandardCharsets.UTF_8), bytes(0)); }

    private static byte[] concat(byte[]... parts) {
        var result = new ByteArrayOutputStream();
        for (byte[] part : parts) result.writeBytes(part);
        return result.toByteArray();
    }

    private static byte[] bytes(int... values) {
        byte[] result = new byte[values.length];
        for (int index = 0; index < values.length; index++) result[index] = (byte) values[index];
        return result;
    }

    private static void equal(byte[] expected, byte[] actual, String label) { require(Arrays.equals(expected, actual), label); }

    private static void require(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
}
