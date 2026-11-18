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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import java.io.ByteArrayInputStream;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.SyntheticSourceSidecar;

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

    public static void main(String[] args) throws Exception {
        for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            for (int width : new int[] { 4, 8 }) {
                Fixture fixture = fixture(order, width, bytes(), bytes());
                exact(fixture, NEW);
                exact(fixture, "C:/retained source");
                cancellation(fixture);
                malformed(fixture);
                forms(order, width);
                limits(order, width);
                container(fixture);
            }
        }
        System.out.println("synthetic-source-relocation-boundaries=PASS cases=" + cases);
    }

    private static void container(Fixture f) throws Exception {
        f = fixture(f.order(), f.width(), bytes(0x25, 0x0e), number(f.strings().length, 4, f.order()));
        byte[] extra = new byte[96 * 1024];
        var random = new java.util.Random(209);
        for (int i = 0; i < extra.length - 1; i++) extra[i] = (byte) ('a' + random.nextInt(26));
        f = f.with(f.info(), f.abbrev(), concat(f.strings(), text("GhidraDwarfForge synthetic test fixture"), extra), f.line());
        boolean wide = f.width() == 8;
        String names = "\0.shstrtab\0.debug_info\0.debug_abbrev\0.debug_str\0.debug_line\0.text\0";
        List<String> sections = List.of(".shstrtab", ".debug_info", ".debug_abbrev", ".debug_str", ".debug_line", ".text");
        List<byte[]> plains = List.of(names.getBytes(StandardCharsets.UTF_8), f.info(), f.abbrev(), f.strings(), f.line(), new byte[8]);
        var payloads = new java.util.ArrayList<byte[]>();
        for (int i = 0; i < plains.size(); i++) {
            if (i == 0 || i == 5) { payloads.add(plains.get(i)); continue; }
            var compressed = new ByteArrayOutputStream();
            try (var zip = new DeflaterOutputStream(compressed)) { zip.write(plains.get(i)); }
            var header = ByteBuffer.allocate(wide ? 24 : 12).order(f.order()).putInt(1);
            if (wide) header.putInt(0).putLong(plains.get(i).length).putLong(1);
            else header.putInt(plains.get(i).length).putInt(1);
            payloads.add(concat(header.array(), compressed.toByteArray()));
        }
        int stride = wide ? 64 : 40;
        int start = 64 + 7 * stride;
        var elf = ByteBuffer.allocate(start + payloads.stream().mapToInt(b -> b.length).sum() + 48).order(f.order());
        elf.put(bytes(0x7f, 'E', 'L', 'F', wide ? 2 : 1, f.order() == ByteOrder.LITTLE_ENDIAN ? 1 : 2, 1));
        elf.putShort(16, (short) 2).putShort(18, (short) (wide ? 62 : 8)).putInt(20, 1);
        if (wide) elf.putLong(40, 64).putShort(52, (short) 64).putShort(58, (short) stride).putShort(60, (short) 7).putShort(62, (short) 1);
        else elf.putInt(32, 64).putShort(40, (short) 52).putShort(46, (short) stride).putShort(48, (short) 7).putShort(50, (short) 1);
        for (int i = 0; i < sections.size(); i++) {
            int at = 64 + (i + 1) * stride;
            int flags = i > 0 && i < 5 ? 0x800 : i == 5 ? 6 : 0;
            int alignment = i > 0 && i < 5 ? (wide ? 8 : 4) : i == 5 ? 4 : 1;
            start = (start + alignment - 1) / alignment * alignment;
            elf.putInt(at, names.indexOf(sections.get(i))).putInt(at + 4, i == 0 ? 3 : 1);
            if (wide) elf.putLong(at + 8, flags).putLong(at + 16, i == 5 ? 0x401000 : 0)
                .putLong(at + 24, start).putLong(at + 32, payloads.get(i).length).putLong(at + 48, alignment);
            else elf.putInt(at + 8, flags).putInt(at + 12, i == 5 ? 0x401000 : 0)
                .putInt(at + 16, start).putInt(at + 20, payloads.get(i).length).putInt(at + 32, alignment);
            elf.position(start); elf.put(payloads.get(i)); start += payloads.get(i).length;
        }
        Path root = Files.createTempDirectory("source-container-");
        try {
            Path input = root.resolve("input.dbg"), output = root.resolve("output.dbg");
            Files.write(input, elf.array());
            var plan = SyntheticSourceSidecar.prepare(input, NEW, () -> false);
            try (var stage = FileChannel.open(output, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                plan.writeStage(stage, () -> false);
            }
            plan.requireMatches(output, () -> false);
            var image = ElfImage.read(output);
            byte[] expectedInfo = f.info().clone();
            put(expectedInfo, 17, f.strings().length, f.order());
            byte[] expectedLine = concat(Arrays.copyOf(f.line(), f.directoryStart()), text(NEW),
                Arrays.copyOfRange(f.line(), f.directoryEnd(), f.line().length));
            put(expectedLine, 0, expectedLine.length - 4, f.order());
            put(expectedLine, 8, f.programStart() - 12 + text(NEW).length - text(OLD).length, f.order());
            var expected = java.util.Map.of(".debug_info", expectedInfo, ".debug_abbrev", f.abbrev(),
                ".debug_str", concat(f.strings(), text(NEW)), ".debug_line", expectedLine);
            for (var section : image.sections()) {
                if (!expected.containsKey(section.name())) continue;
                byte[] data = image.sectionData(section);
                var header = ByteBuffer.wrap(data).order(f.order());
                require(header.getInt() == 1, "compressed section lost zlib format");
                if (wide) require(header.getInt() == 0, "compression reserved word changed");
                long size = wide ? header.getLong() : Integer.toUnsignedLong(header.getInt());
                long alignment = wide ? header.getLong() : Integer.toUnsignedLong(header.getInt());
                require(size == expected.get(section.name()).length && alignment == 1, "compression envelope differs");
                try (var decoded = new InflaterInputStream(new ByteArrayInputStream(data, header.position(), data.length - header.position()))) {
                    equal(expected.get(section.name()), decoded.readAllBytes(), "container relocation changed DWARF bytes");
                }
            }
            // A NOBITS section has no file payload; an empty PROGBITS section
            // occupies no bytes even if its nominal offset is inside a header.
            // The same offset with an actual byte must forbid the header edit.
            int spareHeader = 64 + 6 * stride;
            long overlapOffset = 64 + 2 * stride + (wide ? 24 : 16) + 1L;
            for (int variant = 0; variant < 3; variant++) {
                byte[] candidate = elf.array().clone();
                byte[] expectedContainer = Files.readAllBytes(output);
                for (byte[] bytes : List.of(candidate, expectedContainer)) {
                    var changed = ByteBuffer.wrap(bytes).order(f.order());
                    changed.putInt(spareHeader + 4, variant == 0 ? 8 : 1);
                    long size = variant == 0 ? 8 : variant == 1 ? 0 : 1;
                    if (wide) changed.putLong(spareHeader + 24, overlapOffset).putLong(spareHeader + 32, size);
                    else changed.putInt(spareHeader + 16, (int) overlapOffset).putInt(spareHeader + 20, (int) size);
                }
                Path selected = root.resolve("payload-control-" + variant + ".dbg");
                Path derived = root.resolve("payload-derived-" + variant + ".dbg");
                Files.write(selected, candidate);
                if (variant == 2) {
                    try {
                        SyntheticSourceSidecar.prepare(selected, NEW, () -> false);
                        throw new AssertionError("active payload overlapping header edit accepted");
                    }
                    catch (IllegalArgumentException rejected) {
                        require(rejected.getMessage().contains("overlaps an active section payload"),
                            "unexpected active payload rejection");
                    }
                    require(!Files.exists(derived), "refused overlap left an output");
                }
                else {
                    SyntheticSourceSidecar.Plan allowed;
                    try { allowed = SyntheticSourceSidecar.prepare(selected, NEW, () -> false); }
                    catch (IllegalArgumentException rejected) {
                        throw new AssertionError("section without file payload blocked relocation", rejected);
                    }
                    try (var stage = FileChannel.open(derived, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                        allowed.writeStage(stage, () -> false);
                    }
                    equal(expectedContainer, Files.readAllBytes(derived), "non-payload section altered relocation");
                }
                equal(candidate, Files.readAllBytes(selected), "payload control changed input");
                cases++;
            }
            // One trailing byte is inside the declared section, not merely file padding.
            byte[] trailing = elf.array().clone();
            var fields = ByteBuffer.wrap(trailing).order(f.order());
            int stringsHeader = 64 + 4 * stride;
            if (wide) fields.putLong(stringsHeader + 32, payloads.get(3).length + 1L);
            else fields.putInt(stringsHeader + 20, payloads.get(3).length + 1);
            Path invalid = root.resolve("trailing.dbg");
            Files.write(invalid, trailing);
            try { SyntheticSourceSidecar.prepare(invalid, NEW, () -> false); throw new AssertionError("trailing compressed byte accepted"); }
            catch (IllegalArgumentException rejected) {
                require(rejected.getMessage().contains("size mismatch or trailing input"), "unexpected compressed stream rejection");
            }
            equal(elf.array(), Files.readAllBytes(input), "source relocation modified input container");
            String retained = System.getProperty("forge.test.containers");
            if (retained != null) {
                Path destination = Path.of(retained);
                Files.createDirectories(destination);
                Files.copy(output, destination.resolve(f.width() + "-" + f.order() + ".dbg"));
            }
            cases++;
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void exact(Fixture f, String directory) {
        exact(f, directory, List.of("a.c", "b.c"));
    }

    private static void exact(Fixture f, String directory, List<String> files) {
        Fixture saved = copy(f);
        var actual = accepted(f, directory);
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
            actual.sourceFiles().equals(files), "incorrect source identity");
        try { actual.sourceFiles().add("invented.c"); throw new AssertionError("mutable source inventory"); }
        catch (UnsupportedOperationException expected) { }
        Fixture moved = f.with(actual.info(), f.abbrev(), actual.strings(), actual.line());
        var again = accepted(moved, directory);
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

    private static void limits(ByteOrder order, int width) {
        Fixture f = fixture(order, width, bytes(), bytes());
        exact(f, "/" + "x".repeat(65534));
        exact(f, "/" + "\u03bb".repeat(32767));
        reject(f, "/" + "\u03bb".repeat(32768), "UTF-8 byte limit independent of Java character count");

        var attributes = new ByteArrayOutputStream();
        for (int index = 0; index < 125; index++) {
            // Vendor attributes with flag_present consume no DIE bytes. Together
            // with name/comp_dir/stmt_list these are exactly 128 attributes.
            attributes.writeBytes(uleb(0x2000 + index));
            attributes.write(0x19);
        }
        exact(fixture(order, width, attributes.toByteArray(), bytes()), NEW);
        attributes.writeBytes(uleb(0x2000 + 125)); attributes.write(0x19);
        reject(fixture(order, width, attributes.toByteArray(), bytes()), NEW, "129 abbreviation attributes");

        var abbreviations = new ByteArrayOutputStream();
        abbreviations.writeBytes(Arrays.copyOf(f.abbrev(), f.abbrev().length - 1));
        for (int code = 2; code <= 65536; code++) {
            abbreviations.writeBytes(uleb(code)); abbreviations.writeBytes(bytes(0x2e, 0, 0, 0));
        }
        exact(f.with(f.info(), concat(abbreviations.toByteArray(), bytes(0)), f.strings(), f.line()), NEW);
        abbreviations.writeBytes(uleb(65537)); abbreviations.writeBytes(bytes(0x2e, 0, 0, 0, 0));
        reject(f.with(f.info(), abbreviations.toByteArray(), f.strings(), f.line()), NEW, "65537 abbreviation records");

        var files = new java.util.ArrayList<String>();
        files.add("a.c");
        for (int index = 1; index < 65537; index++) files.add("part" + index + ".c");
        exact(fileTable(f, files), NEW, files);
        files.add("extra.c");
        reject(fileTable(f, files), NEW, "65538 source files");
        for (String invalid : List.of("", ".", "..", "nested/file.c", "nested\\file.c")) {
            reject(fileTable(f, List.of("a.c", invalid)), NEW, "invalid later source basename");
        }
    }

    private static Fixture fileTable(Fixture f, List<String> files) {
        var table = new ByteArrayOutputStream();
        table.writeBytes(Arrays.copyOf(f.line(), f.directoryEnd()));
        table.writeBytes(bytes(2, 1, 8, 2, 15));
        table.writeBytes(uleb(files.size()));
        for (String name : files) { table.writeBytes(text(name)); table.write(0); }
        int programStart = table.size();
        table.writeBytes(Arrays.copyOfRange(f.line(), f.programStart(), f.line().length));
        byte[] line = table.toByteArray();
        put(line, 0, line.length - 4, f.order()); put(line, 8, programStart - 12, f.order());
        return new Fixture(f.info(), f.abbrev(), f.strings(), line, f.order(), f.width(),
            f.directoryStart(), f.directoryEnd(), programStart);
    }

    private static byte[] uleb(int value) {
        var result = new ByteArrayOutputStream();
        do {
            int part = value & 127;
            value >>>= 7;
            result.write(value == 0 ? part : part | 128);
        } while (value != 0);
        return result.toByteArray();
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

    private static SyntheticSourceRelocation.Result accepted(Fixture f, String directory) {
        try { return relocate(f, directory, () -> false); }
        catch (IllegalArgumentException unexpected) { throw new AssertionError("valid bounded source metadata must relocate", unexpected); }
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
