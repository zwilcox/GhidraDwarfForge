package ghidradwarfforge.dwarf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Relocates only the synthetic source directory in Forge's single DWARF32/v5
 * compilation unit and line table. Does not access files or modify caller arrays.
 * Existing DIE offsets, strings, line programs, addresses and location/range
 * sections remain unchanged. An unfamiliar producer layout is a refusal.
 */
public final class SyntheticSourceRelocation {
    private static final int MAX_SECTION = 64 * 1024 * 1024;
    private static final int MAX_STRING = 65536;
    private static final int NAME = 0x03;
    private static final int STMT_LIST = 0x10;
    private static final int COMP_DIR = 0x1b;
    private static final int STRP = 0x0e;
    private static final int SEC_OFFSET = 0x17;

    public record Result(byte[] info, byte[] strings, byte[] line,
            String previousDirectory, String fileName) { }

    private record Attribute(int name, int form) { }
    private record Text(String value, int start, int end) { }

    private SyntheticSourceRelocation() { }

    public static Result relocate(byte[] info, byte[] abbreviations, byte[] strings,
            byte[] line, ByteOrder order, String directory, BooleanSupplier cancelled) {
        Objects.requireNonNull(order, "byte order");
        Objects.requireNonNull(cancelled, "cancellation");
        byte[] replacement = encode(directory);
        if (!(directory.startsWith("/") || directory.matches("[A-Za-z]:/.*"))) {
            throw new IllegalArgumentException("installed source directory must be absolute");
        }
        Cursor cu = new Cursor(info, order, cancelled);
        require(cu.uint(4) == info.length - 4L, "expected one DWARF32 unit");
        require(cu.uint(2) == 5 && cu.uint(1) == 1, "expected DWARF5 compile unit");
        int addressSize = (int) cu.uint(1);
        require(addressSize == 4 || addressSize == 8, "unsupported address size");
        require(cu.uint(4) == 0, "expected one abbreviation table");
        long rootCode = cu.uleb();
        List<Attribute> root = rootAttributes(abbreviations, order, rootCode, cancelled);
        Cursor str = new Cursor(strings, order, cancelled);
        Text name = null;
        Text oldDirectory = null;
        int directoryReference = -1;
        boolean statementList = false;
        var names = new HashSet<Integer>();
        for (var attribute : root) {
            require(names.add(attribute.name()), "duplicate compilation-unit attribute");
            if (attribute.name() == NAME || attribute.name() == COMP_DIR) {
                require(attribute.form() == STRP, "expected indirect CU source strings");
                int offset = cu.position;
                long stringOffset = cu.uint(4);
                require(stringOffset < strings.length, "source string offset is outside section");
                Text value = str.textAt((int) stringOffset);
                if (attribute.name() == NAME) name = value;
                else {
                    oldDirectory = value;
                    directoryReference = offset;
                }
            }
            else if (attribute.name() == STMT_LIST) {
                require(attribute.form() == SEC_OFFSET && cu.uint(4) == 0,
                    "expected line table at section start");
                statementList = true;
            }
            else {
                skip(cu, attribute.form(), addressSize);
            }
        }
        require(name != null && oldDirectory != null && statementList,
            "source relocation requires a current Forge CU with name, comp_dir and stmt_list; re-export legacy artifacts");
        require(!name.value().isEmpty() && !name.value().equals(".") && !name.value().equals("..") &&
            !name.value().contains("/") && !name.value().contains("\\"), "expected a source basename");
        require(!oldDirectory.value().isEmpty(), "empty original source directory");

        Cursor table = new Cursor(line, order, cancelled);
        require(table.uint(4) == line.length - 4L, "expected one DWARF32 line unit");
        require(table.uint(2) == 5 && table.uint(1) == addressSize && table.uint(1) == 0,
            "line header differs from compilation unit");
        long headerLength = table.uint(4);
        long end = table.position + headerLength;
        require(end <= line.length, "truncated line header");
        int headerEnd = (int) end;
        table.advance(5); // Preserve minimum instruction length through line range.
        int opcodeBase = (int) table.uint(1);
        require(opcodeBase > 0, "invalid line opcode base");
        table.advance(opcodeBase - 1);
        require(table.uint(1) == 1 && table.uleb() == 1 && table.uleb() == 8 && table.uleb() == 1,
            "expected one inline line-table source directory");
        Text lineDirectory = table.text();
        require(table.uint(1) == 2 && table.uleb() == 1 && table.uleb() == 8 &&
            table.uleb() == 2 && table.uleb() == 15 && table.uleb() == 1,
            "expected one inline source file with directory index");
        Text lineFile = table.text();
        require(table.uleb() == 0 && table.position == headerEnd,
            "unexpected line source index or header tail");
        require(lineDirectory.value().equals(oldDirectory.value()) && lineFile.value().equals(name.value()),
            "compilation-unit and line-table source paths disagree");
        cu.check();
        if (directory.equals(oldDirectory.value())) {
            return new Result(info.clone(), strings.clone(), line.clone(), directory, name.value());
        }
        int newStringSize = Math.addExact(strings.length, Math.addExact(replacement.length, 1));
        require(newStringSize <= MAX_SECTION, "relocated string section exceeds 64 MiB");
        byte[] newStrings = Arrays.copyOf(strings, newStringSize);
        System.arraycopy(replacement, 0, newStrings, strings.length, replacement.length);
        byte[] newInfo = info.clone();
        ByteBuffer.wrap(newInfo).order(order).putInt(directoryReference, strings.length);
        int delta = replacement.length + 1 - (lineDirectory.end() - lineDirectory.start());
        int newLineSize = Math.addExact(line.length, delta);
        require(newLineSize <= MAX_SECTION, "relocated line section exceeds 64 MiB");
        byte[] newLine = new byte[newLineSize];
        System.arraycopy(line, 0, newLine, 0, lineDirectory.start());
        System.arraycopy(replacement, 0, newLine, lineDirectory.start(), replacement.length);
        System.arraycopy(line, lineDirectory.end(), newLine,
            lineDirectory.start() + replacement.length + 1, line.length - lineDirectory.end());
        ByteBuffer.wrap(newLine).order(order).putInt(0, newLine.length - 4)
            .putInt(8, Math.toIntExact(headerLength + delta));
        cu.check();
        return new Result(newInfo, newStrings, newLine, oldDirectory.value(), name.value());
    }

    private static List<Attribute> rootAttributes(byte[] bytes, ByteOrder order, long rootCode,
            BooleanSupplier cancelled) {
        require(rootCode > 0, "missing compilation-unit abbreviation");
        Cursor c = new Cursor(bytes, order, cancelled);
        var codes = new HashSet<Long>();
        List<Attribute> selected = null;
        boolean terminated = false;
        while (c.position < bytes.length) {
            long code = c.uleb();
            if (code == 0) {
                terminated = true;
                break;
            }
            require(codes.size() < 65536 && codes.add(code), "duplicate or excessive abbreviations");
            long tag = c.uleb();
            require(c.uint(1) <= 1, "invalid abbreviation child flag");
            var attributes = new ArrayList<Attribute>();
            while (true) {
                long encodedName = c.uleb();
                long encodedForm = c.uleb();
                require(encodedName <= 65535 && encodedForm <= 65535,
                    "attribute name/form exceeds producer half-width");
                int name = (int) encodedName;
                int form = (int) encodedForm;
                if (name == 0 && form == 0) break;
                require(name != 0 && form != 0 && attributes.size() < 128,
                    "invalid or excessive abbreviation attributes");
                if (form == 0x21) c.leb(); // DW_FORM_implicit_const's abbreviation operand.
                attributes.add(new Attribute(name, form));
            }
            if (code == rootCode) {
                require(tag == 0x11, "root is not a compile unit");
                selected = List.copyOf(attributes);
            }
        }
        require(terminated && c.position == bytes.length && selected != null,
            "missing root or unexpected abbreviation-table tail");
        return selected;
    }

    private static void skip(Cursor c, int form, int addressSize) {
        switch (form) {
            case 0x01 -> c.advance(addressSize); // addr
            case 0x05 -> c.advance(2); // data2
            case 0x06, STRP, SEC_OFFSET -> c.advance(4);
            case 0x07 -> c.advance(8); // data8
            case 0x0b, 0x0c -> c.advance(1); // data1, flag
            case 0x0d, 0x0f -> c.leb(); // sdata, udata
            case 0x19, 0x21 -> { } // flag_present, implicit_const
            default -> throw new IllegalArgumentException("unreviewed compilation-unit form " + form);
        }
    }

    private static byte[] encode(String value) {
        Objects.requireNonNull(value, "directory");
        require(!value.isEmpty() && value.indexOf('\0') < 0, "invalid source directory");
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(value));
            require(encoded.remaining() < MAX_STRING, "source directory exceeds 65535 bytes");
            byte[] result = new byte[encoded.remaining()];
            encoded.get(result);
            return result;
        }
        catch (CharacterCodingException invalid) {
            throw new IllegalArgumentException("source directory is not valid UTF-8", invalid);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }

    private static final class Cursor {
        private final byte[] bytes;
        private final ByteBuffer buffer;
        private final BooleanSupplier cancelled;
        private int position;

        Cursor(byte[] bytes, ByteOrder order, BooleanSupplier cancelled) {
            this.bytes = Objects.requireNonNull(bytes, "section");
            require(bytes.length <= MAX_SECTION, "source section exceeds 64 MiB");
            this.buffer = ByteBuffer.wrap(bytes).order(order);
            this.cancelled = cancelled;
            check();
        }

        void check() {
            if (cancelled.getAsBoolean()) throw new CancellationException("source relocation cancelled");
        }

        void advance(int count) {
            check();
            require(count >= 0 && position <= bytes.length - count, "truncated DWARF source metadata");
            position += count;
        }

        long uint(int width) {
            int start = position;
            advance(width);
            return switch (width) {
                case 1 -> Byte.toUnsignedInt(bytes[start]);
                case 2 -> Short.toUnsignedInt(buffer.getShort(start));
                case 4 -> Integer.toUnsignedLong(buffer.getInt(start));
                default -> throw new IllegalArgumentException("unsupported source integer width");
            };
        }

        long uleb() {
            long value = 0;
            for (int shift = 0; shift < 63; shift += 7) {
                int b = (int) uint(1);
                value |= (long) (b & 0x7f) << shift;
                if ((b & 0x80) == 0) return value;
            }
            throw new IllegalArgumentException("source metadata integer exceeds signed 63-bit range");
        }

        void leb() {
            for (int count = 0; count < 10; count++) {
                if ((uint(1) & 0x80) == 0) return;
            }
            throw new IllegalArgumentException("source metadata LEB exceeds 10 bytes");
        }

        Text textAt(int offset) {
            require(offset >= 0 && offset < bytes.length, "string offset is outside section");
            position = offset;
            return text();
        }

        Text text() {
            int start = position;
            while (uint(1) != 0) require(position - start < MAX_STRING, "source string exceeds limit");
            try {
                String text = StandardCharsets.UTF_8.newDecoder()
                    .decode(ByteBuffer.wrap(bytes, start, position - start - 1)).toString();
                return new Text(text, start, position);
            }
            catch (CharacterCodingException invalid) {
                throw new IllegalArgumentException("source metadata is not valid UTF-8", invalid);
            }
        }
    }
}
