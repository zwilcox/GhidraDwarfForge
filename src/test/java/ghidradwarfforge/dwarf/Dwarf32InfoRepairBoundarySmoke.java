package ghidradwarfforge.dwarf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;

/** Independent byte-level repair oracles, including malformed producer output. */
public final class Dwarf32InfoRepairBoundarySmoke {
    private static int checks;

    private Dwarf32InfoRepairBoundarySmoke() { }

    public static void main(String[] args) {
        for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            exactRepair(order);
            forms(order);
            failures(order);
        }
        System.out.println("dwarf32-info-repair-boundaries=PASS checks=" + checks);
    }

    private static void exactRepair(ByteOrder order) {
        // CU starts at 12, child at 21 before repair and at 17 afterwards.
        byte[] abbrev = bytes(1, 0x11, 1, 0x10, 0x17, 0, 0,
            2, 0x0f, 0, 0x49, 0x13, 0, 0, 0);
        byte[] input = unit(order, concat(bytes(1), integer(0xfedcba98L, 8, order),
            bytes(2), integer(21, 4, order), bytes(2), integer(12, 4, order), bytes(0)));
        byte[] expected = unit(order, concat(bytes(1), integer(0xfedcba98L, 4, order),
            bytes(2), integer(17, 4, order), bytes(2), integer(12, 4, order), bytes(0)));
        byte[] before = input.clone();
        byte[] abbrevBefore = abbrev.clone();
        equal(expected, Dwarf32InfoRepair.repair(input, abbrev, 8, order), "exact self/back reference repair");
        equal(before, input, "repair mutated source info");
        equal(abbrevBefore, abbrev, "repair mutated abbreviations");
        byte[] narrow = bytes(4, 3, 2, 1);
        byte[] copy = Dwarf32InfoRepair.repair(narrow, new byte[0], 4, order);
        equal(narrow, copy, "32-bit pass-through");
        copy[0] = 0;
        require(narrow[0] == 4, "pass-through aliases caller array");
    }

    private static void forms(ByteOrder order) {
        // Fixed literal payloads specify each form independently of the repair parser.
        int[] forms = { 0x01, 0x05, 0x06, 0x07, 0x08, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x03, 0x04, 0x09, 0x0a, 0x18, 0x19, 0x21 };
        byte[][] payloads = {
            integer(0x123456789abcdefL, 8, order), integer(0xabc, 2, order),
            integer(0x12345678, 4, order), integer(0x123456789abcdefL, 8, order),
            bytes('x', 'y', 0), bytes(0x7f), bytes(1), bytes(0x81, 0x7f),
            integer(0x1234, 4, order), bytes(0x81, 1),
            concat(integer(2, 2, order), bytes(0xab, 0xcd)),
            concat(integer(2, 4, order), bytes(0xab, 0xcd)),
            bytes(2, 0xab, 0xcd), bytes(2, 0xab, 0xcd), bytes(2, 0xab, 0xcd),
            bytes(), bytes()
        };
        for (int index = 0; index < forms.length; index++) {
            for (boolean indirect : List.of(false, true)) {
                if (indirect && forms[index] == 0x21) continue;
                byte[] attr = concat(bytes(0x03, indirect ? 0x16 : forms[index]),
                    forms[index] == 0x21 ? bytes(0x7e) : bytes());
                byte[] abbrev = concat(bytes(1, 0x11, 0, 0x10, 0x17), attr, bytes(0, 0, 0));
                byte[] payload = concat(indirect ? bytes(forms[index]) : bytes(), payloads[index]);
                byte[] input = unit(order, concat(bytes(1), integer(0x12345678, 8, order), payload));
                byte[] expected = unit(order, concat(bytes(1), integer(0x12345678, 4, order), payload));
                equal(expected, Dwarf32InfoRepair.repair(input, abbrev, 8, order),
                    "preserve form " + forms[index] + " indirect=" + indirect);
                // Every truncation inside a value must fail, not cross a section boundary.
                for (int length = 0; length < payload.length; length++) {
                    reject(unit(order, concat(bytes(1), integer(3, 8, order),
                        Arrays.copyOf(payload, length))), abbrev, 8, order, "truncated form " + forms[index]);
                }
            }
        }
        byte[] indirectRef = bytes(1, 0x11, 0, 0x10, 0x17, 0x49, 0x16, 0, 0, 0);
        equal(unit(order, concat(bytes(1), integer(7, 4, order), bytes(0x13), integer(12, 4, order))),
            Dwarf32InfoRepair.repair(unit(order, concat(bytes(1), integer(7, 8, order),
                bytes(0x13), integer(12, 4, order))), indirectRef, 8, order), "indirect ref4");
    }

    private static void failures(ByteOrder order) {
        byte[] abbrev = bytes(1, 0x11, 0, 0x10, 0x17, 0, 0, 0);
        byte[] valid = unit(order, concat(bytes(1), integer(7, 8, order)));
        for (int width : new int[] { 0, 1, 2, 16 }) reject(valid, abbrev, width, order, "width");
        for (int length = 0; length < 12; length++) reject(new byte[length], abbrev, 8, order, "short header");
        for (int offset : new int[] { 0, 4, 7 }) {
            byte[] malformed = valid.clone();
            malformed[offset] ^= 0x40;
            reject(malformed, abbrev, 8, order, "header " + offset);
        }
        reject(unit(order, bytes(2)), abbrev, 8, order, "unknown abbreviation");
        reject(unit(order, bytes(0x80)), abbrev, 8, order, "unterminated code");
        reject(unit(order, bytes(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2)),
            abbrev, 8, order, "overflow code");
        byte[] continuation = new byte[11];
        Arrays.fill(continuation, (byte) 0x80);
        reject(unit(order, continuation), abbrev, 8, order, "excessive code width");
        reject(unit(order, concat(bytes(1), integer(7, 8, order), continuation)),
            bytes(1, 0x11, 0, 0x10, 0x17, 0x03, 0x0d, 0, 0, 0), 8, order, "SLEB overflow");
        reject(valid, bytes(1, 0x11), 8, order, "missing children flag");
        reject(valid, bytes(1, 0x11, 0, 0x10), 8, order, "missing attribute form");
        reject(valid, concat(Arrays.copyOf(abbrev, abbrev.length - 1), abbrev), 8, order, "duplicate code");
        reject(valid, bytes(1, 0x11, 0, 0x03, 0x17, 0, 0, 0), 8, order, "unreviewed section attribute");
        reject(unit(order, bytes(1)), bytes(1, 0x11, 0, 0, 0, 0), 8, order, "no oversized offsets");
        for (int form : new int[] { 0x27, 0x7f }) {
            reject(valid, bytes(1, 0x11, 0, 0x10, 0x17, 0x03, form, 0, 0, 0), 8, order, "unknown form");
        }
        byte[] referenceAbbrev = bytes(1, 0x11, 0, 0x10, 0x17, 0x49, 0x13, 0, 0, 0);
        int removed = order == ByteOrder.LITTLE_ENDIAN ? 17 : 13;
        reject(unit(order, concat(bytes(1), integer(7, 8, order), integer(removed + 1, 4, order))),
            referenceAbbrev, 8, order, "reference inside removed bytes");
        // Discarding a nonzero upper half would silently wrap the section offset.
        reject(unit(order, concat(bytes(1), integer(0x1_0000_0007L, 8, order))),
            abbrev, 8, order, "section offset does not fit DWARF32");
    }

    private static void reject(byte[] info, byte[] abbrev, int width, ByteOrder order, String label) {
        byte[] savedInfo = info.clone();
        byte[] savedAbbrev = abbrev.clone();
        try {
            Dwarf32InfoRepair.repair(info, abbrev, width, order);
            throw new AssertionError("accepted " + label + " / " + order);
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage() != null && !expected.getMessage().isBlank(), "missing refusal diagnostic");
        }
        equal(savedInfo, info, "refusal mutated info: " + label);
        equal(savedAbbrev, abbrev, "refusal mutated abbreviations: " + label);
    }

    private static byte[] unit(ByteOrder order, byte[] body) {
        byte[] result = new byte[12 + body.length];
        ByteBuffer.wrap(result).order(order).putInt(result.length - 4).putShort((short) 5)
            .put((byte) 1).put((byte) 8).putInt(0).put(body);
        return result;
    }

    private static byte[] integer(long value, int size, ByteOrder order) {
        ByteBuffer buffer = ByteBuffer.allocate(size).order(order);
        switch (size) {
            case 2 -> buffer.putShort((short) value);
            case 4 -> buffer.putInt((int) value);
            case 8 -> buffer.putLong(value);
            default -> throw new AssertionError("test integer width");
        }
        return buffer.array();
    }

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

    private static void equal(byte[] expected, byte[] actual, String label) {
        require(Arrays.equals(expected, actual), label);
    }

    private static void require(boolean condition, String label) {
        checks++;
        if (!condition) throw new AssertionError(label);
    }
}
