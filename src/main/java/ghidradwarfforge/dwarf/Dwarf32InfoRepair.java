package ghidradwarfforge.dwarf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Repairs libdwarf 2.3.2 producer section offsets written at target-pointer
 * width in an otherwise DWARF32 unit. CU-relative references are adjusted for
 * the removed bytes. Every parsed form is checked; an unfamiliar layout fails
 * closed instead of producing a guessed artifact.
 */
public final class Dwarf32InfoRepair {
    private static final int DW_AT_STMT_LIST = 0x10;
    private static final int DW_AT_LOCATION = 0x02;
    private static final int DW_AT_RANGES = 0x55;
    private static final int DW_FORM_ADDR = 0x01;
    private static final int DW_FORM_BLOCK2 = 0x03;
    private static final int DW_FORM_BLOCK4 = 0x04;
    private static final int DW_FORM_DATA2 = 0x05;
    private static final int DW_FORM_DATA4 = 0x06;
    private static final int DW_FORM_DATA8 = 0x07;
    private static final int DW_FORM_STRING = 0x08;
    private static final int DW_FORM_BLOCK = 0x09;
    private static final int DW_FORM_BLOCK1 = 0x0a;
    private static final int DW_FORM_DATA1 = 0x0b;
    private static final int DW_FORM_FLAG = 0x0c;
    private static final int DW_FORM_SDATA = 0x0d;
    private static final int DW_FORM_STRP = 0x0e;
    private static final int DW_FORM_UDATA = 0x0f;
    private static final int DW_FORM_REF_ADDR = 0x10;
    private static final int DW_FORM_REF1 = 0x11;
    private static final int DW_FORM_REF2 = 0x12;
    private static final int DW_FORM_REF4 = 0x13;
    private static final int DW_FORM_REF8 = 0x14;
    private static final int DW_FORM_REF_UDATA = 0x15;
    private static final int DW_FORM_INDIRECT = 0x16;
    private static final int DW_FORM_SEC_OFFSET = 0x17;
    private static final int DW_FORM_EXPRLOC = 0x18;
    private static final int DW_FORM_FLAG_PRESENT = 0x19;
    private static final int DW_FORM_IMPLICIT_CONST = 0x21;

    private record Attribute(int name, int form) {
    }

    private record Abbreviation(List<Attribute> attributes) {
    }

    private record Reference(int offset, long target) {
    }

    private record Deletion(int start, int end) {
    }

    private Dwarf32InfoRepair() {
    }

    public static byte[] repair(byte[] info, byte[] abbrev, int addressBytes,
            ByteOrder order) {
        if (addressBytes == 4) {
            return info.clone();
        }
        if (addressBytes != 8 || info.length < 12) {
            throw new IllegalArgumentException("unsupported DWARF32 repair width/layout");
        }
        byte[] working = info.clone();
        ByteBuffer buffer = ByteBuffer.wrap(working).order(order);
        long unitLength = Integer.toUnsignedLong(buffer.getInt(0));
        if (unitLength != working.length - 4L ||
                Short.toUnsignedInt(buffer.getShort(4)) != 5 ||
                Byte.toUnsignedInt(working[7]) != addressBytes) {
            throw new IllegalArgumentException("unexpected DWARF32 compilation-unit header");
        }
        long abbrevOffset = Integer.toUnsignedLong(buffer.getInt(8));
        Map<Long, Abbreviation> abbreviations = parseAbbreviations(abbrev,
            Math.toIntExact(abbrevOffset));
        Cursor cursor = new Cursor(12);
        List<Reference> references = new ArrayList<>();
        List<Deletion> deletions = new ArrayList<>();
        while (cursor.offset < working.length) {
            long code = readUleb(working, cursor);
            if (code == 0) {
                continue;
            }
            Abbreviation abbreviation = abbreviations.get(code);
            if (abbreviation == null) {
                throw new IllegalArgumentException("unknown abbreviation " + code);
            }
            for (Attribute attribute : abbreviation.attributes()) {
                int form = attribute.form();
                if (form == DW_FORM_INDIRECT) {
                    form = Math.toIntExact(readUleb(working, cursor));
                }
                if (form == DW_FORM_REF4) {
                    requireAvailable(working, cursor.offset, 4);
                    references.add(new Reference(cursor.offset,
                        Integer.toUnsignedLong(buffer.getInt(cursor.offset))));
                    cursor.offset += 4;
                }
                else if (form == DW_FORM_SEC_OFFSET) {
                    if (attribute.name() != DW_AT_STMT_LIST &&
                            attribute.name() != DW_AT_LOCATION &&
                            attribute.name() != DW_AT_RANGES) {
                        throw new IllegalArgumentException(
                            "unreviewed oversized section-offset attribute " + attribute.name());
                    }
                    requireAvailable(working, cursor.offset, addressBytes);
                    int deleteStart = order == ByteOrder.LITTLE_ENDIAN
                        ? cursor.offset + 4 : cursor.offset;
                    deletions.add(new Deletion(deleteStart, deleteStart + 4));
                    cursor.offset += addressBytes;
                }
                else {
                    skipForm(working, cursor, form, addressBytes, 4, order);
                }
            }
        }
        if (deletions.isEmpty()) {
            throw new IllegalArgumentException(
                "expected at least one oversized section-offset attribute");
        }
        for (Reference reference : references) {
            long adjusted = adjust(reference.target(), deletions);
            buffer.putInt(reference.offset(), Math.toIntExact(adjusted));
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(
            working.length - deletions.size() * 4);
        int source = 0;
        for (Deletion deletion : deletions) {
            output.write(working, source, deletion.start() - source);
            source = deletion.end();
        }
        output.write(working, source, working.length - source);
        byte[] repaired = output.toByteArray();
        ByteBuffer.wrap(repaired).order(order).putInt(0, repaired.length - 4);
        return repaired;
    }

    private static long adjust(long target, List<Deletion> deletions) {
        long adjusted = target;
        for (Deletion deletion : deletions) {
            if (target >= deletion.end()) {
                adjusted -= deletion.end() - deletion.start();
            }
            else if (target > deletion.start()) {
                throw new IllegalArgumentException("reference points into removed bytes");
            }
        }
        return adjusted;
    }

    private static Map<Long, Abbreviation> parseAbbreviations(byte[] data, int start) {
        Cursor cursor = new Cursor(start);
        Map<Long, Abbreviation> result = new HashMap<>();
        while (cursor.offset < data.length) {
            long code = readUleb(data, cursor);
            if (code == 0) {
                break;
            }
            readUleb(data, cursor); // tag
            requireAvailable(data, cursor.offset, 1);
            cursor.offset++; // children flag
            List<Attribute> attributes = new ArrayList<>();
            while (true) {
                int name = Math.toIntExact(readUleb(data, cursor));
                int form = Math.toIntExact(readUleb(data, cursor));
                if (name == 0 && form == 0) {
                    break;
                }
                if (form == DW_FORM_IMPLICIT_CONST) {
                    readSleb(data, cursor);
                }
                attributes.add(new Attribute(name, form));
            }
            if (result.put(code, new Abbreviation(List.copyOf(attributes))) != null) {
                throw new IllegalArgumentException("duplicate abbreviation " + code);
            }
        }
        return result;
    }

    private static void skipForm(byte[] data, Cursor cursor, int form, int addressBytes,
            int offsetBytes, ByteOrder order) {
        switch (form) {
            case DW_FORM_ADDR -> cursor.offset += addressBytes;
            case DW_FORM_DATA1, DW_FORM_FLAG, DW_FORM_REF1 -> cursor.offset += 1;
            case DW_FORM_DATA2, DW_FORM_REF2 -> cursor.offset += 2;
            case DW_FORM_DATA4 -> cursor.offset += 4;
            case DW_FORM_DATA8, DW_FORM_REF8 -> cursor.offset += 8;
            case DW_FORM_STRP, DW_FORM_REF_ADDR -> cursor.offset += offsetBytes;
            case DW_FORM_STRING -> {
                boolean terminated = false;
                while (cursor.offset < data.length) {
                    if (data[cursor.offset++] == 0) {
                        terminated = true;
                        break;
                    }
                    // Scan the inline UTF-8 string.
                }
                if (!terminated) {
                    throw new IllegalArgumentException("unterminated DW_FORM_string");
                }
            }
            case DW_FORM_UDATA, DW_FORM_REF_UDATA -> readUleb(data, cursor);
            case DW_FORM_SDATA -> readSleb(data, cursor);
            case DW_FORM_BLOCK1 -> {
                requireAvailable(data, cursor.offset, 1);
                skipBlock(data, cursor, Byte.toUnsignedInt(data[cursor.offset++]));
            }
            case DW_FORM_BLOCK2 -> {
                requireAvailable(data, cursor.offset, 2);
                int length = Short.toUnsignedInt(ByteBuffer.wrap(data).order(order)
                    .getShort(cursor.offset));
                cursor.offset += 2;
                skipBlock(data, cursor, length);
            }
            case DW_FORM_BLOCK4 -> {
                requireAvailable(data, cursor.offset, 4);
                long length = Integer.toUnsignedLong(ByteBuffer.wrap(data).order(order)
                    .getInt(cursor.offset));
                cursor.offset += 4;
                skipBlock(data, cursor, Math.toIntExact(length));
            }
            case DW_FORM_BLOCK, DW_FORM_EXPRLOC ->
                skipBlock(data, cursor, Math.toIntExact(readUleb(data, cursor)));
            case DW_FORM_FLAG_PRESENT, DW_FORM_IMPLICIT_CONST -> {
                // No bytes in the DIE.
            }
            default -> throw new IllegalArgumentException(
                "unsupported DWARF form 0x" + Integer.toHexString(form));
        }
        requireAvailable(data, cursor.offset, 0);
    }

    private static void skipBlock(byte[] data, Cursor cursor, int length) {
        requireAvailable(data, cursor.offset, length);
        cursor.offset += length;
    }

    private static long readUleb(byte[] data, Cursor cursor) {
        long value = 0;
        int shift = 0;
        while (true) {
            requireAvailable(data, cursor.offset, 1);
            int next = Byte.toUnsignedInt(data[cursor.offset++]);
            if (shift >= 64 || (shift == 63 && (next & 0x7e) != 0)) {
                throw new IllegalArgumentException("ULEB128 overflow");
            }
            value |= (long) (next & 0x7f) << shift;
            if ((next & 0x80) == 0) {
                return value;
            }
            shift += 7;
        }
    }

    private static long readSleb(byte[] data, Cursor cursor) {
        long value = 0;
        int shift = 0;
        int next;
        do {
            requireAvailable(data, cursor.offset, 1);
            next = Byte.toUnsignedInt(data[cursor.offset++]);
            value |= (long) (next & 0x7f) << shift;
            shift += 7;
        } while ((next & 0x80) != 0 && shift < 64);
        if ((next & 0x80) != 0) {
            throw new IllegalArgumentException("SLEB128 overflow");
        }
        if (shift < 64 && (next & 0x40) != 0) {
            value |= -1L << shift;
        }
        return value;
    }

    private static void requireAvailable(byte[] data, int offset, int length) {
        if (offset < 0 || length < 0 || offset > data.length - length) {
            throw new IllegalArgumentException("truncated DWARF data");
        }
    }

    private static final class Cursor {
        private int offset;

        Cursor(int offset) {
            this.offset = offset;
        }
    }
}
