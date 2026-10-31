package ghidradwarfforge.elf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Bounded original dynamic inventory for a separate, nonallocated static mirror. */
final class DynamicSymbolMirror {
    private static final int MAX_SYMBOLS = 262144;
    private static final long VERSYM = 0x6fffffffL;
    private static final long VERDEF = 0x6ffffffdL;

    record Snapshot(int locals, byte[] records, byte[] names, byte[] indices,
            Set<ByteBuffer> existingNames, boolean versionedDefinitions) {
    }

    private DynamicSymbolMirror() {
    }

    static Snapshot read(ElfImage image, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        ElfImage.Section table = null;
        for (var section : image.sections()) {
            checkCancelled(cancelled);
            if (section.type == 11) {
                require(table == null, "multiple dynamic symbol tables");
                table = section;
            }
        }
        if (table == null) {
            return null;
        }
        int width = image.is64Bit() ? 24 : 16;
        require(table.entrySize == width && table.size >= width && table.size % width == 0 &&
            table.size / width <= MAX_SYMBOLS && table.info >= 1 && table.info <= table.size / width &&
            (table.flags & 0x800) == 0 && table.link > 0 && table.link < image.sections().size(),
            "unsupported dynamic symbol framing");
        var strings = image.sections().get((int) table.link);
        require(strings.type == 3 && (strings.flags & 0x800) == 0 && strings.size > 0 &&
            strings.size <= ElfImage.MAX_NAME_TABLE_BYTES, "unsupported dynamic string table");
        int count = (int) (table.size / width);
        var names = new Names(image.sectionData(strings), cancelled);
        byte[] records = image.sectionData(table);
        ByteBuffer rows = ByteBuffer.wrap(records).order(image.byteOrder());
        for (int index = 0; index < width; index++) {
            require(records[index] == 0, "dynamic null symbol is not zero");
        }
        ElfImage.Section indexSection = null;
        ElfImage.Section versionSection = null;
        ElfImage.Section definitions = null;
        for (var section : image.sections()) {
            checkCancelled(cancelled);
            if (section.type == 18 && section.link == table.originalIndex) {
                require(indexSection == null && section.size == count * 4L && section.entrySize == 4 &&
                    section.info == 0 && (section.flags & 0x800) == 0, "unsupported dynamic extended indices");
                indexSection = section;
            }
            if (section.type == VERSYM && section.link == table.originalIndex) {
                require(versionSection == null && section.size == count * 2L && section.entrySize == 2 &&
                    (section.flags & 0x800) == 0, "unsupported dynamic symbol versions");
                versionSection = section;
            }
            if (section.type == VERDEF && section.link == table.link) {
                require(definitions == null && (section.flags & 0x800) == 0,
                    "ambiguous or compressed version definitions");
                definitions = section;
            }
        }
        require(definitions == null || versionSection != null, "version definitions lack symbol versions");
        byte[] extended = indexSection == null ? null : image.sectionData(indexSection);
        ByteBuffer indices = extended == null ? null : ByteBuffer.wrap(extended).order(image.byteOrder());
        ByteBuffer versions = versionSection == null ? null :
            ByteBuffer.wrap(image.sectionData(versionSection)).order(image.byteOrder());
        Map<Integer, byte[]> versionNames = definitions == null ? Map.of() :
            definitions(image, definitions, names, cancelled);
        ByteArrayOutputStream text = new ByteArrayOutputStream();
        text.writeBytes(names.bytes);
        Set<ByteBuffer> occupied = new HashSet<>();
        Map<ByteBuffer, Integer> appended = new HashMap<>();
        boolean versioned = false;
        for (int index = 0; index < count; index++) {
            checkCancelled(cancelled);
            int offset = index * width;
            int info = Byte.toUnsignedInt(records[offset + (image.is64Bit() ? 4 : 12)]);
            int section = Short.toUnsignedInt(rows.getShort(offset + (image.is64Bit() ? 6 : 14)));
            require(((info >>> 4) == 0) == (index < table.info), "dynamic local/global order disagrees");
            require(section >= 0xff00 || section < image.sections().size(), "dynamic section index is invalid");
            long escaped = indices == null ? 0 : Integer.toUnsignedLong(indices.getInt(index * 4));
            require(section == 0xffff ? escaped > 0 && escaped < image.sections().size() : escaped == 0,
                "dynamic extended section index is invalid");
            byte[] name = names.get(Integer.toUnsignedLong(rows.getInt(offset)));
            occupied.add(ByteBuffer.wrap(name).asReadOnlyBuffer());
            if (versions == null) {
                continue;
            }
            int version = Short.toUnsignedInt(versions.getShort(index * 2));
            int versionIndex = version & 0x7fff;
            if (index == 0) {
                require(version == 0, "dynamic null symbol has a version");
            }
            if (section == 0 || versionIndex <= 1) {
                continue;
            }
            byte[] versionName = versionNames.get(versionIndex);
            require(versionName != null, "defined dynamic symbol lacks a version definition");
            long value = image.is64Bit() ? rows.getLong(offset + 8) : Integer.toUnsignedLong(rows.getInt(offset + 4));
            // GNU's absolute version-node symbols retain their original spelling.
            if (section == 0xfff1 && value == 0 && Arrays.equals(name, versionName)) {
                continue;
            }
            require(name.length > 0, "versioned definition has an empty name");
            int separator = (version & 0x8000) == 0 ? 2 : 1;
            require((long) name.length + separator + versionName.length <= ElfImage.MAX_NAME_BYTES,
                "qualified dynamic name exceeds limit");
            byte[] qualified = Arrays.copyOf(name, name.length + separator + versionName.length);
            Arrays.fill(qualified, name.length, name.length + separator, (byte) '@');
            System.arraycopy(versionName, 0, qualified, name.length + separator, versionName.length);
            var key = ByteBuffer.wrap(qualified).asReadOnlyBuffer();
            Integer position = appended.get(key);
            if (position == null) {
                require((long) text.size() + qualified.length + 1 <= ElfImage.MAX_NAME_TABLE_BYTES,
                    "qualified dynamic string table exceeds limit");
                position = text.size();
                text.writeBytes(qualified);
                text.write(0);
                appended.put(key, position);
            }
            occupied.add(key);
            rows.putInt(offset, position);
            versioned = true;
        }
        checkCancelled(cancelled);
        return new Snapshot((int) table.info, records, text.toByteArray(), extended,
            Set.copyOf(occupied), versioned);
    }

    private static Map<Integer, byte[]> definitions(ElfImage image, ElfImage.Section section,
            Names strings, BooleanSupplier cancelled) throws IOException {
        require(section.size >= 20 && section.size <= ElfImage.MAX_TABLE_BYTES &&
            section.info > 0 && section.info <= MAX_SYMBOLS, "unsupported version-definition extent");
        ByteBuffer bytes = ByteBuffer.wrap(image.sectionData(section)).order(image.byteOrder());
        var names = new HashMap<Integer, byte[]>();
        int cursor = 0;
        long totalAux = 0;
        for (int index = 0; index < section.info; index++) {
            checkCancelled(cancelled);
            require(cursor <= bytes.limit() - 20, "truncated version definition");
            int revision = Short.toUnsignedInt(bytes.getShort(cursor));
            int flags = Short.toUnsignedInt(bytes.getShort(cursor + 2));
            int identifier = Short.toUnsignedInt(bytes.getShort(cursor + 4));
            int count = Short.toUnsignedInt(bytes.getShort(cursor + 6));
            long auxiliary = Integer.toUnsignedLong(bytes.getInt(cursor + 12));
            long next = Integer.toUnsignedLong(bytes.getInt(cursor + 16));
            require(revision == 1 && (flags & ~7) == 0 && identifier > 0 && identifier < 0x8000 &&
                count > 0 && (totalAux += count) <= MAX_SYMBOLS && auxiliary >= 20 &&
                auxiliary <= bytes.limit() - cursor - 8L, "unsupported version definition");
            long boundary = next == 0 ? bytes.limit() : (long) cursor + next;
            require(boundary <= bytes.limit() && boundary >= cursor + auxiliary + 8 &&
                (index + 1 == section.info) == (next == 0), "invalid version-definition chain");
            int aux = (int) (cursor + auxiliary);
            for (int member = 0; member < count; member++) {
                checkCancelled(cancelled);
                require(aux <= boundary - 8, "truncated version auxiliary");
                byte[] name = strings.get(Integer.toUnsignedLong(bytes.getInt(aux)));
                require(name.length > 0, "empty version name");
                if (member == 0) {
                    require(names.putIfAbsent(identifier, name) == null, "duplicate version identifier");
                }
                long following = Integer.toUnsignedLong(bytes.getInt(aux + 4));
                require((member + 1 == count) == (following == 0), "invalid version auxiliary count");
                if (following != 0) {
                    require(following >= 8 && following <= boundary - aux - 8, "invalid version auxiliary chain");
                    aux += (int) following;
                }
            }
            if (next != 0) {
                cursor += (int) next;
            }
        }
        return names;
    }

    private static final class Names {
        private final byte[] bytes;
        private final BooleanSupplier cancelled;
        private final Map<Integer, byte[]> cached = new HashMap<>();
        private long total;

        private Names(byte[] bytes, BooleanSupplier cancelled) {
            require(bytes[0] == 0 && bytes[bytes.length - 1] == 0, "dynamic string boundary is not terminated");
            this.bytes = bytes;
            this.cancelled = cancelled;
        }

        private byte[] get(long offset) {
            require(offset < bytes.length, "dynamic string offset is invalid");
            int start = (int) offset;
            byte[] previous = cached.get(start);
            if (previous != null) {
                return previous;
            }
            int end = start;
            while (bytes[end] != 0) {
                if ((end & 1023) == 0) {
                    checkCancelled(cancelled);
                }
                require(++end - start <= ElfImage.MAX_NAME_BYTES, "dynamic name exceeds limit");
            }
            require((total += end - start) <= ElfImage.MAX_NAME_TABLE_BYTES, "dynamic names exceed aggregate limit");
            byte[] value = Arrays.copyOfRange(bytes, start, end);
            cached.put(start, value);
            return value;
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("dynamic symbol inventory cancelled");
        }
    }
}
