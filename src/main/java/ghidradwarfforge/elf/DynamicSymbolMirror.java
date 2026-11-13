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
    private static final long VERNEED = 0x6ffffffeL;

    record Snapshot(int locals, byte[] records, byte[] names, byte[] indices,
            Set<ByteBuffer> existingNames, boolean versionedDefinitions) {
    }

    private DynamicSymbolMirror() {
    }

    record Input(int locals, byte[] records, byte[] names, byte[] indices, byte[] versions,
            byte[] definitions, long definitionCount, byte[] requirements, long requirementCount, int sectionCount) {
    }

    static Snapshot read(ElfImage image, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        Input input = image.sections().isEmpty() ? SectionlessDynamicSymbols.read(image, cancelled) :
            sectionInput(image, cancelled);
        if (input == null) {
            return null;
        }
        int width = image.is64Bit() ? 24 : 16;
        int count = input.records().length / width;
        var names = new Names(input.names(), cancelled);
        byte[] records = input.records();
        ByteBuffer rows = ByteBuffer.wrap(records).order(image.byteOrder());
        for (int index = 0; index < width; index++) {
            require(records[index] == 0, "dynamic null symbol is not zero");
        }
        byte[] extended = input.indices();
        ByteBuffer indices = extended == null ? null : ByteBuffer.wrap(extended).order(image.byteOrder());
        ByteBuffer versions = input.versions() == null ? null :
            ByteBuffer.wrap(input.versions()).order(image.byteOrder());
        Map<Integer, byte[]> versionNames = input.definitions() == null ? Map.of() :
            definitions(image, input.definitions(), input.definitionCount(), names, cancelled);
        Map<Integer, byte[]> requiredNames = input.requirements() == null ? Map.of() :
            requirements(image, input.requirements(), input.requirementCount(), names, cancelled);
        for (int identifier : requiredNames.keySet()) {
            checkCancelled(cancelled);
            require(!versionNames.containsKey(identifier), "conflicting definition/requirement version identifier");
        }
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
            require(((info >>> 4) == 0) == (index < input.locals()), "dynamic local/global order disagrees");
            require(section >= 0xff00 || section < input.sectionCount(), "dynamic section index is invalid");
            long escaped = indices == null ? 0 : Integer.toUnsignedLong(indices.getInt(index * 4));
            require(section == 0xffff ? escaped > 0 && escaped < input.sectionCount() : escaped == 0,
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
            boolean importedVersion = versionName == null;
            if (importedVersion) versionName = requiredNames.get(versionIndex);
            // Copy-relocated objects have defined storage, but their version
            // identity still comes from VERNEED rather than VERDEF. Do not infer
            // this distinction from section type (.dynbss need not be NOBITS).
            require(versionName != null, "defined dynamic symbol lacks a version definition or requirement");
            long value = image.is64Bit() ? rows.getLong(offset + 8) : Integer.toUnsignedLong(rows.getInt(offset + 4));
            // GNU's absolute version-node symbols retain their original spelling.
            if (section == 0xfff1 && value == 0 && Arrays.equals(name, versionName)) {
                continue;
            }
            require(name.length > 0, "versioned definition has an empty name");
            int separator = !importedVersion && (version & 0x8000) == 0 ? 2 : 1;
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
        return new Snapshot((int) input.locals(), records, text.toByteArray(), extended,
            Set.copyOf(occupied), versioned);
    }

    private static Input sectionInput(ElfImage image, BooleanSupplier cancelled) throws IOException {
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
        byte[] names = image.sectionData(strings);
        byte[] records = image.sectionData(table);
        ElfImage.Section indexSection = null;
        ElfImage.Section versionSection = null;
        ElfImage.Section definitions = null;
        ElfImage.Section requirements = null;
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
            if (section.type == VERNEED && section.link == table.link) {
                require(requirements == null && (section.flags & 0x800) == 0,
                    "ambiguous or compressed version requirements");
                requirements = section;
            }
        }
        require(definitions == null || versionSection != null, "version definitions lack symbol versions");
        require(requirements == null || versionSection != null, "version requirements lack symbol versions");
        return new Input((int) table.info, records, names,
            indexSection == null ? null : image.sectionData(indexSection),
            versionSection == null ? null : image.sectionData(versionSection),
            definitions == null ? null : image.sectionData(definitions),
            definitions == null ? 0 : definitions.info,
            requirements == null ? null : image.sectionData(requirements),
            requirements == null ? 0 : requirements.info, image.sections().size());
    }

    private static Map<Integer, byte[]> requirements(ElfImage image, byte[] data, long requirementCount,
            Names strings, BooleanSupplier cancelled) throws IOException {
        require(data.length >= 16 && data.length <= ElfImage.MAX_TABLE_BYTES &&
            requirementCount > 0 && requirementCount <= MAX_SYMBOLS, "unsupported version-requirement extent");
        ByteBuffer bytes = ByteBuffer.wrap(data).order(image.byteOrder());
        var names = new HashMap<Integer, byte[]>();
        int cursor = 0;
        long totalAux = 0;
        for (int index = 0; index < requirementCount; index++) {
            checkCancelled(cancelled);
            require(cursor <= bytes.limit() - 16, "truncated version requirement");
            int revision = Short.toUnsignedInt(bytes.getShort(cursor));
            int count = Short.toUnsignedInt(bytes.getShort(cursor + 2));
            byte[] file = strings.get(Integer.toUnsignedLong(bytes.getInt(cursor + 4)));
            long auxiliary = Integer.toUnsignedLong(bytes.getInt(cursor + 8));
            long next = Integer.toUnsignedLong(bytes.getInt(cursor + 12));
            require(revision == 1 && file.length > 0 && count > 0 && (totalAux += count) <= MAX_SYMBOLS &&
                auxiliary >= 16 && auxiliary <= bytes.limit() - cursor - 16L, "unsupported version requirement");
            long boundary = next == 0 ? bytes.limit() : (long) cursor + next;
            require(boundary <= bytes.limit() && boundary >= cursor + auxiliary + 16 &&
                (index + 1 == requirementCount) == (next == 0), "invalid version-requirement chain");
            int aux = (int) (cursor + auxiliary);
            for (int member = 0; member < count; member++) {
                checkCancelled(cancelled);
                require(aux <= boundary - 16, "truncated version requirement auxiliary");
                int flags = Short.toUnsignedInt(bytes.getShort(aux + 4));
                int identifier = Short.toUnsignedInt(bytes.getShort(aux + 6)) & 0x7fff;
                byte[] name = strings.get(Integer.toUnsignedLong(bytes.getInt(aux + 8)));
                require((flags & ~7) == 0 && identifier > 1 && name.length > 0,
                    "unsupported required version identifier or name");
                require(names.putIfAbsent(identifier, name) == null, "duplicate required version identifier");
                long following = Integer.toUnsignedLong(bytes.getInt(aux + 12));
                require((member + 1 == count) == (following == 0), "invalid version requirement auxiliary count");
                if (following != 0) {
                    require(following >= 16 && following <= boundary - aux - 16, "invalid version requirement auxiliary chain");
                    aux += (int) following;
                }
            }
            if (next != 0) cursor += (int) next;
        }
        return names;
    }

    private static Map<Integer, byte[]> definitions(ElfImage image, byte[] data, long definitionCount,
            Names strings, BooleanSupplier cancelled) throws IOException {
        require(data.length >= 20 && data.length <= ElfImage.MAX_TABLE_BYTES &&
            definitionCount > 0 && definitionCount <= MAX_SYMBOLS, "unsupported version-definition extent");
        ByteBuffer bytes = ByteBuffer.wrap(data).order(image.byteOrder());
        var names = new HashMap<Integer, byte[]>();
        int cursor = 0;
        long totalAux = 0;
        for (int index = 0; index < definitionCount; index++) {
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
                (index + 1 == definitionCount) == (next == 0), "invalid version-definition chain");
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
