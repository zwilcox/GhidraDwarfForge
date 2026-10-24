package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Observes GNU build-ID notes, without asserting file identity or attachment
 * eligibility. Equal IDs are only equal observed note bytes. Reads are not an
 * atomic snapshot: basic source-change checks cannot detect every concurrent edit.
 *
 * Both SHT_NOTE and PT_NOTE views are parsed, regardless of section names. Note
 * layout follows GNU binutils 2.42 readelf: alignment below four becomes four,
 * only four/eight are supported, and every record (including the last) must
 * include its padding. Padding values are unrestricted. Unlike readelf's display
 * prefix matching, recognition follows BFD's object-note rule: exact GNU NUL
 * owner, type three, nonempty descriptor. Malformed or unsupported views fail;
 * they are never reported as an absent ID. Nonempty compressed note sections
 * and the distinct OpenVMS IA-64 note-header format are unsupported.
 *
 * Explicit resource limits (not ELF format limits): 4096 nonempty views, 65536
 * record visits including duplicate views, 1 MiB per ID, 16 MiB of note bytes
 * actually read. At most 65536 record metadata entries are retained; descriptor
 * data for only the current and first ID is retained. Reads use at most 64 KiB
 * chunks. ElfImage's separate bounded metadata limits also apply. Cancellation
 * is checked around metadata parsing and each note/read, but cannot interrupt a
 * blocked filesystem operation or an in-progress ElfImage metadata parse.
 */
public final class ElfBuildId {
    static final int MAX_VIEWS = 4096;
    static final int MAX_NOTE_VISITS = 65536;
    static final int MAX_BUILD_ID_BYTES = 1024 * 1024;
    static final int MAX_READ_BYTES = 16 * 1024 * 1024;
    private static final int CHUNK_BYTES = 65536;
    private static final byte[] GNU_OWNER = { 'G', 'N', 'U', 0 };

    public enum ContainerKind { SECTION, SEGMENT }

    /** Physical container provenance; index is the original header-table index. */
    public record Container(ContainerKind kind, int index, long offset, long size,
            long declaredAlignment, int alignment) {
        public Container {
            Objects.requireNonNull(kind, "kind");
            if (index < 0 || offset < 0 || size <= 0 || size > Long.MAX_VALUE - offset ||
                    declaredAlignment < 0 || (alignment != 4 && alignment != 8)) {
                throw new IllegalArgumentException("invalid note container");
            }
        }
    }

    /** One physical GNU record, possibly exposed through several container views. */
    public record Occurrence(long noteOffset, long descriptorOffset,
            int descriptorSize, List<Container> containers) {
        public Occurrence {
            containers = List.copyOf(containers);
            if (noteOffset < 0 || noteOffset > Long.MAX_VALUE - 12 ||
                    descriptorOffset < noteOffset + 12 || descriptorSize <= 0 ||
                    descriptorSize > MAX_BUILD_ID_BYTES ||
                    descriptorOffset > Long.MAX_VALUE - descriptorSize || containers.isEmpty()) {
                throw new IllegalArgumentException("invalid build-ID occurrence");
            }
        }
    }

    public record Observation(Optional<String> hex, List<Occurrence> occurrences) {
        public Observation {
            Objects.requireNonNull(hex, "hex");
            occurrences = List.copyOf(occurrences);
            if (hex.isPresent() != !occurrences.isEmpty() ||
                    hex.isPresent() && (hex.get().isEmpty() ||
                    hex.get().length() > 2 * MAX_BUILD_ID_BYTES ||
                    (hex.get().length() & 1) != 0 || !hex.get().matches("[0-9a-f]+"))) {
                throw new IllegalArgumentException("invalid build-ID observation");
            }
        }
    }

    public enum Relationship {
        SAME_BUILD_ID, DIFFERENT_BUILD_IDS, ABSENT_BOTH,
        MISSING_FROM_ORIGINAL, MISSING_FROM_SIDECAR
    }

    private ElfBuildId() {
    }

    public static Observation read(Path path) throws IOException {
        return read(path, () -> false);
    }

    public static Observation read(Path path, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(cancelled, "cancelled");
        checkCancelled(cancelled);
        ElfImage image;
        try {
            image = ElfImage.read(path);
        }
        catch (IllegalArgumentException invalid) {
            throw new IOException("invalid ELF metadata for build-ID observation: " + invalid.getMessage(), invalid);
        }
        checkCancelled(cancelled);
        return new Reader(image, cancelled).read();
    }

    /** Compares observations only, not ELF identity, provenance, or authenticity. */
    public static Relationship compare(Observation original, Observation sidecar) {
        Objects.requireNonNull(original, "original");
        Objects.requireNonNull(sidecar, "sidecar");
        if (original.hex().isEmpty()) {
            return sidecar.hex().isEmpty() ? Relationship.ABSENT_BOTH : Relationship.MISSING_FROM_ORIGINAL;
        }
        if (sidecar.hex().isEmpty()) {
            return Relationship.MISSING_FROM_SIDECAR;
        }
        return original.hex().equals(sidecar.hex()) ? Relationship.SAME_BUILD_ID : Relationship.DIFFERENT_BUILD_IDS;
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("ELF build-ID observation cancelled");
        }
    }

    private record Layout(long start, long end, long nameSize, long type,
            long descriptorOffset, long descriptorSize) {
    }

    private static final class Found {
        private final Layout layout;
        private final List<Container> containers = new ArrayList<>();

        private Found(Layout layout) {
            this.layout = layout;
        }
    }

    private static final class Reader {
        private final ElfImage image;
        private final BooleanSupplier cancelled;
        private final TreeMap<Long, Layout> records = new TreeMap<>();
        private final TreeMap<Long, Found> found = new TreeMap<>();
        private int views;
        private int visits;
        private long readBytes;
        private byte[] firstId;

        private Reader(ElfImage image, BooleanSupplier cancelled) {
            this.image = image;
            this.cancelled = cancelled;
        }

        private Observation read() throws IOException {
            for (ElfImage.Section section : image.sections()) {
                checkCancelled(cancelled);
                if (section.type == 7 && section.size != 0) {
                    if ((section.flags & 0x800) != 0) {
                        throw new IOException("compressed SHT_NOTE is unsupported for build-ID observation");
                    }
                    parse(ContainerKind.SECTION, section.originalIndex, section.offset,
                        section.size, section.alignment);
                }
            }
            for (int index = 0; index < image.segments().size(); index++) {
                checkCancelled(cancelled);
                ElfImage.Segment segment = image.segments().get(index);
                if (segment.type == 4 && segment.fileSize != 0) {
                    parse(ContainerKind.SEGMENT, index, segment.offset, segment.fileSize, segment.alignment);
                }
            }
            List<Occurrence> occurrences = new ArrayList<>(found.size());
            for (Found value : found.values()) {
                Layout layout = value.layout;
                occurrences.add(new Occurrence(layout.start,
                    layout.descriptorOffset, (int) layout.descriptorSize, value.containers));
            }
            checkCancelled(cancelled);
            return new Observation(firstId == null ? Optional.empty() :
                Optional.of(HexFormat.of().formatHex(firstId)), occurrences);
        }

        private void parse(ContainerKind kind, int index, long offset, long size, long declared)
                throws IOException {
            String unsupported = ElfNoteFormats.unsupportedFormat(image);
            if (unsupported != null) {
                throw new IOException(unsupported + " is unsupported");
            }
            if (++views > MAX_VIEWS) {
                throw new IOException("note views exceed safety limit " + MAX_VIEWS);
            }
            long alignment = Math.max(4, declared);
            if (alignment != 4 && alignment != 8) {
                throw new IOException("unsupported note alignment " + declared + " in " + kind + " " + index);
            }
            Container container = new Container(kind, index, offset, size, declared, (int) alignment);
            long end = add(offset, size);
            long cursor = offset;
            while (cursor < end) {
                checkCancelled(cancelled);
                if (++visits > MAX_NOTE_VISITS) {
                    throw new IOException("note visits exceed safety limit " + MAX_NOTE_VISITS);
                }
                if (end - cursor < 12) {
                    throw new IOException("truncated note header at " + cursor + " in " + container);
                }
                ByteBuffer header = ByteBuffer.wrap(bytes(cursor, 12)).order(image.byteOrder());
                long names = Integer.toUnsignedLong(header.getInt());
                long descriptors = Integer.toUnsignedLong(header.getInt());
                long type = Integer.toUnsignedLong(header.getInt());
                long descriptorRelative = align(add(12, names), alignment);
                long nextRelative = align(add(descriptorRelative, descriptors), alignment);
                long next = add(cursor, nextRelative);
                if (next > end) {
                    throw new IOException("note payload/padding exceeds container at " + cursor);
                }
                long nameOffset = add(cursor, 12);
                if (names > 0 && bytes(add(nameOffset, names - 1), 1)[0] != 0) {
                    throw new IOException("unterminated note owner at " + cursor);
                }
                long descriptorOffset = add(cursor, descriptorRelative);
                Layout layout = new Layout(cursor, next, names, type, descriptorOffset, descriptors);
                checkOverlap(layout);
                if (type == 3 && names == GNU_OWNER.length &&
                        Arrays.equals(GNU_OWNER, bytes(nameOffset, GNU_OWNER.length))) {
                    if (descriptors == 0 || descriptors > MAX_BUILD_ID_BYTES) {
                        throw new IOException("GNU build-ID size is outside safety limit 1.." + MAX_BUILD_ID_BYTES);
                    }
                    byte[] id = bytes(descriptorOffset, (int) descriptors);
                    if (firstId != null && !Arrays.equals(firstId, id)) {
                        throw new IOException("conflicting GNU build IDs at physical note offset " + cursor);
                    }
                    if (firstId == null) {
                        firstId = id;
                    }
                    Found occurrence = found.computeIfAbsent(cursor, unused -> new Found(layout));
                    occurrence.containers.add(container);
                }
                cursor = next;
            }
        }

        private void checkOverlap(Layout layout) throws IOException {
            Map.Entry<Long, Layout> before = records.floorEntry(layout.start);
            if (before != null && before.getValue().end > layout.start) {
                Layout previous = before.getValue();
                if (previous.start == layout.start && previous.nameSize == layout.nameSize &&
                        previous.type == layout.type && previous.descriptorOffset == layout.descriptorOffset &&
                        previous.descriptorSize == layout.descriptorSize) {
                    // A complete 4-byte view can end before an 8-byte view's
                    // trailing pad. The physical record is still the same.
                    long end = Math.max(previous.end, layout.end);
                    Map.Entry<Long, Layout> following = records.higherEntry(layout.start);
                    if (following != null && following.getKey() < end) {
                        throw new IOException("incompatible overlapping note views at " + layout.start);
                    }
                    if (end != previous.end) {
                        records.put(layout.start, layout);
                    }
                    return;
                }
                throw new IOException("incompatible overlapping note views at " + layout.start);
            }
            Map.Entry<Long, Layout> after = records.ceilingEntry(layout.start);
            if (after != null && after.getKey() < layout.end) {
                throw new IOException("incompatible overlapping note views at " + layout.start);
            }
            records.put(layout.start, layout);
        }

        private byte[] bytes(long offset, int size) throws IOException {
            if (size > MAX_READ_BYTES - readBytes) {
                throw new IOException("note reads exceed safety limit " + MAX_READ_BYTES + " bytes");
            }
            readBytes += size;
            byte[] result = new byte[size];
            for (int position = 0; position < size;) {
                checkCancelled(cancelled);
                int count = Math.min(size - position, CHUNK_BYTES);
                byte[] chunk = image.readSourceRange(add(offset, position), count, "ELF note");
                System.arraycopy(chunk, 0, result, position, count);
                position += count;
                checkCancelled(cancelled);
            }
            return result;
        }
    }

    private static long add(long left, long right) throws IOException {
        if (left < 0 || right < 0 || right > Long.MAX_VALUE - left) {
            throw new IOException("ELF note offset arithmetic overflow");
        }
        return left + right;
    }

    private static long align(long value, long alignment) throws IOException {
        return add(value, alignment - 1) & -alignment;
    }
}
