package ghidradwarfforge.elf;

import ghidradwarfforge.dwarf.SyntheticSourceRelocation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Relocates source references in a current Forge matched sidecar. Retains every
 * original byte except the changed sections' offset/size fields, and appends
 * their replacement payloads. No executable, source, registration or final output
 * is modified here. The caller owns an empty private staging channel and must
 * validate, synchronize and publish it through its installation transaction.
 * Inputs must be stable owned snapshots; ElfImage metadata checks alone do not
 * establish a race-free snapshot of a concurrently writable user file.
 */
public final class SyntheticSourceSidecar {
    private static final long COMPRESSED = 0x800;
    private static final int LIMIT = 64 * 1024 * 1024;
    private static final int CHUNK = 32 * 1024;
    private static final List<String> NAMES = List.of(".debug_info", ".debug_abbrev", ".debug_str", ".debug_line");

    private record Decoded(ElfImage.Section section, byte[] plain, int alignment) { }
    private record Change(long headerOffset, long payloadOffset, byte[] bytes) { }

    private SyntheticSourceSidecar() { }

    public static final class Plan {
        private final ElfImage image;
        private final List<Change> changes;
        private final long size;
        private final String previousDirectory;
        private final String fileName;
        private final List<String> sourceFiles;

        private Plan(ElfImage image, List<Change> changes, long size,
                String previousDirectory, String fileName, List<String> sourceFiles) {
            this.image = image;
            this.changes = List.copyOf(changes);
            this.size = size;
            this.previousDirectory = previousDirectory;
            this.fileName = fileName;
            this.sourceFiles = List.copyOf(sourceFiles);
        }

        public String previousDirectory() { return previousDirectory; }
        public String fileName() { return fileName; }
        public List<String> sourceFiles() { return sourceFiles; }
        public long outputSize() { return size; }

        /**
         * Read-only proof that a selected candidate is exactly this transformation.
         * The caller still brackets both paths with its native identity/hash checks.
         */
        public void requireMatches(Path candidate, BooleanSupplier cancelled) throws IOException {
            Objects.requireNonNull(cancelled, "cancellation");
            check(cancelled);
            try (var original = FileChannel.open(image.sourcePath(), java.nio.file.StandardOpenOption.READ);
                    var actual = FileChannel.open(candidate, java.nio.file.StandardOpenOption.READ)) {
                image.requireUnchanged(original);
                if (actual.size() != size) throw new IOException("derived sidecar length differs from relocation plan");
                byte[] expected = new byte[CHUNK];
                byte[] observed = new byte[CHUNK];
                for (long offset = 0; offset < size;) {
                    check(cancelled);
                    int count = (int) Math.min(CHUNK, size - offset);
                    Arrays.fill(expected, (byte) 0);
                    if (offset < image.fileSize()) {
                        int inherited = (int) Math.min(count, image.fileSize() - offset);
                        read(original, ByteBuffer.wrap(expected, 0, inherited), offset, cancelled);
                    }
                    for (Change change : changes) {
                        overlay(expected, offset, count, change.payloadOffset(), change.bytes());
                        ByteBuffer fields = ByteBuffer.allocate(image.is64Bit() ? 16 : 8).order(image.byteOrder());
                        if (image.is64Bit()) fields.putLong(change.payloadOffset()).putLong(change.bytes().length);
                        else fields.putInt((int) change.payloadOffset()).putInt(change.bytes().length);
                        overlay(expected, offset, count, change.headerOffset(), fields.array());
                    }
                    read(actual, ByteBuffer.wrap(observed, 0, count), offset, cancelled);
                    int difference = Arrays.mismatch(expected, 0, count, observed, 0, count);
                    if (difference >= 0) throw new IOException("derived sidecar differs from relocation plan at byte " + (offset + difference));
                    offset += count;
                }
                image.requireUnchanged(original);
                if (actual.size() != size) throw new IOException("derived sidecar length changed during comparison");
                check(cancelled);
            }
        }

        /** A failed/cancelled write leaves an unpublished stage for its owner to discard. */
        public void writeStage(FileChannel stage, BooleanSupplier cancelled) throws IOException {
            Objects.requireNonNull(stage, "private stage");
            Objects.requireNonNull(cancelled, "cancellation");
            check(cancelled);
            require(stage.size() == 0 && stage.position() == 0, "source relocation needs an empty private stage");
            image.copyTo(stage, cancelled);
            for (Change change : changes) {
                check(cancelled);
                // At most seven padding bytes: preserve the original section alignment.
                int padding = Math.toIntExact(change.payloadOffset() - stage.size());
                require(padding >= 0 && padding <= 7, "invalid planned source-section padding");
                write(stage, ByteBuffer.allocate(padding), stage.size(), cancelled);
                write(stage, ByteBuffer.wrap(change.bytes()), change.payloadOffset(), cancelled);
                ByteBuffer fields = ByteBuffer.allocate(image.is64Bit() ? 16 : 8).order(image.byteOrder());
                if (image.is64Bit()) fields.putLong(change.payloadOffset()).putLong(change.bytes().length);
                else fields.putInt((int) change.payloadOffset()).putInt(change.bytes().length);
                fields.flip();
                write(stage, fields, change.headerOffset(), cancelled);
            }
            require(stage.size() == size, "source relocation stage length differs from plan");
            check(cancelled);
        }
    }

    public static Plan prepare(Path sidecar, String directory, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(cancelled, "cancellation");
        check(cancelled);
        ElfImage image = ElfImage.read(sidecar);
        require(image.segments().isEmpty(), "source relocation requires a non-loadable Forge sidecar");
        ByteBuffer header = ByteBuffer.wrap(image.headerBytes()).order(image.byteOrder());
        int stride = Short.toUnsignedInt(header.getShort(image.is64Bit() ? 58 : 46));
        long table = image.is64Bit() ? header.getLong(40) : Integer.toUnsignedLong(header.getInt(32));
        require(table > 0 && stride >= (image.is64Bit() ? 64 : 40), "missing sidecar section table");
        Map<String, Decoded> decoded = new LinkedHashMap<>();
        for (String name : NAMES) {
            check(cancelled);
            var matches = image.sections().stream().filter(section -> section.name.equals(name)).toList();
            require(matches.size() == 1, "expected exactly one Forge source section " + name);
            var section = matches.getFirst();
            require(section.type == 1 && (section.flags & ~COMPRESSED) == 0 && section.address == 0 &&
                section.link == 0 && section.info == 0 && section.entrySize == 0,
                "unexpected Forge source-section attributes: " + name);
            require(section.alignment > 0 && section.alignment <= 8 &&
                (section.alignment & (section.alignment - 1)) == 0, "unsupported source-section alignment");
            require(section.size > 0 && section.size <= LIMIT, "source-section stored size exceeds limit");
            byte[] stored = image.sectionData(section);
            decoded.put(name, decode(section, stored, image.is64Bit(), image.byteOrder(), cancelled));
        }
        for (var section : image.sections()) {
            check(cancelled);
            if ((section.type == 4 || section.type == 9) && section.size != 0) {
                require(decoded.values().stream().noneMatch(value -> value.section().originalIndex == section.info),
                    "active relocations target a source section");
            }
        }
        var relocated = SyntheticSourceRelocation.relocate(decoded.get(".debug_info").plain(),
            decoded.get(".debug_abbrev").plain(), decoded.get(".debug_str").plain(),
            decoded.get(".debug_line").plain(), image.byteOrder(), directory, cancelled);
        Map<String, byte[]> replacements = new LinkedHashMap<>();
        replacements.put(".debug_info", relocated.info());
        replacements.put(".debug_str", relocated.strings());
        replacements.put(".debug_line", relocated.line());
        List<Change> changes = new ArrayList<>();
        long cursor = image.fileSize();
        for (var replacement : replacements.entrySet()) {
            check(cancelled);
            Decoded before = decoded.get(replacement.getKey());
            if (Arrays.equals(before.plain(), replacement.getValue())) continue;
            var section = before.section();
            byte[] payload = (section.flags & COMPRESSED) == 0 ? replacement.getValue() :
                compress(replacement.getValue(), image.is64Bit(), image.byteOrder(), before.alignment(), cancelled);
            cursor = Math.addExact(cursor, (section.alignment - cursor % section.alignment) % section.alignment);
            long field = Math.addExact(table, Math.addExact((long) stride * section.originalIndex,
                image.is64Bit() ? 24 : 16));
            long end = Math.addExact(field, image.is64Bit() ? 16 : 8);
            require(field >= Short.toUnsignedInt(header.getShort(image.is64Bit() ? 52 : 40)),
                "source section header overlaps the ELF header");
            // A malformed section table must not turn a header patch into an edit
            // of active code, notes, symbols, or unrelated DWARF payloads.
            for (var other : image.sections()) {
                check(cancelled);
                if (other.type != 0 && other.type != 8 && other.size != 0) {
                    require(end <= other.offset || field >= Math.addExact(other.offset, other.size),
                        "source section header overlaps an active section payload");
                }
            }
            changes.add(new Change(field, cursor, payload));
            cursor = Math.addExact(cursor, payload.length);
            require(image.is64Bit() || cursor <= 0xffff_ffffL, "relocated ELF32 exceeds 32-bit file offsets");
        }
        check(cancelled);
        return new Plan(image, changes, cursor, relocated.previousDirectory(), relocated.fileName(), relocated.sourceFiles());
    }

    private static Decoded decode(ElfImage.Section section, byte[] stored, boolean wide,
            ByteOrder order, BooleanSupplier cancelled) {
        if ((section.flags & COMPRESSED) == 0) return new Decoded(section, stored, (int) section.alignment);
        int headerSize = wide ? 24 : 12;
        require(stored.length >= headerSize, "truncated compressed source-section header");
        ByteBuffer header = ByteBuffer.wrap(stored).order(order);
        require(header.getInt() == 1, "unsupported source-section compression type");
        if (wide) require(header.getInt() == 0, "nonzero compressed source-section reserved field");
        long size = wide ? header.getLong() : Integer.toUnsignedLong(header.getInt());
        long alignment = wide ? header.getLong() : Integer.toUnsignedLong(header.getInt());
        require(size > 0 && size <= LIMIT, "decoded source-section size exceeds limit");
        require(alignment > 0 && alignment <= 8 && (alignment & (alignment - 1)) == 0,
            "unsupported decoded source-section alignment");
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(stored, headerSize, stored.length - headerSize);
            ByteArrayOutputStream plain = new ByteArrayOutputStream((int) Math.min(size, CHUNK));
            byte[] buffer = new byte[CHUNK];
            while (!inflater.finished()) {
                check(cancelled);
                int count;
                try { count = inflater.inflate(buffer); }
                catch (DataFormatException invalid) {
                    throw new IllegalArgumentException("invalid compressed source-section stream", invalid);
                }
                require(count <= size - plain.size(), "source-section stream exceeds declared size");
                plain.write(buffer, 0, count);
                require(count > 0 || inflater.finished(), "truncated, dictionary-dependent or stalled source stream");
            }
            require(plain.size() == size && inflater.getRemaining() == 0,
                "compressed source-section size mismatch or trailing input");
            check(cancelled);
            return new Decoded(section, plain.toByteArray(), (int) alignment);
        }
        finally { inflater.end(); }
    }

    private static byte[] compress(byte[] plain, boolean wide, ByteOrder order, int alignment,
            BooleanSupplier cancelled) {
        int headerSize = wide ? 24 : 12;
        Deflater compressor = new Deflater();
        try {
            ByteArrayOutputStream stored = new ByteArrayOutputStream(Math.min(plain.length, CHUNK));
            ByteBuffer header = ByteBuffer.allocate(headerSize).order(order).putInt(1);
            if (wide) header.putInt(0).putLong(plain.length).putLong(alignment);
            else header.putInt(plain.length).putInt(alignment);
            stored.writeBytes(header.array());
            byte[] chunk = new byte[CHUNK];
            int supplied = 0;
            while (!compressor.finished()) {
                check(cancelled);
                if (compressor.needsInput() && supplied < plain.length) {
                    int count = Math.min(CHUNK, plain.length - supplied);
                    compressor.setInput(plain, supplied, count);
                    supplied += count;
                    if (supplied == plain.length) compressor.finish();
                }
                int count = compressor.deflate(chunk);
                require(count <= LIMIT - stored.size(), "compressed source section exceeds stored-size limit");
                stored.write(chunk, 0, count);
                require(count > 0 || compressor.needsInput() || compressor.finished(), "source compression stalled");
            }
            check(cancelled);
            return stored.toByteArray();
        }
        finally { compressor.end(); }
    }

    private static void overlay(byte[] expected, long offset, int count, long start, byte[] patch) {
        long first = Math.max(offset, start);
        long last = Math.min(offset + count, start + patch.length);
        if (first < last) System.arraycopy(patch, (int) (first - start), expected,
            (int) (first - offset), (int) (last - first));
    }

    private static void read(FileChannel channel, ByteBuffer bytes, long position,
            BooleanSupplier cancelled) throws IOException {
        while (bytes.hasRemaining()) {
            check(cancelled);
            int count = channel.read(bytes, position);
            if (count <= 0) throw new IOException("source relocation comparison read made no progress");
            position += count;
        }
    }

    private static void write(FileChannel channel, ByteBuffer bytes, long position,
            BooleanSupplier cancelled) throws IOException {
        while (bytes.hasRemaining()) {
            check(cancelled);
            int limit = bytes.limit();
            bytes.limit(bytes.position() + Math.min(bytes.remaining(), CHUNK));
            int count = channel.write(bytes, position);
            bytes.limit(limit);
            if (count <= 0) throw new IOException("source relocation stage write made no progress");
            position += count;
        }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("source sidecar relocation cancelled");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}
