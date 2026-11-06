package ghidradwarfforge.elf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import ghidradwarfforge.unwind.OriginalFrameRanges;

/**
 * Complete named/program-header source inventory or an explicit failure.
 * This does not qualify runtime relocations or certify unwind rule semantics.
 * In particular, this result alone must not authorize synthesis in apparent gaps.
 */
public final class OriginalFrameSources {
    private static final long PT_GNU_EH_FRAME = 0x6474e550L;
    private static final long COMPRESSED = 0x800;
    private static final int MAX_BYTES = 64 * 1024 * 1024;
    private static final int CHUNK_BYTES = 32768;

    public record Source(String name, long offset, long storedBytes, long decodedBytes,
            long address, boolean programHeaders, String storedSha256, String decodedSha256,
            OriginalFrameRanges.Inventory records) { }
    public record Inventory(List<Source> sources) {
        public Inventory { sources = List.copyOf(sources); }
    }
    private OriginalFrameSources() { }

    public static Inventory inspect(ElfImage image, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        require(image.type() == 2 || image.type() == 3, "original frame sources require a linked ELF");
        var sections = new ArrayList<ElfImage.Section>();
        ElfImage.Section namedEh = null;
        boolean debugSeen = false, namedHeader = false, programHeader = false;
        for (var section : image.sections()) {
            check(cancelled);
            if (section.name.equals(".eh_frame_hdr") && section.size != 0) namedHeader = true;
            if (section.name.equals(".eh_frame")) {
                require(namedEh == null, "multiple named original EH frame sources");
                namedEh = section;
                sections.add(section);
            }
            if (section.name.equals(".debug_frame") || section.name.equals(".zdebug_frame")) {
                require(!debugSeen, "multiple original debug-frame encodings");
                debugSeen = true;
                sections.add(section);
            }
        }
        for (var segment : image.segments()) {
            check(cancelled);
            if (segment.type == PT_GNU_EH_FRAME) programHeader = true;
        }
        ElfImage.Section discovered = null;
        SectionlessUnwind.Discovery discovery = null;
        if (programHeader) {
            var diagnostics = new ArrayList<String>();
            discovery = SectionlessUnwind.inventoryFromProgramHeaders(image, cancelled, diagnostics::add);
            discovered = discovery == null ? null : discovery.section();
            require(discovered != null && diagnostics.isEmpty(),
                "original EH program-header coverage is unknown: " + diagnostics);
            if (namedEh == null) sections.add(discovered);
            else require(namedEh.offset == discovered.offset && namedEh.address == discovered.address &&
                namedEh.size >= discovered.size, "named and program-header EH extents disagree");
        }
        require(!namedHeader || namedEh != null || discovered != null,
            "named EH search header has no established frame source");
        var sources = new ArrayList<Source>();
        var budget = new Budget();
        try (var input = FileChannel.open(image.sourcePath(), StandardOpenOption.READ)) {
            image.requireUnchanged(input);
            for (var section : sections) {
                check(cancelled);
                require(section.type == 1, "original frame source is not PROGBITS");
                require(section.size <= MAX_BYTES - budget.stored, "original frame stored-byte budget exceeded");
                budget.stored += section.size;
                byte[] stored = read(image, input, section.offset, section.size, cancelled);
                if (section == namedEh && discovered != null) {
                    for (int index = (int) discovered.size; index < stored.length; index++) {
                        if ((index & (CHUNK_BYTES - 1)) == 0) check(cancelled);
                        require(stored[index] == 0, "named EH source contains records outside program-header extent");
                    }
                }
                byte[] plain = decode(stored, image.is64Bit(), image.byteOrder(), section.name,
                    section.flags, budget, cancelled);
                var format = section.name.equals(".eh_frame") ?
                    OriginalFrameRanges.Format.EH_FRAME : OriginalFrameRanges.Format.DEBUG_FRAME;
                var records = OriginalFrameRanges.read(plain, image.byteOrder(), image.is64Bit() ? 8 : 4,
                    format, section.address, cancelled);
                if (discovery != null && format == OriginalFrameRanges.Format.EH_FRAME) {
                    require(discovery.initialLocations().size() == records.frames().size(),
                        "EH search-table and frame inventory counts disagree");
                    for (var frame : records.frames()) {
                        check(cancelled);
                        Long expected = discovery.initialLocations().get(Math.addExact(section.address, frame.offset()));
                        require(expected != null && expected.longValue() == frame.address(),
                            "EH search-table location differs from referenced FDE");
                    }
                }
                sources.add(new Source(section.name, section.offset, stored.length, plain.length, section.address,
                    section == discovered || section == namedEh && discovered != null,
                    hash(stored, cancelled), hash(plain, cancelled), records));
            }
            image.requireUnchanged(input);
        }
        check(cancelled);
        return new Inventory(sources);
    }

    private static byte[] read(ElfImage image, FileChannel input, long offset, long size,
            BooleanSupplier cancelled) throws IOException {
        require(offset >= 0 && size >= 0 && offset <= image.fileSize() &&
            size <= image.fileSize() - offset && size <= MAX_BYTES, "invalid original frame source extent");
        image.requireUnchanged(input);
        var data = ByteBuffer.allocate((int) size);
        while (data.hasRemaining()) {
            check(cancelled);
            int limit = data.limit();
            data.limit(Math.min(limit, data.position() + CHUNK_BYTES));
            int count = input.read(data, offset + data.position());
            data.limit(limit);
            if (count <= 0) throw new IOException("original frame source read made no progress");
        }
        image.requireUnchanged(input);
        return data.array();
    }

    private static byte[] decode(byte[] stored, boolean wide, ByteOrder order, String name, long flags,
            Budget budget, BooleanSupplier cancelled) {
        check(cancelled);
        boolean gnu = name.equals(".zdebug_frame");
        boolean compressed = (flags & COMPRESSED) != 0;
        if (!gnu && !compressed) {
            budget.decoded(stored.length);
            return stored;
        }
        require(!name.equals(".eh_frame") && (flags & 2) == 0,
            "compressed allocated/EH frame source is unsupported");
        require(!gnu || !compressed, "mixed GNU and gABI frame compression");
        long size;
        int header;
        if (gnu) {
            header = 12;
            require(stored.length >= header && stored[0] == 'Z' && stored[1] == 'L' &&
                stored[2] == 'I' && stored[3] == 'B', "invalid GNU compressed frame header");
            size = ByteBuffer.wrap(stored).order(ByteOrder.BIG_ENDIAN).getLong(4);
        }
        else {
            header = wide ? 24 : 12;
            require(stored.length >= header, "truncated compressed frame header");
            var fields = ByteBuffer.wrap(stored).order(order);
            require(fields.getInt() == 1, "unsupported frame compression type");
            if (wide) require(fields.getInt() == 0, "nonzero reserved frame compression field");
            size = wide ? fields.getLong() : Integer.toUnsignedLong(fields.getInt());
            long alignment = wide ? fields.getLong() : Integer.toUnsignedLong(fields.getInt());
            require(alignment >= 0 && (alignment == 0 || (alignment & (alignment - 1)) == 0),
                "invalid original frame uncompressed alignment");
        }
        budget.decoded(size);
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(stored, header, stored.length - header);
            var plain = new ByteArrayOutputStream((int) Math.min(size, CHUNK_BYTES));
            byte[] chunk = new byte[CHUNK_BYTES];
            while (!inflater.finished()) {
                check(cancelled);
                int count;
                try { count = inflater.inflate(chunk); }
                catch (DataFormatException malformed) {
                    throw new IllegalArgumentException("invalid compressed frame stream", malformed);
                }
                require(count <= size - plain.size(), "compressed frame exceeds declared size");
                plain.write(chunk, 0, count);
                require(count > 0 || inflater.finished(), "truncated, dictionary-dependent or stalled frame stream");
            }
            require(plain.size() == size && inflater.getRemaining() == 0,
                "compressed frame size mismatch or trailing input");
            check(cancelled);
            return plain.toByteArray();
        }
        finally { inflater.end(); }
    }

    private static String hash(byte[] bytes, BooleanSupplier cancelled) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            for (int offset = 0; offset < bytes.length; offset += CHUNK_BYTES) {
                check(cancelled);
                digest.update(bytes, offset, Math.min(CHUNK_BYTES, bytes.length - offset));
            }
            return HexFormat.of().formatHex(digest.digest());
        }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }
    private static final class Budget {
        private long stored, decoded;
        private void decoded(long size) {
            require(size >= 0 && size <= MAX_BYTES - decoded, "original frame decoded-byte budget exceeded");
            decoded += size;
        }
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("original frame source inventory cancelled");
    }
}
