package ghidradwarfforge.elf;

import ghidradwarfforge.UnsignedAddress;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Bounded original-image instruction agreement using load mappings, never section-name guesses. */
public final class ElfCodeBytes implements AutoCloseable {
    private record Load(long start, long end, long offset, long fileSize, long flags) { }
    public record Match(long address, long fileOffset, int bytes, String sha256) { }
    private final ElfImage image;
    private final FileChannel input;
    private final List<Load> loads;
    private final long[] prefixEnds;

    private ElfCodeBytes(ElfImage image, FileChannel input, List<Load> loads, long[] prefixEnds) {
        this.image = image; this.input = input; this.loads = loads; this.prefixEnds = prefixEnds;
    }

    public static ElfCodeBytes open(ElfImage image, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(image);
        Objects.requireNonNull(cancelled);
        check(cancelled);
        if (image.type() != 2 && image.type() != 3) throw new IllegalArgumentException("code agreement requires a linked ELF image");
        var loads = new ArrayList<Load>();
        for (var segment : image.segments()) {
            check(cancelled);
            if (segment.type != 1 || segment.memorySize == 0) continue;
            long end = UnsignedAddress.lastByte(segment.virtualAddress, segment.memorySize);
            if (!image.is64Bit() && Long.compareUnsigned(end, 0xffff_ffffL) > 0) throw new IllegalArgumentException("load extent exceeds ELF address width");
            loads.add(new Load(segment.virtualAddress, end, segment.offset, segment.fileSize, segment.flags));
        }
        loads.sort(Comparator.comparing(Load::start, Long::compareUnsigned));
        var ends = new long[loads.size()];
        for (int index = 0; index < loads.size(); index++) {
            check(cancelled);
            long current = loads.get(index).end();
            ends[index] = index == 0 || Long.compareUnsigned(current, ends[index - 1]) > 0 ? current : ends[index - 1];
        }
        check(cancelled);
        FileChannel input = FileChannel.open(image.sourcePath(), StandardOpenOption.READ);
        try {
            image.requireUnchanged(input);
            check(cancelled);
            return new ElfCodeBytes(image, input, List.copyOf(loads), ends);
        }
        catch (Throwable failure) {
            try { input.close(); } catch (IOException closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    /**
     * Each instruction must have one unambiguous, executable, file-backed load
     * mapping. Overlapping or cross-segment instructions require another proof.
     * File identity checks detect observed changes but do not create a snapshot.
     */
    public Match requireMatches(long address, byte[] decoded, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        Objects.requireNonNull(decoded);
        if (decoded.length == 0 || decoded.length > 4096) {
            throw new IllegalArgumentException("invalid or unbounded instruction byte agreement request");
        }
        long end = UnsignedAddress.lastByte(address, decoded.length);
        int low = 0, high = loads.size();
        while (low < high) {
            check(cancelled);
            int middle = (low + high) >>> 1;
            if (Long.compareUnsigned(loads.get(middle).start(), end) <= 0) low = middle + 1;
            else high = middle;
        }
        Load selected = null;
        for (int index = low - 1; index >= 0 && Long.compareUnsigned(prefixEnds[index], address) >= 0; index--) {
            check(cancelled);
            Load candidate = loads.get(index);
            if (Long.compareUnsigned(candidate.end(), address) < 0) continue;
            if (selected != null) throw new IllegalArgumentException("instruction intersects overlapping ELF load mappings");
            selected = candidate;
        }
        if (selected == null || Long.compareUnsigned(selected.start(), address) > 0 || Long.compareUnsigned(selected.end(), end) < 0) {
            throw new IllegalArgumentException("instruction lacks one complete ELF load mapping");
        }
        long delta = address - selected.start();
        if ((selected.flags() & 1) == 0 || delta > selected.fileSize() || decoded.length > selected.fileSize() - delta) {
            throw new IllegalArgumentException("instruction is not executable file-backed ELF code");
        }
        long offset = Math.addExact(selected.offset(), delta);
        image.requireUnchanged(input);
        var original = ByteBuffer.allocate(decoded.length);
        while (original.hasRemaining()) {
            check(cancelled);
            if (input.read(original, offset + original.position()) <= 0) throw new IOException("original instruction bytes ended during comparison");
        }
        check(cancelled);
        image.requireUnchanged(input);
        if (!Arrays.equals(decoded, original.array())) {
            throw new IllegalArgumentException("decoded instruction differs from original ELF at " + Long.toHexString(address));
        }
        try {
            return new Match(address, offset, decoded.length,
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(original.array())));
        }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    /**
     * Read one bounded scalar from a unique, non-writable original load mapping.
     * The caller must separately reject loader writes; this does not evaluate
     * relocations or assert that a runtime process cannot change protections.
     */
    public byte[] readReadOnlyData(long address, int bytes, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        if (bytes < 1 || bytes > 8) throw new IllegalArgumentException("invalid scalar table read");
        long end = UnsignedAddress.lastByte(address, bytes);
        Load selected = null;
        for (var load : loads) {
            check(cancelled);
            if (Long.compareUnsigned(load.start(), end) > 0 || Long.compareUnsigned(load.end(), address) < 0) continue;
            if (selected != null || Long.compareUnsigned(load.start(), address) > 0 || Long.compareUnsigned(load.end(), end) < 0 ||
                    (load.flags() & 2) != 0 || address - load.start() > load.fileSize() ||
                    bytes > load.fileSize() - (address - load.start())) {
                throw new IllegalArgumentException("table lacks a unique non-writable file-backed load mapping");
            }
            selected = load;
        }
        if (selected == null) throw new IllegalArgumentException("table is outside original load mappings");
        long offset = Math.addExact(selected.offset(), address - selected.start());
        image.requireUnchanged(input);
        var buffer = ByteBuffer.allocate(bytes);
        while (buffer.hasRemaining()) {
            check(cancelled);
            if (input.read(buffer, offset + buffer.position()) <= 0) throw new IOException("short original table read");
        }
        check(cancelled);
        image.requireUnchanged(input);
        return buffer.array();
    }

    @Override public void close() throws IOException { input.close(); }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("ELF instruction agreement cancelled");
    }
}
