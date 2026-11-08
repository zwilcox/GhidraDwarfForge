package ghidradwarfforge.elf;

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
            long end;
            try { end = Math.addExact(segment.virtualAddress, segment.memorySize - 1); }
            catch (ArithmeticException overflow) { throw new IllegalArgumentException("load address extent overflows", overflow); }
            if (!image.is64Bit() && end > 0xffff_ffffL) throw new IllegalArgumentException("load extent exceeds ELF address width");
            loads.add(new Load(segment.virtualAddress, end, segment.offset, segment.fileSize, segment.flags));
        }
        loads.sort(Comparator.comparingLong(Load::start));
        var ends = new long[loads.size()];
        for (int index = 0; index < loads.size(); index++) {
            check(cancelled);
            ends[index] = Math.max(index == 0 ? 0 : ends[index - 1], loads.get(index).end());
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
        if (address < 0 || decoded.length == 0 || decoded.length > 4096) {
            throw new IllegalArgumentException("invalid or unbounded instruction byte agreement request");
        }
        long end;
        try { end = Math.addExact(address, decoded.length - 1); }
        catch (ArithmeticException overflow) { throw new IllegalArgumentException("instruction address extent overflows", overflow); }
        int low = 0, high = loads.size();
        while (low < high) {
            check(cancelled);
            int middle = (low + high) >>> 1;
            if (loads.get(middle).start() <= end) low = middle + 1;
            else high = middle;
        }
        Load selected = null;
        for (int index = low - 1; index >= 0 && prefixEnds[index] >= address; index--) {
            check(cancelled);
            Load candidate = loads.get(index);
            if (candidate.end() < address) continue;
            if (selected != null) throw new IllegalArgumentException("instruction intersects overlapping ELF load mappings");
            selected = candidate;
        }
        if (selected == null || selected.start() > address || selected.end() < end) {
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

    @Override public void close() throws IOException { input.close(); }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("ELF instruction agreement cancelled");
    }
}
