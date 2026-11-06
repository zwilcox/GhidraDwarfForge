package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.targets.UnwindRelocationProfile;

/**
 * Relative pointer candidates in declared RELRO. These are link-time values,
 * NOT runtime memory observations or proof that a loader has completed or that
 * protection is enforced. An explicit immutable-memory condition is required
 * before using any candidate in instruction analysis.
 */
public final class ElfRelocatedPointers {
    public record Pointer(long address, long value, long recordOffset, long fileOffset, String storedSha256) { }
    private ElfRelocatedPointers() { }

    public static List<Pointer> inspect(ElfImage image, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var profile = UnwindRelocationProfile.select(image);
        int width = image.is64Bit() ? 8 : 4;
        require(profile.fixedWidths().get(profile.relativeType()) == width, "relative relocation width differs from pointer width");
        var effects = ElfRelocationEffects.inspect(image, cancelled);
        var inventory = ElfRuntimeRelocations.inspect(image, cancelled);
        var result = new ArrayList<Pointer>();
        long comparisons = 0;
        try (var input = FileChannel.open(image.sourcePath(), StandardOpenOption.READ)) {
            image.requireUnchanged(input);
            for (var table : inventory.tables()) {
                if (table.format() != ElfRuntimeRelocations.Format.RELA) continue;
                for (var row : table.relocations()) {
                    check(cancelled);
                    // The selected profile defines symbol-zero RELATIVE as the
                    // object's load bias plus the explicit addend. No symbol,
                    // resolver, TLS, REL or RELR evaluation is guessed here.
                    if (row.info() == null || row.info() != profile.relativeType() || row.addend() == null || row.addend() < 0) continue;
                    long end = end(row.address(), width);
                    long fileOffset = -1;
                    int mappings = 0, targets = 0, protections = 0;
                    for (var segment : image.segments()) {
                        check(cancelled);
                        require(++comparisons <= 16L * 1024 * 1024, "relative pointer mapping budget exceeded");
                        if (segment.type == 1) {
                            long limit = end(segment.virtualAddress, segment.memorySize);
                            if (row.address() < limit && segment.virtualAddress < end) {
                                mappings++;
                                if (row.address() >= segment.virtualAddress && end <= end(segment.virtualAddress, segment.fileSize) &&
                                        (segment.flags & 6) == 6 && (segment.flags & 1) == 0) {
                                    fileOffset = end(segment.offset, row.address() - segment.virtualAddress);
                                }
                            }
                            if (row.addend() >= segment.virtualAddress && row.addend() < limit && (segment.flags & 4) != 0) targets++;
                        }
                        else if (segment.type == 0x6474e552L && row.address() >= segment.virtualAddress &&
                                end <= end(segment.virtualAddress, segment.memorySize)) protections++;
                    }
                    if (mappings != 1 || targets != 1 || protections != 1 || fileOffset < 0) continue;
                    int writers = 0;
                    for (var write : effects.writes()) {
                        check(cancelled);
                        require(++comparisons <= 16L * 1024 * 1024, "relative pointer writer budget exceeded");
                        if (row.address() < end(write.address(), write.size()) && write.address() < end) writers++;
                    }
                    require(writers == 1, "relative pointer has overlapping loader writes");
                    var bytes = ByteBuffer.allocate(width);
                    while (bytes.hasRemaining()) {
                        check(cancelled);
                        int count = input.read(bytes, fileOffset + bytes.position());
                        if (count <= 0) throw new IOException("short relative pointer input");
                    }
                    result.add(new Pointer(row.address(), row.addend(), row.recordOffset(), fileOffset, sha256(bytes.array())));
                    require(result.size() <= 64, "relative pointer candidate budget exceeded");
                }
            }
            image.requireUnchanged(input);
        }
        result.sort(Comparator.comparingLong(Pointer::address));
        check(cancelled);
        return List.copyOf(result);
    }

    private static long end(long start, long size) {
        require(start >= 0 && size >= 0, "negative relative pointer extent");
        try { return Math.addExact(start, size); }
        catch (ArithmeticException failure) { throw new IllegalArgumentException("relative pointer extent overflows", failure); }
    }
    private static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }
    private static void require(boolean value, String message) {
        if (!value) throw new IllegalArgumentException(message);
    }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("relative pointer inventory cancelled");
    }
}
