package ghidradwarfforge.output;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.zip.CRC32;

/**
 * Bounded-memory digests of the bytes observed while reading a file.
 * This does not establish a stable snapshot, file identity, ELF compatibility,
 * or readiness to attach a debuglink. Concurrent edits can change observed bytes.
 */
public final class FileDigests {
    private static final int BUFFER_BYTES = 64 * 1024;

    /** CRC is an unsigned 32-bit value; byteCount counts bytes actually read. */
    public record Result(String sha256, long gnuDebuglinkCrc32, long byteCount) {
        public Result {
            if (sha256 == null || !sha256.matches("[0-9a-f]{64}") ||
                    gnuDebuglinkCrc32 < 0 || gnuDebuglinkCrc32 > 0xffff_ffffL ||
                    byteCount < 0) {
                throw new IllegalArgumentException("invalid file digest result");
            }
        }
    }

    @FunctionalInterface
    interface InputOpener {
        InputStream open(Path path) throws IOException;
    }

    private FileDigests() {
    }

    public static Result read(Path path) throws IOException {
        return read(path, () -> false);
    }

    /**
     * Reads the supplied path without rewriting it and closes its input stream.
     * Cancellation is checked before opening, between reads, and after EOF;
     * it cannot interrupt a filesystem read that is already blocked.
     */
    public static Result read(Path path, BooleanSupplier cancelled) throws IOException {
        return read(path, cancelled, Files::newInputStream);
    }

    /** Test seam: ownership of a successfully opened stream transfers to this method. */
    static Result read(Path path, BooleanSupplier cancelled, InputOpener opener)
            throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(opener, "opener");
        checkCancelled(cancelled);
        final MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
        CRC32 crc = new CRC32();
        long byteCount = 0;
        byte[] buffer = new byte[BUFFER_BYTES];
        try (InputStream input = opener.open(path)) {
            while (true) {
                checkCancelled(cancelled);
                int count = input.read(buffer);
                if (count == -1) {
                    break;
                }
                if (count <= 0 || count > buffer.length) {
                    throw new IOException("file digest input made no progress or returned an invalid count");
                }
                try {
                    byteCount = Math.addExact(byteCount, count);
                }
                catch (ArithmeticException overflow) {
                    throw new IOException("file digest byte count exceeds signed 64-bit range", overflow);
                }
                sha256.update(buffer, 0, count);
                crc.update(buffer, 0, count);
            }
            checkCancelled(cancelled);
            return new Result(HexFormat.of().formatHex(sha256.digest()), crc.getValue(), byteCount);
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("file digest cancelled");
        }
    }
}
