package ghidradwarfforge.output;

import com.sun.jna.Library;
import com.sun.jna.Native;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Linux namespace primitive, not a complete attachment host or metadata contract.
 * Signature and constants are audited in docs/ATTACHMENT-TRANSACTION-PROTOCOL.md.
 * No stat structure, native long, callback or native producer ABI is involved.
 */
public final class LinuxAtomicRename {
    private interface LibC extends Library {
        int renameat2(int oldDirectory, byte[] oldPath, int newDirectory, byte[] newPath, int flags);
    }

    private static final int AT_FDCWD = -100;
    private static final int RENAME_NOREPLACE = 1;
    private final LibC libc;

    public LinuxAtomicRename() throws IOException {
        if (!System.getProperty("os.name").equals("Linux")) {
            throw new IOException("Linux atomic rename requires a Linux host");
        }
        try {
            libc = Native.load("c", LibC.class);
        }
        catch (LinkageError | RuntimeException unavailable) {
            throw new IOException("Linux libc atomic rename is unavailable", unavailable);
        }
    }

    /** The caller owns and validates stage and destination; this only changes names. */
    public void publishNew(Path stage, Path destination) throws IOException {
        byte[] sourceBytes = pathBytes(stage);
        byte[] destinationBytes = pathBytes(destination);
        final int result;
        final int error;
        try {
            result = libc.renameat2(AT_FDCWD, sourceBytes, AT_FDCWD, destinationBytes, RENAME_NOREPLACE);
            error = Native.getLastError();
        }
        catch (LinkageError | RuntimeException unavailable) {
            throw new IOException("Linux atomic no-replace rename is unavailable", unavailable);
        }
        if (result != 0) {
            throw new IOException("Linux atomic no-replace rename failed (errno=" + error +
                ") from " + stage + " to " + destination);
        }
    }

    private static byte[] pathBytes(Path path) throws IOException {
        Path absolute = path.toAbsolutePath();
        String text = absolute.toString();
        // Linux paths can contain bytes that Java cannot round-trip as text.
        // Refuse these rather than selecting a different file through replacement characters.
        if (!Path.of(text).equals(absolute)) {
            throw new IOException("Linux attachment path cannot be represented losslessly");
        }
        byte[] utf8 = text.getBytes(StandardCharsets.UTF_8);
        return Arrays.copyOf(utf8, utf8.length + 1);
    }
}
