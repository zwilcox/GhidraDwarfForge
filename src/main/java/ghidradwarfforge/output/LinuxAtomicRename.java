package ghidradwarfforge.output;

import com.sun.jna.Library;
import com.sun.jna.Native;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.InvalidPathException;
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
    private static final int RENAME_EXCHANGE = 2;
    private final LibC libc;
    private final Charset pathCharset;

    public LinuxAtomicRename() throws IOException {
        this(Charset.forName(System.getProperty("sun.jnu.encoding")));
        if (!pathCharset.equals(StandardCharsets.UTF_8)) {
            throw new IOException("Linux atomic rename requires UTF-8 native paths");
        }
    }

    private LinuxAtomicRename(Charset pathCharset) throws IOException {
        if (!System.getProperty("os.name").equals("Linux")) {
            throw new IOException("Linux atomic rename requires a Linux host");
        }
        this.pathCharset = pathCharset;
        try {
            libc = Native.load("c", LibC.class);
        }
        catch (LinkageError | RuntimeException unavailable) {
            throw new IOException("Linux libc atomic rename is unavailable", unavailable);
        }
    }

    /** The caller owns and validates stage and destination; this only changes names. */
    public void publishNew(Path stage, Path destination) throws IOException {
        rename(stage, destination, RENAME_NOREPLACE, "no-replace");
    }

    /**
     * Consume an owned verified stage in one replacement rename. The caller
     * must bind/recheck the prior target, preserve metadata and flush both
     * affected directories. No copy fallback or durability claim is made here.
     */
    public void replaceAtomic(Path stage, Path target) throws IOException {
        rename(stage, target, 0, "replacement");
    }

    static LinuxAtomicRename forOutputExchange() throws IOException {
        return new LinuxAtomicRename(Charset.forName(System.getProperty("sun.jnu.encoding")));
    }

    /** Both directory entries stay present. The caller retains the exact displaced inode. */
    void exchange(Path privateName, Path target) throws IOException {
        rename(privateName, target, RENAME_EXCHANGE, "exchange");
    }

    private void rename(Path stage, Path destination, int flags, String operation) throws IOException {
        byte[] sourceBytes = pathBytes(stage);
        byte[] destinationBytes = pathBytes(destination);
        final int result;
        final int error;
        try {
            result = libc.renameat2(AT_FDCWD, sourceBytes, AT_FDCWD, destinationBytes, flags);
            error = Native.getLastError();
        }
        catch (LinkageError | RuntimeException unavailable) {
            throw new IOException("Linux atomic " + operation + " rename is unavailable", unavailable);
        }
        if (result != 0) {
            throw new IOException("Linux atomic " + operation + " rename failed (errno=" + error +
                ") from " + stage + " to " + destination);
        }
    }

    private byte[] pathBytes(Path path) throws IOException {
        Path absolute = path.toAbsolutePath();
        String text = absolute.toString();
        // Linux paths can contain bytes that Java cannot round-trip as text.
        // Refuse these rather than selecting a different file through replacement characters.
        try {
            if (!pathCharset.newEncoder().canEncode(text) || !Path.of(text).equals(absolute)) {
                throw new IOException("Linux rename path cannot be represented losslessly");
            }
        }
        catch (InvalidPathException invalid) {
            throw new IOException("Linux rename path cannot be represented losslessly", invalid);
        }
        byte[] bytes = text.getBytes(pathCharset);
        return Arrays.copyOf(bytes, bytes.length + 1);
    }
}
