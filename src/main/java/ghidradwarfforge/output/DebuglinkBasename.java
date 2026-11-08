package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Explicit consumer filename policies for attachment. These methods encode
 * only a selected leaf; they never rename an artifact or change source paths.
 * Identity, discovery-directory and all-role alias checks remain mandatory.
 */
public final class DebuglinkBasename {
    private DebuglinkBasename() { }

    /** Linux GDB consumes the native UTF-8 filename bytes without transcoding. */
    public static byte[] linuxUtf8(Path sidecar) throws IOException {
        if (!"Linux".equals(System.getProperty("os.name"))) {
            throw new IOException("Linux UTF-8 debuglink policy requires a Linux host");
        }
        String nativeEncoding = System.getProperty("sun.jnu.encoding");
        try {
            if (nativeEncoding == null || !Charset.forName(nativeEncoding).equals(StandardCharsets.UTF_8)) {
                throw new IOException("Linux debuglink attachment requires UTF-8 native paths");
            }
        }
        catch (IllegalArgumentException invalid) {
            throw new IOException("Linux native filename encoding is unavailable", invalid);
        }
        return encode(leaf(sidecar), StandardCharsets.UTF_8);
    }

    /**
     * Portable subset for Windows production: no assumption about the eventual
     * debugger's non-ASCII filename code page. Unicode ancestors are unchanged;
     * the consumer must already be able to open the selected original there.
     */
    public static byte[] portableAscii(Path sidecar) throws IOException {
        return portableAsciiName(leaf(sidecar));
    }

    static byte[] portableAsciiName(String name) throws IOException {
        validate(name);
        if (name.chars().anyMatch(value -> value > 126 || "<>:\"/\\|?*".indexOf(value) >= 0) ||
                name.endsWith(".") || name.endsWith(" ")) {
            throw new IOException("attachment requires a portable ASCII debuglink basename; select a supported sidecar name");
        }
        String stem = name.split("\\.", 2)[0].stripTrailing().toUpperCase(Locale.ROOT);
        if (stem.matches("CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\\$|CONOUT\\$")) {
            throw new IOException("debuglink basename is a reserved Windows device name");
        }
        return encode(name, StandardCharsets.US_ASCII);
    }

    private static String leaf(Path path) throws IOException {
        Path leaf = path.getFileName();
        if (leaf == null) throw new IOException("debuglink requires a filename, not a filesystem root");
        String name = leaf.toString();
        // UnixPath can retain native bytes that its printable Java string loses.
        // A replacement character must not silently select a different sidecar.
        if (!Path.of(name).equals(leaf)) throw new IOException("debuglink basename cannot round-trip through native paths");
        validate(name);
        return name;
    }

    private static void validate(String name) throws IOException {
        if (name.isEmpty() || name.equals(".") || name.equals("..") ||
                name.chars().anyMatch(value -> value < 32 || value == 127 || value == '/')) {
            throw new IOException("debuglink basename contains a directory component or control character");
        }
    }

    private static byte[] encode(String name, Charset charset) throws IOException {
        var encoded = charset.newEncoder().encode(CharBuffer.wrap(name));
        if (encoded.remaining() == 0 || encoded.remaining() > 65536) {
            throw new IOException("debuglink basename exceeds the candidate format bound");
        }
        var bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        return bytes;
    }
}
