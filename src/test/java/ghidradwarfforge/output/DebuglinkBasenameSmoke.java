package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

/** Isolated filename policy checks; does not supply an attachment Host. */
public final class DebuglinkBasenameSmoke {
    public static void main(String[] args) throws Exception {
        int checks = 0;
        if (args.length == 2 && args[0].equals("raw-paths")) {
            int accepted = 0, rejected = 0;
            try (var paths = Files.newDirectoryStream(Path.of(args[1]))) {
                for (Path path : paths) {
                    try {
                        byte[] name = DebuglinkBasename.linuxUtf8(path);
                        if (!HexFormat.of().formatHex(name).equals("736861646f77efbfbd2e646267")) {
                            throw new AssertionError("Unexpected literal native path");
                        }
                        accepted++;
                    }
                    catch (IOException failure) {
                        if (!failure.getMessage().contains("round-trip")) throw failure;
                        rejected++;
                    }
                }
            }
            if (accepted != 1 || rejected != 1) throw new AssertionError("Raw byte alias control was not exercised");
            System.out.println("debuglink-native-bytes=PASS accepted=1 rejected=1");
            return;
        }
        if (args.length == 1 && args[0].equals("non-utf8")) {
            reject(() -> DebuglinkBasename.linuxUtf8(Path.of("plain.dbg")));
            System.out.println("debuglink-native-encoding=REJECTED " + System.getProperty("sun.jnu.encoding"));
            return;
        }
        if (args.length != 0) throw new IllegalArgumentException("no args | raw-paths directory | non-utf8");
        checks += boundaries();
        for (String name : new String[]{"app.dbg", ".hidden.dbg", "name ;$['literal'].dbg", "COM10.dbg", "two words.dbg"}) {
            byte[] actual = DebuglinkBasename.portableAscii(Path.of("parent").resolve(name));
            if (!Arrays.equals(name.getBytes(StandardCharsets.US_ASCII), actual)) throw new AssertionError("Portable bytes changed");
            checks++;
        }
        for (String name : new String[]{"", ".", "..", "λ.dbg", "name\n.dbg", "name\r.dbg", "name\u007f.dbg",
                "NUL", "nul.dbg", "CoN.tar.dbg", "COM1.dbg", "LPT9.dbg", "CON .dbg", "CONIN$", "CONOUT$",
                "trailing.", "trailing ", "a:b", "a\\b", "a/b", "a?b", "a*b", "a\"b", "a<b", "a>b", "a|b"}) {
            reject(() -> DebuglinkBasename.portableAsciiName(name));
            checks++;
        }
        if ("Linux".equals(System.getProperty("os.name")) &&
                Charset.forName(System.getProperty("sun.jnu.encoding")).equals(StandardCharsets.UTF_8)) {
            String name = "literal λ ;$['quoted']\\name.dbg";
            if (!Arrays.equals(name.getBytes(StandardCharsets.UTF_8), DebuglinkBasename.linuxUtf8(Path.of(name)))) {
                throw new AssertionError("UTF-8 bytes changed");
            }
            reject(() -> DebuglinkBasename.linuxUtf8(Path.of("..")));
            reject(() -> DebuglinkBasename.linuxUtf8(Path.of("bad\nname")));
            checks += 3;
        }
        System.out.println("debuglink-basename=PASS checks=" + checks);
    }

    private static int boundaries() throws Exception {
        int checks = 0;
        Path root = Path.of(".").toAbsolutePath().getRoot();
        reject(() -> DebuglinkBasename.portableAscii(root));
        checks++;
        // These are encoder-format limits, not filesystem filename limits.
        // No file with a large name is created or claimed to be discoverable.
        String ascii = "a".repeat(65536);
        byte[] accepted;
        try { accepted = DebuglinkBasename.portableAsciiName(ascii); }
        catch (IOException refused) { throw new AssertionError("exact encoded-byte limit refused", refused); }
        if (!Arrays.equals(ascii.getBytes(StandardCharsets.US_ASCII), accepted)) {
            throw new AssertionError("ASCII basename bytes changed at format bound");
        }
        reject(() -> DebuglinkBasename.portableAsciiName(ascii + "a"));
        checks += 2;
        for (int control = 0; control < 32; control++) {
            String name = "before" + (char) control + "after.dbg";
            reject(() -> DebuglinkBasename.portableAsciiName(name));
            checks++;
        }
        String os = System.getProperty("os.name");
        String encoding = System.getProperty("sun.jnu.encoding");
        try {
            // Test refusal of invalid advertised host metadata. Setting these
            // properties does not change the real host or its native encoding.
            System.setProperty("os.name", "Unsupported-test-host");
            reject(() -> DebuglinkBasename.linuxUtf8(Path.of("test.dbg")));
            checks++;
        }
        finally { restoreProperty("os.name", os); }
        if ("Linux".equals(os)) {
            try {
                System.clearProperty("sun.jnu.encoding");
                reject(() -> DebuglinkBasename.linuxUtf8(Path.of("test.dbg")));
                System.setProperty("sun.jnu.encoding", "invalid charset ?");
                reject(() -> DebuglinkBasename.linuxUtf8(Path.of("test.dbg")));
                System.setProperty("sun.jnu.encoding", "US-ASCII");
                reject(() -> DebuglinkBasename.linuxUtf8(Path.of("test.dbg")));
                checks += 3;
            }
            finally { restoreProperty("sun.jnu.encoding", encoding); }
            if (encoding != null && Charset.forName(encoding).equals(StandardCharsets.UTF_8)) {
                for (String exact : new String[] {"λ".repeat(32768), "😀".repeat(16384)}) {
                    byte[] expected = exact.getBytes(StandardCharsets.UTF_8);
                    if (expected.length != 65536) throw new AssertionError("invalid UTF-8 boundary fixture");
                    try { accepted = DebuglinkBasename.linuxUtf8(Path.of(exact)); }
                    catch (IOException refused) { throw new AssertionError("exact UTF-8 bound refused", refused); }
                    if (!Arrays.equals(expected, accepted)) throw new AssertionError("UTF-8 basename bytes changed");
                    reject(() -> DebuglinkBasename.linuxUtf8(Path.of(exact + "a")));
                    checks += 2;
                }
                reject(() -> DebuglinkBasename.linuxUtf8(root));
                checks++;
            }
        }
        if (!java.util.Objects.equals(os, System.getProperty("os.name")) ||
                !java.util.Objects.equals(encoding, System.getProperty("sun.jnu.encoding"))) {
            throw new AssertionError("basename metadata controls leaked process properties");
        }
        return checks;
    }

    private static void restoreProperty(String key, String value) {
        if (value == null) System.clearProperty(key);
        else System.setProperty(key, value);
    }

    private static void reject(Action action) throws Exception {
        try { action.run(); }
        catch (IOException expected) { return; }
        throw new AssertionError("Unsupported basename was accepted");
    }
    @FunctionalInterface private interface Action { void run() throws Exception; }
}
