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

    private static void reject(Action action) throws Exception {
        try { action.run(); }
        catch (IOException expected) { return; }
        throw new AssertionError("Unsupported basename was accepted");
    }
    @FunctionalInterface private interface Action { void run() throws Exception; }
}
