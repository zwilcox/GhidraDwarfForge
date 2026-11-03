package ghidradwarfforge.output;

import com.google.gson.Gson;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;

/** Test-only own-token adjustment in an isolated JVM; never packaged as a helper. */
public final class WindowsFileSecurityProbe {
    private interface Kernel extends StdCallLibrary {
        Pointer GetCurrentProcess();
        int CloseHandle(Pointer handle);
    }
    private interface Tokens extends StdCallLibrary {
        int OpenProcessToken(Pointer process, int access, PointerByReference token);
        int LookupPrivilegeValueW(WString system, WString name, Pointer luid);
        int GetTokenInformation(Pointer token, int kind, Pointer data, int bytes, Pointer needed);
        int AdjustTokenPrivileges(Pointer token, int disableAll, Pointer state, int bytes, Pointer previous, Pointer needed);
    }

    private static final class OwnPrivilege implements AutoCloseable {
        private final Kernel kernel = Native.load("kernel32", Kernel.class);
        private final Tokens tokens = Native.load("advapi32", Tokens.class);
        private final Memory previous = new Memory(16);
        private Pointer token;
        private byte[] luidBytes;
        private int originalAttributes;
        private OwnPrivilege(boolean enabled) throws IOException {
            boolean retained = false;
            try (var luid = new Memory(8); var state = new Memory(16); var needed = new Memory(4)) {
                previous.clear(); luid.clear(); state.clear(); needed.clear();
                var output = new PointerByReference();
                check(tokens.OpenProcessToken(kernel.GetCurrentProcess(), 0x28, output) != 0, "OpenProcessToken");
                token = output.getValue();
                check(token != null, "missing own token");
                check(tokens.LookupPrivilegeValueW(null, new WString("SeSecurityPrivilege"), luid) != 0, "LookupPrivilegeValueW");
                luidBytes = luid.getByteArray(0, 8);
                originalAttributes = attributes();
                state.setInt(0, 1);
                state.write(4, luid.getByteArray(0, 8), 0, 8);
                state.setInt(12, enabled ? 2 : 0);
                Native.setLastError(0);
                int ok = tokens.AdjustTokenPrivileges(token, 0, state, 16, previous, needed);
                int error = Native.getLastError();
                check(ok != 0 && error == 0, "own token adjustment error=" + error);
                check(needed.getInt(0) <= 16 && previous.getInt(0) >= 0 && previous.getInt(0) <= 1,
                    "previous token state exceeds audited layout");
                check(((attributes() & 2) != 0) == enabled, "own token adjustment readback");
                retained = true;
            }
            finally {
                if (!retained) {
                    if (token != null) kernel.CloseHandle(token);
                    previous.close();
                }
            }
        }
        private int attributes() throws IOException {
            try (var needed = new Memory(4)) {
                int first = tokens.GetTokenInformation(token, 3, null, 0, needed);
                int error = Native.getLastError();
                int length = needed.getInt(0);
                check(first == 0 && error == 122 && length >= 4 && length <= 1024 * 1024, "token information sizing");
                try (var data = new Memory(length)) {
                    check(tokens.GetTokenInformation(token, 3, data, length, needed) != 0, "token information");
                    int count = data.getInt(0);
                    check(count >= 0 && count <= (length - 4) / 12, "token privilege count");
                    for (int i = 0; i < count; i++) {
                        int offset = 4 + i * 12;
                        if (java.util.Arrays.equals(luidBytes, data.getByteArray(offset, 8))) return data.getInt(offset + 8);
                    }
                    throw new IOException("Runner does not possess the test security privilege");
                }
            }
        }
        public void close() throws IOException {
            try {
                Native.setLastError(0);
                int ok = tokens.AdjustTokenPrivileges(token, 0, previous, 0, null, null);
                int error = Native.getLastError();
                check(ok != 0 && error == 0, "restore own privilege error=" + error);
                check(attributes() == originalAttributes, "restored own privilege differs");
            }
            finally {
                previous.close();
                check(kernel.CloseHandle(token) != 0, "CloseHandle own token");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        System.setOut(new java.io.PrintStream(System.out, true, java.nio.charset.StandardCharsets.UTF_8));
        if (args.length != 2) throw new IllegalArgumentException("mode owned-file");
        var security = new WindowsFileSecurity();
        Path path = Path.of(args[1]);
        try (var privilege = new OwnPrivilege(!args[0].equals("denied"))) {
            if (args[0].equals("cycles")) {
                var metadata = new WindowsFileMetadata();
                for (int i = 0; i < 32; i++) cycle(security, path);
                long before = metadata.processHandleCount();
                for (int i = 0; i < 128; i++) {
                    cycle(security, path);
                    check(before == metadata.processHandleCount(), "security native handle count grew");
                }
                System.out.println("windows-security-handles=PASS cycles=128 baseline=" + before);
                return;
            }
            var snapshot = security.inspect(path, () -> args[0].equals("cancel-before"), () -> {
                if (args[0].equals("cancel-open")) throw new CancellationException("security cancelled after open");
                if (args[0].equals("late")) {
                    Files.move(path, path.resolveSibling(path.getFileName() + ".retained"));
                    Files.writeString(path, "replacement sentinel");
                }
            });
            System.out.println(new Gson().toJson(snapshot));
        }
    }

    private static void cycle(WindowsFileSecurity security, Path path) throws Exception {
        security.inspect(path, () -> false);
        try {
            security.inspect(path, () -> false, () -> { throw new CancellationException("owned opened control"); });
            throw new AssertionError("security cancellation ignored");
        }
        catch (CancellationException expected) { }
    }
    private static void check(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message + " (win32=" + Native.getLastError() + ")");
    }
}
