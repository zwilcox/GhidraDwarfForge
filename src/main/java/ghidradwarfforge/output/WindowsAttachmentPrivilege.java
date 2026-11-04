package ghidradwarfforge.output;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;

/**
 * Enables only an already-owned SeSecurityPrivilege in the isolated helper's
 * own process token, and restores its original state. Never opens another
 * process, grants a missing privilege, requests UAC or adjusts Ghidra's token.
 * See docs/WINDOWS-ATTACHMENT-AUTHORIZATION.md for the audited native contract.
 */
final class WindowsAttachmentPrivilege implements AutoCloseable {
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

    private final Kernel kernel;
    private final Tokens tokens;
    private Pointer token;
    private long securityLuid;
    private int original;
    private boolean originalKnown;

    WindowsAttachmentPrivilege() throws IOException {
        if (!Platform.isWindows() || Native.POINTER_SIZE != 8 || !Platform.isIntel()) {
            throw new IOException("helper token adjustment requires the validated Windows x64 host");
        }
        kernel = Native.load("kernel32", Kernel.class);
        tokens = Native.load("advapi32", Tokens.class);
        try {
            var output = new PointerByReference();
            require(tokens.OpenProcessToken(kernel.GetCurrentProcess(), 0x28, output) != 0,
                "OpenProcessToken(TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES)");
            token = output.getValue();
            require(token != null, "OpenProcessToken returned no handle");
            try (var luid = new Memory(8)) {
                luid.clear();
                require(tokens.LookupPrivilegeValueW(null, new WString("SeSecurityPrivilege"), luid) != 0,
                    "LookupPrivilegeValueW(SeSecurityPrivilege)");
                securityLuid = luid.getLong(0);
            }
            original = attributes();
            require((original & 4) == 0, "SeSecurityPrivilege was removed from the helper token");
            originalKnown = true;
            if ((original & 2) == 0) adjust(true);
            require(attributes() == (original | 2), "enabled helper privilege differs from its expected state");
        }
        catch (IOException | RuntimeException failure) {
            try { close(); } catch (IOException | RuntimeException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    /** Readback is also used by the isolated native acceptance probe. */
    int attributes() throws IOException {
        require(token != null, "helper token scope is closed");
        try (var needed = new Memory(4)) {
            needed.clear();
            Native.setLastError(0);
            int first = tokens.GetTokenInformation(token, 3, null, 0, needed);
            int error = Native.getLastError();
            int length = needed.getInt(0);
            require(first == 0 && error == 122 && length >= 4 && length <= 1024 * 1024,
                "GetTokenInformation(TokenPrivileges) sizing failed, error=" + error);
            try (var data = new Memory(length)) {
                data.clear();
                require(tokens.GetTokenInformation(token, 3, data, length, needed) != 0,
                    "GetTokenInformation(TokenPrivileges)");
                int returned = needed.getInt(0);
                require(returned >= 4 && returned <= length, "token information returned invalid length");
                int count = data.getInt(0);
                require(count >= 0 && count <= (returned - 4) / 12, "token privilege array exceeds returned bytes");
                Integer found = null;
                for (int index = 0; index < count; index++) {
                    int offset = 4 + index * 12;
                    if (data.getLong(offset) == securityLuid) {
                        require(found == null, "duplicate SeSecurityPrivilege in helper token");
                        found = data.getInt(offset + 8);
                    }
                }
                require(found != null, "helper does not own SeSecurityPrivilege; explicit OS authorization is required");
                return found;
            }
        }
    }

    private void adjust(boolean enabled) throws IOException {
        try (var state = new Memory(16); var previous = new Memory(16); var needed = new Memory(4)) {
            state.clear(); previous.clear(); needed.clear();
            state.setInt(0, 1);
            state.setLong(4, securityLuid);
            state.setInt(12, enabled ? 2 : 0);
            Native.setLastError(0);
            int ok = tokens.AdjustTokenPrivileges(token, 0, state, 16, previous, needed);
            int error = Native.getLastError();
            // A TRUE result with ERROR_NOT_ALL_ASSIGNED is failure, not authority.
            require(ok != 0 && error == 0, "AdjustTokenPrivileges failed, error=" + error);
            int count = previous.getInt(0);
            require(needed.getInt(0) >= 4 && needed.getInt(0) <= 16 && count >= 0 && count <= 1,
                "previous privilege state exceeds the audited layout");
            require(count == 0 || previous.getLong(4) == securityLuid, "adjustment returned a different privilege");
        }
    }

    @Override public void close() throws IOException {
        if (token == null) return;
        Throwable failure = null;
        try {
            if (originalKnown) {
                if ((attributes() & 2) != (original & 2)) adjust((original & 2) != 0);
                require(attributes() == original, "helper privilege restoration readback differs");
            }
        }
        catch (IOException | RuntimeException problem) { failure = problem; }
        finally {
            Pointer owned = token;
            token = null;
            if (kernel.CloseHandle(owned) == 0) {
                var cleanup = new IOException("CloseHandle(helper token) failed, error=" + Native.getLastError());
                if (failure == null) failure = cleanup;
                else failure.addSuppressed(cleanup);
            }
        }
        if (failure instanceof IOException checked) throw checked;
        if (failure instanceof RuntimeException unchecked) throw unchecked;
    }

    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }
}
