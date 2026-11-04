package ghidradwarfforge.output;

import java.io.IOException;

/** Runs only in an isolated, already authorized Windows CI fixture process. */
public final class WindowsAttachmentPrivilegeProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 0) throw new IllegalArgumentException("no arguments expected");
        var metadata = new WindowsFileMetadata();
        try (var control = new WindowsFileSecurityProbe.OwnPrivilege(false)) {
            int original = control.attributes();
            require((original & 2) == 0, "test setup did not disable the owned security privilege");
            for (int index = 0; index < 16; index++) exercise(control, original);
            long handles = metadata.processHandleCount();
            for (int index = 0; index < 128; index++) {
                exercise(control, original);
                require(metadata.processHandleCount() == handles, "helper token scope leaked a native handle");
            }
            System.out.println("windows-attachment-privilege=PASS cycles=128 originalAttributes=" + original +
                " handles=" + handles + " restored=true already-enabled=true exceptional-exit=true");
        }
    }

    private static void exercise(WindowsFileSecurityProbe.OwnPrivilege control, int original) throws Exception {
        try {
            try (var scope = new WindowsAttachmentPrivilege()) {
                require(scope.attributes() == (original | 2) && control.attributes() == (original | 2),
                    "production scope did not enable precisely the selected privilege");
                try (var nested = new WindowsAttachmentPrivilege()) {
                    require(nested.attributes() == (original | 2), "already-enabled scope changed state");
                }
                require(control.attributes() == (original | 2), "nested scope disabled the outer owned privilege");
                throw new IOException("owned operation failure");
            }
        }
        catch (IOException expected) {
            require(expected.getMessage().equals("owned operation failure") && expected.getSuppressed().length == 0,
                "native scope failed rather than the injected operation");
        }
        require(control.attributes() == original, "failed operation did not restore original token state");
        var scope = new WindowsAttachmentPrivilege();
        scope.close();
        scope.close();
        require(control.attributes() == original, "idempotent close changed restored state");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
