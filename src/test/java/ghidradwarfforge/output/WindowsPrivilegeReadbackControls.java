package ghidradwarfforge.output;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Token reply faults after actual Windows admission; never grants a missing privilege. */
public final class WindowsPrivilegeReadbackControls {
    private record Case(String name, String diagnostic) { }
    private static final List<Case> CASES = List.of(
        new Case("sizing-success", "TokenPrivileges) sizing failed"),
        new Case("sizing-error", "TokenPrivileges) sizing failed"),
        new Case("sizing-short", "TokenPrivileges) sizing failed"),
        new Case("sizing-large", "TokenPrivileges) sizing failed"),
        new Case("sizing-negative", "TokenPrivileges) sizing failed"),
        new Case("read-error", "GetTokenInformation(TokenPrivileges)"),
        new Case("returned-short", "returned invalid length"),
        new Case("returned-large", "returned invalid length"),
        new Case("returned-negative", "returned invalid length"),
        new Case("count-negative", "array exceeds returned bytes"),
        new Case("count-excess", "array exceeds returned bytes"),
        new Case("duplicate-privilege", "duplicate SeSecurityPrivilege"),
        new Case("missing-privilege", "does not own SeSecurityPrivilege"));

    static Map<String, Object> check() throws Exception {
        var metadata = new WindowsFileMetadata(); // Actual Windows x64 admission before any reply control.
        try (var control = new WindowsFileSecurityProbe.OwnPrivilege(false)) {
            int original = control.attributes();
            require((original & 2) == 0, "fixture did not disable the owned privilege");
            exercise(control, original);
            closeReplies(control, original);
            long before = metadata.processHandleCount();
            var rows = exercise(control, original);
            var closing = closeReplies(control, original);
            long after = metadata.processHandleCount();
            require(before == after, "privilege readback controls leaked handles");
            return Map.of("status", "PASS_WINDOWS_PRIVILEGE_READBACK_FAILURES", "cases", rows,
                "closeCases", closing,
                "handlesBefore", before, "handlesAfter", after,
                "scope", "Actual Windows token queries/restoration with controlled replies after real constructor admission; original token state restored and real handles released");
        }
    }

    /** Error replies occur after real restoration/close, so no injected fault deliberately leaks authority. */
    private static List<Map<String, Object>> closeReplies(WindowsFileSecurityProbe.OwnPrivilege control,
            int original) throws Exception {
        Field tokens = WindowsAttachmentPrivilege.class.getDeclaredField("tokens");
        Field kernel = WindowsAttachmentPrivilege.class.getDeclaredField("kernel");
        Field luid = WindowsAttachmentPrivilege.class.getDeclaredField("securityLuid");
        tokens.setAccessible(true);
        kernel.setAccessible(true);
        luid.setAccessible(true);
        var rows = new ArrayList<Map<String, Object>>();
        for (Case selected : List.of(
                new Case("adjust-false", "AdjustTokenPrivileges failed"),
                new Case("adjust-not-assigned", "AdjustTokenPrivileges failed"),
                new Case("previous-short", "previous privilege state exceeds"),
                new Case("previous-large", "previous privilege state exceeds"),
                new Case("previous-count-negative", "previous privilege state exceeds"),
                new Case("previous-count-excess", "previous privilege state exceeds"),
                new Case("previous-other-luid", "adjustment returned a different privilege"),
                new Case("restore-readback", "helper privilege restoration readback differs"),
                new Case("adjust-runtime", "injected restoration reply exception"),
                new Case("close-only", "CloseHandle(helper token) failed"),
                new Case("adjust-and-close", "AdjustTokenPrivileges failed"),
                new Case("runtime-and-close", "injected restoration reply exception"))) {
            var scope = new WindowsAttachmentPrivilege();
            Object realTokens = tokens.get(scope);
            Object realKernel = kernel.get(scope);
            var fault = new CloseFault(selected.name(), luid.getLong(scope));
            Throwable rejected;
            try {
                require(scope.attributes() == (original | 2), "close fixture was not admitted");
                tokens.set(scope, Proxy.newProxyInstance(tokens.getType().getClassLoader(), new Class<?>[] {tokens.getType()},
                    (object, method, args) -> {
                        method.setAccessible(true);
                        Object result;
                        try { result = method.invoke(realTokens, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                        return fault.tokenReply(method.getName(), args, result);
                    }));
                kernel.set(scope, Proxy.newProxyInstance(kernel.getType().getClassLoader(), new Class<?>[] {kernel.getType()},
                    (object, method, args) -> {
                        method.setAccessible(true);
                        Object result;
                        try { result = method.invoke(realKernel, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                        if (method.getName().equals("CloseHandle")) {
                            require((int) result != 0, "actual token CloseHandle failed");
                            fault.closed++;
                            if (selected.name().equals("close-only") || selected.name().endsWith("-and-close")) {
                                fault.closeFaults++;
                                Native.setLastError(6);
                                return 0;
                            }
                        }
                        return result;
                    }));
                try {
                    scope.close();
                    throw new AssertionError("invalid close reply accepted: " + selected.name());
                }
                catch (IOException | RuntimeException expected) { rejected = expected; }
            }
            finally {
                tokens.set(scope, realTokens);
                kernel.set(scope, realKernel);
                scope.close(); // Real cleanup if a fixture assertion interrupted the first close.
            }
            require(rejected.getMessage().contains(selected.diagnostic()), "wrong close failure: " + rejected);
            require((rejected instanceof IllegalStateException) == selected.name().contains("runtime"),
                "restoration failure changed its checked/unchecked type");
            boolean suppressed = selected.name().endsWith("-and-close");
            require(rejected.getSuppressed().length == (suppressed ? 1 : 0), "cleanup failure suppression differs");
            if (suppressed) require(rejected.getSuppressed()[0] instanceof IOException &&
                rejected.getSuppressed()[0].getMessage().contains("CloseHandle(helper token) failed"),
                "real restoration error was replaced by secondary close error");
            require(fault.adjustments == 1 && fault.closed == 1, "restoration and real handle release must occur once");
            require(fault.replyFaults == (selected.name().equals("close-only") ? 0 : 1), "restoration reply control was not reached");
            require(fault.closeFaults == (selected.name().equals("close-only") || suppressed ? 1 : 0), "close reply control was not reached");
            require(control.attributes() == original, "close failure left the actual privilege changed");
            try {
                scope.attributes();
                throw new AssertionError("closed token scope still usable");
            }
            catch (IOException expected) { require(expected.getMessage().contains("scope is closed"), expected.toString()); }
            rows.add(Map.of("name", selected.name(), "diagnostic", rejected.getMessage(),
                "originalStateRestored", true, "realHandlesClosed", fault.closed,
                "suppressedCloseFailure", suppressed));
        }
        System.out.println("windows-privilege-close-replies=PASS cases=" + rows.size());
        return rows;
    }

    private static final class CloseFault {
        final String name;
        final long luid;
        int adjustments;
        int closed;
        int replyFaults;
        int closeFaults;
        CloseFault(String name, long luid) { this.name = name; this.luid = luid; }

        Object tokenReply(String method, Object[] args, Object result) {
            if (method.equals("AdjustTokenPrivileges")) {
                require((int) result != 0 && Native.getLastError() == 0, "actual restoration failed");
                adjustments++;
                if (name.equals("close-only") || name.equals("restore-readback")) return result;
                replyFaults++;
                Pointer previous = (Pointer) args[4], needed = (Pointer) args[5];
                switch (name) {
                    case "adjust-false", "adjust-and-close" -> { Native.setLastError(5); return 0; }
                    case "adjust-not-assigned" -> Native.setLastError(1300);
                    case "previous-short" -> needed.setInt(0, 3);
                    case "previous-large" -> needed.setInt(0, 17);
                    case "previous-count-negative" -> previous.setInt(0, -1);
                    case "previous-count-excess" -> previous.setInt(0, 2);
                    case "previous-other-luid" -> { previous.setInt(0, 1); previous.setLong(4, luid ^ 1); }
                    case "adjust-runtime", "runtime-and-close" -> throw new IllegalStateException("injected restoration reply exception");
                    default -> throw new AssertionError(name);
                }
            }
            else if (method.equals("GetTokenInformation") && name.equals("restore-readback") &&
                    adjustments == 1 && args[2] != null) {
                require((int) result != 0, "actual restored privilege readback failed");
                Pointer data = (Pointer) args[2];
                int returned = ((Pointer) args[4]).getInt(0);
                int count = data.getInt(0);
                require(returned >= 4 && returned <= (int) args[3] && count >= 0 && count <= (returned - 4) / 12,
                    "actual restored privilege array exceeds its buffer");
                for (int index = 0; index < count; index++) {
                    int offset = 4 + index * 12;
                    if (data.getLong(offset) == luid) {
                        data.setInt(offset + 8, data.getInt(offset + 8) ^ 2);
                        replyFaults++;
                    }
                }
            }
            return result;
        }
    }

    private static List<Map<String, Object>> exercise(WindowsFileSecurityProbe.OwnPrivilege control,
            int original) throws Exception {
        Field field = WindowsAttachmentPrivilege.class.getDeclaredField("tokens");
        Field luid = WindowsAttachmentPrivilege.class.getDeclaredField("securityLuid");
        field.setAccessible(true);
        luid.setAccessible(true);
        var rows = new ArrayList<Map<String, Object>>();
        for (Case selected : CASES) {
            String diagnostic;
            int hits;
            try (var scope = new WindowsAttachmentPrivilege()) {
                int enabled = original | 2;
                require(scope.attributes() == enabled && control.attributes() == enabled, "real scope admission failed");
                Object real = field.get(scope);
                var fault = new Fault(selected.name(), luid.getLong(scope));
                Object proxy = Proxy.newProxyInstance(field.getType().getClassLoader(), new Class<?>[] {field.getType()},
                    (object, method, args) -> {
                        method.setAccessible(true);
                        Object result;
                        try { result = method.invoke(real, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                        return method.getName().equals("GetTokenInformation") ? fault.reply(args, result) : result;
                    });
                field.set(scope, proxy);
                try {
                    require(scope.attributes() == enabled, "forwarded privilege readback differs");
                    fault.armed = true;
                    try {
                        scope.attributes();
                        throw new AssertionError("malformed token reply accepted: " + selected.name());
                    }
                    catch (IOException expected) {
                        diagnostic = expected.getMessage();
                        require(diagnostic != null && diagnostic.contains(selected.diagnostic()),
                            "wrong privilege rejection: " + selected.name() + ": " + diagnostic);
                    }
                    hits = fault.hits;
                    require(hits == 1, "privilege reply fault was not reached exactly once");
                    require(control.attributes() == enabled, "readback failure changed the real token");
                }
                finally { field.set(scope, real); }
                require(scope.attributes() == enabled, "native privilege readback retry failed");
            }
            require(control.attributes() == original, "failed readback scope did not restore the original token");
            rows.add(Map.of("name", selected.name(), "faultHits", hits, "diagnostic", diagnostic,
                "tokenUnchanged", true, "retryPassed", true, "scopeRestored", true));
        }
        return rows;
    }

    private static final class Fault {
        final String name;
        final long luid;
        boolean armed;
        int hits;
        Fault(String name, long luid) { this.name = name; this.luid = luid; }

        Object reply(Object[] args, Object result) {
            if (!armed || hits != 0) return result;
            Pointer needed = (Pointer) args[4];
            if (args[2] == null) {
                require((int) result == 0 && Native.getLastError() == 122, "real token sizing failed");
                if (!name.startsWith("sizing-")) return result;
                hits++;
                switch (name) {
                    case "sizing-success" -> { return 1; }
                    case "sizing-error" -> Native.setLastError(5);
                    case "sizing-short" -> needed.setInt(0, 3);
                    case "sizing-large" -> needed.setInt(0, 1024 * 1024 + 1);
                    case "sizing-negative" -> needed.setInt(0, -1);
                    default -> throw new AssertionError(name);
                }
                return result;
            }
            require((int) result != 0, "real token information read failed");
            Pointer data = (Pointer) args[2];
            int returned = needed.getInt(0);
            hits++;
            switch (name) {
                case "read-error" -> { Native.setLastError(5); return 0; }
                case "returned-short" -> needed.setInt(0, 3);
                case "returned-large" -> needed.setInt(0, (int) args[3] + 1);
                case "returned-negative" -> needed.setInt(0, -1);
                case "count-negative" -> data.setInt(0, -1);
                case "count-excess" -> data.setInt(0, (returned - 4) / 12 + 1);
                case "missing-privilege" -> data.setInt(0, 0);
                case "duplicate-privilege" -> {
                    require(returned >= 28 && (int) args[3] >= returned, "fixture token needs two privilege records");
                    data.setInt(0, 2);
                    data.setLong(4, luid);
                    data.setLong(16, luid);
                }
                default -> throw new AssertionError(name);
            }
            return result;
        }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
