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

/** Read-only token reply faults after actual Windows admission; never grants a missing privilege. */
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
            long before = metadata.processHandleCount();
            var rows = exercise(control, original);
            long after = metadata.processHandleCount();
            require(before == after, "privilege readback controls leaked handles");
            return Map.of("status", "PASS_WINDOWS_PRIVILEGE_READBACK_FAILURES", "cases", rows,
                "handlesBefore", before, "handlesAfter", after,
                "scope", "Actual Windows token queries with controlled replies after real constructor admission; token unchanged by reads and scope restored");
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
