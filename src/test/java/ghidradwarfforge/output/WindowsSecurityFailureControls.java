package ghidradwarfforge.output;

import com.google.gson.Gson;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/** Actual Windows calls with controlled error replies; not observations of malformed kernel data. */
public final class WindowsSecurityFailureControls {
    private record Case(String name, String diagnostic) { }
    private static final int LIMIT = 1024 * 1024;
    private static final List<Case> CASES = List.of(
        new Case("sizing-success", "complete security sizing failed"),
        new Case("sizing-error", "complete security sizing failed"),
        new Case("capacity-small", "descriptor capacity exceeds bound"),
        new Case("capacity-large", "descriptor capacity exceeds bound"),
        new Case("capacity-unsigned", "descriptor capacity exceeds bound"),
        new Case("read-error", "GetKernelObjectSecurity failed (error=5)"),
        new Case("returned-small", "descriptor changed size"),
        new Case("returned-large", "descriptor changed size"),
        new Case("returned-unsigned", "descriptor changed size"),
        new Case("descriptor-invalid", "IsValidSecurityDescriptor failed (error=5)"),
        new Case("length-small", "descriptor exceeds bound"),
        new Case("length-large", "descriptor exceeds bound"),
        new Case("control-error", "GetSecurityDescriptorControl failed (error=5)"),
        new Case("revision", "Unsupported complete descriptor format"),
        new Case("absolute", "Unsupported complete descriptor format"),
        new Case("sacl-error", "GetSecurityDescriptorSacl failed (error=5)"),
        new Case("sacl-presence", "Inconsistent complete SACL presence"),
        new Case("readback-change", "security descriptor changed during inspection"));

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("owned results directory required");
        var security = new WindowsFileSecurity(); // Real host admission precedes all reflection.
        var metadata = new WindowsFileMetadata();
        Path root = Path.of(args[0]);
        Files.createDirectory(root);
        Path source = root.resolve("source");
        Files.writeString(source, "owned complete Windows security failure fixture");
        try (var privilege = new WindowsFileSecurityProbe.OwnPrivilege(true)) {
            check(security, source); // Warm class loading before process-handle accounting.
            long before = metadata.processHandleCount();
            var rows = check(security, source);
            long after = metadata.processHandleCount();
            require(before == after, "Windows full-security process handles leaked");
            Files.writeString(root.resolve("result.json"), new Gson().toJson(Map.of(
                "status", "PASS_CONTROLLED_WINDOWS_SECURITY_FAILURES", "cases", rows,
                "handlesBefore", before, "handlesAfter", after,
                "scope", "Actual Windows x64 read-only security APIs with controlled replies; no fabricated host admission")));
        }
        System.out.println("windows-security-failures=PASS cases=" + CASES.size());
    }

    private static List<Map<String, Object>> check(WindowsFileSecurity security, Path source) throws Exception {
        var baseline = security.inspect(source, () -> false);
        byte[] bytes = Files.readAllBytes(source);
        Field api = field(WindowsFileSecurity.class, "security");
        var metadata = (WindowsFileMetadata) field(WindowsFileSecurity.class, "metadata").get(security);
        Field kernel = field(WindowsFileMetadata.class, "kernel");
        Object realApi = api.get(security), realKernel = kernel.get(metadata);
        var rows = new ArrayList<Map<String, Object>>();
        for (Case selected : CASES) {
            var fault = new Fault(selected.name(), realKernel);
            api.set(security, wrapper(api, fault, realApi));
            kernel.set(metadata, wrapper(kernel, fault, realKernel));
            try {
                require(security.inspect(source, () -> false).equals(baseline), "forwarded security baseline differs");
                fault.balanced();
                fault.armed = true;
                fault.opened = fault.closed = fault.controls = 0;
                IOException rejected;
                try {
                    security.inspect(source, () -> false);
                    throw new AssertionError("controlled security reply accepted: " + selected.name());
                }
                catch (IOException expected) { rejected = expected; }
                require(rejected.getMessage().contains(selected.diagnostic()),
                    "wrong security rejection for " + selected.name() + ": " + rejected);
                require(fault.hits == 1, "security fault not reached exactly once: " + selected.name());
                fault.balanced();
                api.set(security, realApi);
                kernel.set(metadata, realKernel);
                require(security.inspect(source, () -> false).equals(baseline), "complete source security changed");
                require(Arrays.equals(bytes, Files.readAllBytes(source)), "source bytes changed");
                rows.add(Map.of("name", selected.name(), "faultHits", fault.hits,
                    "opened", fault.opened, "closed", fault.closed, "sourceUnchanged", true,
                    "retryPassed", true, "diagnostic", rejected.getMessage()));
            }
            finally {
                api.set(security, realApi);
                kernel.set(metadata, realKernel);
                fault.releaseLeftovers();
            }
        }
        return rows;
    }

    private static Field field(Class<?> owner, String name) throws Exception {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private static Object wrapper(Field field, Fault fault, Object real) {
        return Proxy.newProxyInstance(field.getType().getClassLoader(), new Class<?>[] {field.getType()},
            (proxy, method, args) -> fault.invoke(real, method, args));
    }

    private static final class Fault {
        final String name;
        final Object kernel;
        final HashSet<Pointer> handles = new HashSet<>();
        boolean armed;
        int hits, opened, closed, controls;

        Fault(String name, Object kernel) { this.name = name; this.kernel = kernel; }

        void balanced() {
            require(handles.isEmpty() && opened == closed, "full-security file handle leaked: " + name);
        }

        Object invoke(Object real, Method method, Object[] args) throws Throwable {
            method.setAccessible(true);
            Object result;
            try { result = method.invoke(real, args); }
            catch (InvocationTargetException failure) { throw failure.getCause(); }
            String operation = method.getName();
            if (operation.equals("CreateFileW") && result != null && Pointer.nativeValue((Pointer) result) != -1L) {
                require(handles.add((Pointer) result), "duplicate live security handle");
                opened++;
            }
            if (operation.equals("CloseHandle") && (int) result != 0) {
                require(handles.remove((Pointer) args[0]), "untracked security handle close");
                closed++;
            }
            if (!armed || hits != 0) return result;
            boolean changed = false;
            if (operation.equals("GetKernelObjectSecurity")) {
                Pointer needed = (Pointer) args[4];
                if (args[2] == null) {
                    require((int) result == 0 && Native.getLastError() == 122, "real security sizing failed");
                    switch (name) {
                        case "sizing-success" -> { hits++; return 1; }
                        case "sizing-error" -> { return failure(); }
                        case "capacity-small" -> { needed.setInt(0, 19); changed = true; }
                        case "capacity-large" -> { needed.setInt(0, LIMIT + 1); changed = true; }
                        case "capacity-unsigned" -> { needed.setInt(0, -1); changed = true; }
                        default -> { }
                    }
                }
                else {
                    require((int) result != 0, "real complete security read failed");
                    switch (name) {
                        case "read-error" -> { return failure(); }
                        case "returned-small" -> { needed.setInt(0, 19); changed = true; }
                        case "returned-large" -> { needed.setInt(0, (int) args[3] + 1); changed = true; }
                        case "returned-unsigned" -> { needed.setInt(0, -1); changed = true; }
                        default -> { }
                    }
                }
            }
            if ((operation.equals("IsValidSecurityDescriptor") && name.equals("descriptor-invalid")) ||
                    (operation.equals("GetSecurityDescriptorControl") && name.equals("control-error")) ||
                    (operation.equals("GetSecurityDescriptorSacl") && name.equals("sacl-error"))) {
                require((int) result != 0, "real complete security validation failed");
                return failure();
            }
            if (operation.equals("GetSecurityDescriptorLength") && name.startsWith("length-")) {
                hits++;
                return name.equals("length-small") ? 19 : LIMIT + 1;
            }
            if (operation.equals("GetSecurityDescriptorControl")) {
                require((int) result != 0, "real security control query failed");
                controls++;
                Pointer flags = (Pointer) args[1];
                if (name.equals("revision")) { ((Pointer) args[2]).setInt(0, 2); changed = true; }
                if (name.equals("absolute")) { flags.setShort(0, (short) (flags.getShort(0) & ~0x8000)); changed = true; }
                if (name.equals("readback-change") && controls == 2) {
                    flags.setShort(0, (short) (flags.getShort(0) ^ 0x1000));
                    changed = true;
                }
            }
            if (operation.equals("GetSecurityDescriptorSacl") && name.equals("sacl-presence")) {
                Pointer present = (Pointer) args[1];
                present.setInt(0, present.getInt(0) == 0 ? 1 : 0);
                changed = true;
            }
            if (changed) hits++;
            return result;
        }

        private int failure() { hits++; Native.setLastError(5); return 0; }

        void releaseLeftovers() throws Exception {
            for (Pointer handle : List.copyOf(handles)) {
                Method close = kernel.getClass().getInterfaces()[0].getDeclaredMethod("CloseHandle", Pointer.class);
                close.setAccessible(true);
                close.invoke(kernel, handle);
            }
        }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
