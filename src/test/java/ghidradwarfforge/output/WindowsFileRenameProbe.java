package ghidradwarfforge.output;

import com.google.gson.Gson;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.CancellationException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

/** Isolated Windows namespace exercise; the PowerShell/C# harness observes files independently. */
public final class WindowsFileRenameProbe {
    public static void main(String[] arguments) throws Exception {
        System.setOut(new java.io.PrintStream(System.out, true, StandardCharsets.UTF_8));
        System.setErr(new java.io.PrintStream(System.err, true, StandardCharsets.UTF_8));
        if (arguments.length != 2 || !arguments[0].equals("--request-file")) {
            throw new IllegalArgumentException("UTF-8 request file required");
        }
        var json = new Gson();
        String[] args = json.fromJson(Files.readString(Path.of(arguments[1]), StandardCharsets.UTF_8), String[].class);
        if (args[0].equals("request-roundtrip")) { System.out.println(json.toJson(args)); return; }
        Path stage = Path.of(args[1]);
        Path target = Path.of(args[2]);
        var metadata = new WindowsFileMetadata();
        var rename = new WindowsFileRename();
        if (args[0].equals("lifetime")) {
            for (int i = 0; i < 32; i++) cycle(rename, metadata, stage, target);
            controlledReplies(rename, metadata, stage, target);
            long before = metadata.processHandleCount();
            for (int i = 0; i < 128; i++) cycle(rename, metadata, stage, target);
            controlledReplies(rename, metadata, stage, target);
            long after = metadata.processHandleCount();
            if (before != after) throw new AssertionError("handle count changed: " + before + " -> " + after);
            System.out.println("windows-rename-handles=PASS iterations=128");
            return;
        }
        var originalStage = metadata.inspect(stage, () -> false);
        var originalTarget = args[0].equals("replace") || args[0].equals("stale-target") ||
            args[0].equals("late-target") ? metadata.inspect(target, () -> false) : null;
        if (args[0].equals("stale-stage")) Files.writeString(stage, "changed stage after snapshot; must remain");
        if (args[0].equals("stale-target")) Files.writeString(target, "changed target after snapshot; must remain");
        System.out.println("expected-stage=" + json.toJson(originalStage));
        System.out.println("expected-target=" + json.toJson(originalTarget));
        var result = rename.rename(stage, originalStage, target, originalTarget,
            () -> args[0].equals("cancel-before"), point -> {
                if (point == WindowsFileRename.Boundary.OPENED) {
                    if (args[0].equals("cancel-open")) throw new CancellationException("cancel after opening stage");
                    if (args[0].equals("late-stage")) {
                        Files.move(stage, stage.resolveSibling(stage.getFileName() + ".retained"));
                        Files.writeString(stage, "concurrent stage; must remain", StandardOpenOption.CREATE_NEW);
                    }
                    if (args[0].equals("late-target")) Files.writeString(target, "concurrent target; must remain");
                }
                if (point == WindowsFileRename.Boundary.BEFORE_RENAME && args[0].equals("last-moment-collision")) {
                    Files.writeString(target, "concurrent new target; must remain", StandardOpenOption.CREATE_NEW);
                }
            });
        System.out.println("installed=" + json.toJson(result));
    }

    /** Forward real Windows handles except for one explicit error reply; never leak a deliberately failed close. */
    private static void controlledReplies(WindowsFileRename rename, WindowsFileMetadata metadata, Path stage, Path target)
            throws Exception {
        var kernel = WindowsFileRename.class.getDeclaredField("kernel");
        kernel.setAccessible(true);
        Object real = kernel.get(rename);
        for (String fault : new String[] {"open-null", "open-invalid", "rename-error", "close-after-release", "cancel-after-rename"}) {
            var original = metadata.inspect(stage, () -> false);
            byte[] bytes = Files.readAllBytes(stage);
            var cancelled = new AtomicBoolean();
            int[] opened = {0}, closed = {0}, injected = {0};
            var handles = new java.util.HashMap<Long, Pointer>();
            Object controlled = Proxy.newProxyInstance(kernel.getType().getClassLoader(), new Class<?>[] {kernel.getType()},
                (proxy, method, arguments) -> {
                    String name = method.getName();
                    if (name.equals("CreateFileW") && fault.startsWith("open-")) {
                        injected[0]++;
                        Native.setLastError(5);
                        return fault.equals("open-null") ? null : Pointer.createConstant(-1L);
                    }
                    if (name.equals("SetFileInformationByHandle") && fault.equals("rename-error")) {
                        injected[0]++;
                        Native.setLastError(5);
                        return 0;
                    }
                    Object result;
                    method.setAccessible(true);
                    try { result = method.invoke(real, arguments); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                    if (name.equals("CreateFileW")) {
                        require(result instanceof Pointer p && Pointer.nativeValue(p) != -1L, "forwarded open failed");
                        Pointer handle = (Pointer) result;
                        require(handles.put(Pointer.nativeValue(handle), handle) == null, "duplicate native handle");
                        opened[0]++;
                    }
                    if (name.equals("SetFileInformationByHandle") && fault.equals("cancel-after-rename")) {
                        require(((Number) result).intValue() != 0, "forwarded rename failed");
                        injected[0]++;
                        cancelled.set(true);
                    }
                    if (name.equals("CloseHandle")) {
                        require(((Number) result).intValue() != 0, "real handle release failed");
                        require(handles.remove(Pointer.nativeValue((Pointer) arguments[0])) != null, "unowned handle close");
                        closed[0]++;
                        if (fault.equals("close-after-release")) {
                            injected[0]++;
                            Native.setLastError(5);
                            return 0;
                        }
                    }
                    return result;
                });
            kernel.set(rename, controlled);
            try {
                try {
                    var installed = rename.publishNew(stage, original, target, cancelled::get);
                    require(fault.equals("cancel-after-rename"), "native error was ignored: " + fault);
                    require(installed.facts().identity().equals(original.facts().identity()), "cancelled readback lost identity");
                }
                catch (IOException rejected) {
                    String operation = fault.startsWith("open-") ? "CreateFileW stage" :
                        fault.equals("rename-error") ? "FileRenameInfo" : "CloseHandle stage";
                    require(!fault.equals("cancel-after-rename") && rejected.getMessage().contains(
                        "Windows rename " + operation + " failed (error=5)"), "unrelated failure: " + rejected);
                }
                require(injected[0] == 1 && opened[0] == closed[0] &&
                    opened[0] == (fault.startsWith("open-") ? 0 : 1), "native handle ownership differs: " + fault);
                boolean published = fault.equals("close-after-release") || fault.equals("cancel-after-rename");
                Path observed = published ? target : stage;
                require(!Files.exists(published ? stage : target), "unexpected namespace after " + fault);
                var after = metadata.inspect(observed, () -> false);
                require(after.facts().identity().equals(original.facts().identity()) &&
                    after.preservation().equals(original.preservation()) && after.dataStreams().equals(original.dataStreams()) &&
                    Arrays.equals(bytes, Files.readAllBytes(observed)), "owned bytes or metadata changed: " + fault);
            }
            finally {
                kernel.set(rename, real);
                // A failed ownership assertion must not leave its real test handle open.
                var close = kernel.getType().getDeclaredMethod("CloseHandle", Pointer.class);
                close.setAccessible(true);
                for (Pointer handle : handles.values()) {
                    require(((Number) close.invoke(real, handle)).intValue() != 0, "test handle cleanup failed");
                }
            }
            if (Files.exists(target)) rename.publishNew(target, metadata.inspect(target, () -> false), stage, () -> false);
        }
        System.out.println("windows-rename-controlled-replies=PASS cases=5");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void cycle(WindowsFileRename rename, WindowsFileMetadata metadata, Path stage, Path target)
            throws Exception {
        var before = metadata.inspect(stage, () -> false);
        rename.publishNew(stage, before, target, () -> false);
        rename.publishNew(target, metadata.inspect(target, () -> false), stage, () -> false);
        before = metadata.inspect(stage, () -> false);
        try {
            rename.rename(stage, before, target, null, () -> false, point -> {
                if (point == WindowsFileRename.Boundary.OPENED) throw new CancellationException("opened control");
            });
            throw new AssertionError("cancellation was not propagated");
        }
        catch (CancellationException accepted) { }
    }
}
