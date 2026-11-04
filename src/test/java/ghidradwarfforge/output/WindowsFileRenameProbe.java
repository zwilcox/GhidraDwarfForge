package ghidradwarfforge.output;

import com.google.gson.Gson;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.CancellationException;

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
            long before = metadata.processHandleCount();
            for (int i = 0; i < 128; i++) cycle(rename, metadata, stage, target);
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
