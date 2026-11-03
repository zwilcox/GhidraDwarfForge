package ghidradwarfforge.output;

import com.google.gson.Gson;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;

/** Isolated native directory binding; owned fixtures and independent facts are supplied by PowerShell. */
public final class WindowsDirectorySyncProbe {
    public static void main(String[] arguments) throws Exception {
        System.setOut(new java.io.PrintStream(System.out, true, StandardCharsets.UTF_8));
        System.setErr(new java.io.PrintStream(System.err, true, StandardCharsets.UTF_8));
        if (arguments.length != 2 || !arguments[0].equals("--request-file")) {
            throw new IllegalArgumentException("UTF-8 request file required");
        }
        var json = new Gson();
        String[] args = json.fromJson(Files.readString(Path.of(arguments[1]), StandardCharsets.UTF_8), String[].class);
        if (args[0].equals("request-roundtrip")) { System.out.println(json.toJson(args)); return; }
        var sync = new WindowsDirectorySync();
        Path directory = Path.of(args[1]);
        if (args[0].equals("inspect")) {
            System.out.println(json.toJson(sync.inspect(directory, () -> false)));
            return;
        }
        if (args[0].equals("lifetime")) {
            var metadata = new WindowsFileMetadata();
            for (int i = 0; i < 32; i++) cycle(sync, directory);
            long before = metadata.processHandleCount();
            for (int i = 0; i < 128; i++) {
                cycle(sync, directory);
                long after = metadata.processHandleCount();
                if (before != after) throw new AssertionError("directory handle count: " + before + " -> " + after);
            }
            System.out.println("windows-directory-handles=PASS cycles=128 baseline=" + before);
            return;
        }
        var before = sync.inspect(directory, () -> false);
        if (args[0].equals("stale")) replaceOwnedDirectory(directory);
        sync.sync(directory, before, () -> args[0].equals("cancel-before"), () -> {
            if (args[0].equals("cancel-open")) throw new CancellationException("directory cancelled after open");
            if (args[0].equals("late")) replaceOwnedDirectory(directory);
        });
        var after = sync.inspect(directory, () -> false);
        if (!before.equals(after)) throw new AssertionError("directory changed after sync");
        System.out.println(json.toJson(after));
    }

    private static void replaceOwnedDirectory(Path directory) throws IOException {
        // Only exercised with a freshly owned fixture selected by the harness.
        Files.move(directory, directory.resolveSibling(directory.getFileName() + ".retained"));
        Files.createDirectory(directory);
    }

    private static void cycle(WindowsDirectorySync sync, Path directory) throws Exception {
        var expected = sync.inspect(directory, () -> false);
        sync.sync(directory, expected, () -> false);
        try {
            sync.sync(directory, expected, () -> false, () -> {
                throw new CancellationException("directory lifetime opened control");
            });
            throw new AssertionError("opened directory cancellation was ignored");
        }
        catch (CancellationException accepted) { }
    }
}
