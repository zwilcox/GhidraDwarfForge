package ghidradwarfforge.output;

import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;

/** Separate-process native probe; request files preserve literal Unicode paths. */
public final class WindowsBackupStreamsProbe {
    public static void main(String[] args) throws Exception {
        var gson = new Gson();
        if (args.length == 2 && args[0].equals("--request-file")) {
            args = gson.fromJson(Files.readString(Path.of(args[1]), StandardCharsets.UTF_8), String[].class);
        }
        if (args.length > 0 && args[0].equals("request-roundtrip")) {
            System.out.println(gson.toJson(args));
            return;
        }
        if (args.length != 2) throw new IllegalArgumentException("inspect|ordinary|cancel|lifetime path");
        var metadata = new WindowsFileMetadata();
        var backup = new WindowsBackupStreams(metadata);
        Path path = Path.of(args[1]);
        switch (args[0]) {
            case "inspect", "ordinary" -> {
                var inventory = backup.inspect(path, () -> false);
                if (args[0].equals("ordinary")) WindowsBackupStreams.requireOrdinaryData(inventory);
                System.out.println(gson.toJson(inventory));
            }
            case "cancel" -> {
                cancelled(backup, path);
                System.out.println("windows-backup-cancel=PASS after-stream-header");
            }
            case "lifetime" -> {
                backup.inspect(path, () -> false);
                cancelled(backup, path);
                long count = metadata.processHandleCount();
                var samples = new java.util.ArrayList<java.util.Map<String, Long>>();
                for (int iteration = 0; iteration < 128; iteration++) {
                    backup.inspect(path, () -> false);
                    long afterRead = metadata.processHandleCount();
                    cancelled(backup, path);
                    samples.add(java.util.Map.of("iteration", (long) iteration,
                        "afterRead", afterRead, "afterCancel", metadata.processHandleCount()));
                }
                long after = metadata.processHandleCount();
                System.out.println(gson.toJson(java.util.Map.of("baseline", count, "after", after, "samples", samples)));
                if (after != count) throw new AssertionError("Backup handle count changed: before=" + count + " after=" + after);
                System.out.println("windows-backup-handles=PASS iterations=128");
            }
            default -> throw new IllegalArgumentException("Unknown backup probe command");
        }
    }

    private static void cancelled(WindowsBackupStreams backup, Path path) throws Exception {
        var stop = new AtomicBoolean();
        try {
            backup.inspect(path, stop::get, stream -> stop.set(true));
            throw new AssertionError("Cancellation after a real header was ignored");
        }
        catch (CancellationException expected) {
            if (!stop.get()) throw new AssertionError("Cancellation did not reach a stream header");
        }
    }
}
