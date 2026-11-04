package ghidradwarfforge.output;

import com.google.gson.Gson;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Isolated native test with an independently compiled C stat/filesystem observer. */
public final class LinuxDirectorySyncSmoke {
    private static int checks;
    private static final Gson JSON = new Gson();

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("C observer and fresh owned results path required");
        Path root = Files.createDirectory(Path.of(args[1]).toAbsolutePath());
        var sync = new LinuxDirectorySync();
        Path directory = Files.createDirectory(root.resolve("owned λ directory with spaces"));
        var before = sync.inspect(directory, () -> false);
        var child = new ProcessBuilder(Path.of(args[0]).toAbsolutePath().toString(), directory.toString())
            .redirectOutput(root.resolve("independent.json").toFile())
            .redirectError(root.resolve("independent.stderr").toFile()).start();
        if (!child.waitFor(10, TimeUnit.SECONDS)) { child.destroyForcibly().waitFor(); throw new AssertionError("C observer timed out"); }
        equal(0, child.exitValue());
        equal(0L, Files.size(root.resolve("independent.stderr")));
        equal(JsonParser.parseString(Files.readString(root.resolve("independent.json"))), JSON.toJsonTree(before));
        Files.writeString(root.resolve("java.json"), JSON.toJson(before) + "\n");
        Files.writeString(directory.resolve("entry"), "owned data");
        sync.sync(directory, before, () -> false);
        equal(before, sync.inspect(directory, () -> false));
        var other = Files.createDirectory(root.resolve("other"));
        refuse(() -> sync.sync(other, before, () -> false), "identity or mount changed");
        Path link = Files.createSymbolicLink(root.resolve("link"), directory);
        refuse(() -> sync.inspect(link, () -> false), "open directory");
        refuse(() -> sync.inspect(directory.resolve("entry"), () -> false), "open directory");
        refuse(() -> sync.inspect(root.resolve("missing"), () -> false), "open directory");
        Path moved = root.resolve("temporarily moved");
        refuse(() -> sync.sync(directory, before, () -> false, () -> {
            Files.move(directory, moved, StandardCopyOption.ATOMIC_MOVE);
            Files.createDirectory(directory);
        }), "path changed before sync");
        Files.delete(directory);
        Files.move(moved, directory, StandardCopyOption.ATOMIC_MOVE);
        equal(before, sync.inspect(directory, () -> false));
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("r-x------"));
        sync.sync(directory, before, () -> false);
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        // procfs accepts directory inspection but refuses fsync: do not swallow errno
        // or replace this with a global sync. No procfs entries are changed.
        var proc = sync.inspect(Path.of("/proc"), () -> false);
        refuse(() -> sync.sync(Path.of("/proc"), proc, () -> false), "fsync directory failed");
        for (int i = 0; i < 32; i++) cycle(sync, directory, before);
        long descriptors = descriptors();
        for (int i = 0; i < 128; i++) cycle(sync, directory, before);
        equal(descriptors, descriptors());
        equal(before, sync.inspect(directory, () -> false));
        equal("owned data", Files.readString(directory.resolve("entry")));
        Files.writeString(root.resolve("result.txt"), "linux-directory-sync=PASS checks=" + checks +
            " cycles=128 filesystem=" + Long.toHexString(before.fileSystemType()) + "\n");
        System.out.print(Files.readString(root.resolve("result.txt")));
    }

    private static void cycle(LinuxDirectorySync sync, Path directory, LinuxDirectorySync.Snapshot expected)
            throws Exception {
        equal(expected, sync.inspect(directory, () -> false));
        var polls = new AtomicInteger(1);
        try {
            sync.sync(directory, expected, () -> polls.getAndDecrement() == 0);
            throw new AssertionError("post-open cancellation accepted");
        }
        catch (CancellationException accepted) { checks++; }
        refuse(() -> sync.sync(directory, expected, () -> false, () -> {
            throw new IOException("owned hook failure");
        }), "owned hook failure");
    }

    private static long descriptors() throws IOException {
        try (var entries = Files.list(Path.of("/proc/self/fd"))) { return entries.count(); }
    }
    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void refuse(Checked action, String message) throws Exception {
        try { action.run(); throw new AssertionError("expected refusal: " + message); }
        catch (IOException expected) {
            if (!expected.getMessage().contains(message)) throw expected;
            checks++;
        }
    }
    private static void equal(Object expected, Object actual) {
        if (!java.util.Objects.equals(expected, actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }
}
