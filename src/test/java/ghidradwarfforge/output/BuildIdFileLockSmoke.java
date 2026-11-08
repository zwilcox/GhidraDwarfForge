package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;

/** Isolated real-host lease checks, including the previous platform failure modes. */
public final class BuildIdFileLockSmoke {
    private static final byte[] MAGIC = "Forge owned lock smoke v1\n".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) throws Exception {
        if (System.getProperty("os.name").startsWith("Windows")) {
            try (var privilege = new WindowsAttachmentPrivilege()) { run(args); }
        }
        else run(args);
    }

    private static void run(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("supply exercise|try owned-path");
        Path path = Path.of(args[1]).toAbsolutePath();
        boolean windows = System.getProperty("os.name").startsWith("Windows");
        AttachmentOperation.Host host = windows ? new WindowsAttachmentHost() : new LinuxBuildIdHost();
        if (args[0].equals("try")) {
            try (var lease = BuildIdFileLock.acquire(path, MAGIC, host, () -> false)) {
                lease.verify(() -> false);
                System.out.println("LOCK_ACQUIRED");
            }
            catch (IOException busy) {
                if (!busy.getMessage().equals("build-ID installation is busy")) throw busy;
                System.out.println("LOCK_BUSY");
            }
            return;
        }
        if (!args[0].equals("exercise")) throw new IllegalArgumentException("unknown mode");
        Files.write(path, MAGIC, StandardOpenOption.CREATE_NEW);
        // Prove why the former second-handle verification is unsafe on each OS.
        try (var channel = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE);
                var old = channel.tryLock()) {
            require(old != null, "legacy initial lock");
            child(path, "LOCK_BUSY");
            if (windows) {
                try {
                    Files.readAllBytes(path);
                    throw new AssertionError("Windows second-handle read unexpectedly succeeded");
                }
                catch (IOException expected) { System.out.println("LEGACY_WINDOWS_SECOND_HANDLE_REFUSED"); }
                child(path, "LOCK_BUSY");
            }
            else {
                Files.readAllBytes(path);
                child(path, "LOCK_ACQUIRED");
                require(old.isValid(), "Java bookkeeping must still describe the lost kernel lock");
                System.out.println("LEGACY_LINUX_SECOND_HANDLE_RELEASED_LOCK");
            }
        }
        try (var lease = BuildIdFileLock.acquire(path, MAGIC, host, () -> false)) {
            for (int count = 0; count < 3; count++) {
                lease.verify(() -> false); // real host metadata opens/closes independent handles
                if (!windows) Files.readAllBytes(path);
                child(path, "LOCK_BUSY");
            }
            try (var unexpected = BuildIdFileLock.acquire(path, MAGIC, host, () -> false)) {
                throw new AssertionError("same-JVM competing lease acquired");
            }
            catch (IOException busy) { require(busy.getMessage().equals("build-ID installation is busy"), busy.toString()); }
            child(path, "LOCK_BUSY");
            try {
                lease.verify(() -> true);
                throw new AssertionError("verification ignored cancellation");
            }
            catch (CancellationException expected) { child(path, "LOCK_BUSY"); }
        }
        child(path, "LOCK_ACQUIRED");
        for (byte[] malformed : new byte[][] {new byte[MAGIC.length], new byte[MAGIC.length + 1]}) {
            Files.write(path, malformed);
            try (var unexpected = BuildIdFileLock.acquire(path, MAGIC, host, () -> false)) {
                throw new AssertionError("invalid lock record acquired");
            }
            catch (IOException expected) { require(expected.getMessage().equals("foreign or incomplete build-ID lock"), expected.toString()); }
            Files.write(path, MAGIC);
            child(path, "LOCK_ACQUIRED");
        }
        System.out.println("build-id-file-lock=PASS host=" + (windows ? "windows" : "linux"));
    }

    private static void child(Path path, String marker) throws Exception {
        Path java = Path.of(System.getProperty("java.home"), "bin",
            System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java");
        var process = new ProcessBuilder(java.toString(), "--enable-native-access=ALL-UNNAMED", "-cp",
            System.getProperty("java.class.path"), BuildIdFileLockSmoke.class.getName(), "try", path.toString())
            .redirectErrorStream(true).start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            process.waitFor();
            throw new IOException("lease contender timed out");
        }
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        require(process.exitValue() == 0 && output.lines().anyMatch(marker::equals), output);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
