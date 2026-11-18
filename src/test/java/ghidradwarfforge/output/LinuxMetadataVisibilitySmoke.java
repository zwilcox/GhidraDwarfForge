package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;

/** Standalone process only: privileged mode is explicitly invoked by the harness. */
public final class LinuxMetadataVisibilitySmoke {
    @FunctionalInterface interface Action { void run() throws Exception; }
    private static int checks;

    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !(args[0].equals("unprivileged") || args[0].equals("privileged"))) {
            throw new IllegalArgumentException("usage: unprivileged|privileged new-test-directory");
        }
        Path root = Files.createDirectory(Path.of(args[1]));
        canaryPreconditions(root);
        refused(() -> LinuxMetadataVisibility.create(root, () -> true), CancellationException.class, "cancelled");
        empty(root);
        var virtualFailure = new AtomicReference<Throwable>();
        Thread virtual = Thread.ofVirtual().start(() -> {
            try { LinuxMetadataVisibility.create(root, () -> false); }
            catch (Throwable failure) { virtualFailure.set(failure); }
        });
        virtual.join();
        require(virtualFailure.get() instanceof IOException && virtualFailure.get().getMessage().contains("platform thread"),
            "virtual thread was not rejected");
        empty(root);
        if (args[0].equals("unprivileged")) {
            refused(() -> LinuxMetadataVisibility.create(root, () -> false), IOException.class,
                "create protected visibility canary failed (errno=1)");
            empty(root);
        }
        else {
            try (var session = LinuxMetadataVisibility.create(root, () -> false)) {
                session.check(() -> false);
                refused(() -> session.check(() -> true), CancellationException.class, "cancelled");
                var failure = new AtomicReference<Throwable>();
                Thread thread = new Thread(() -> {
                    try { session.check(() -> false); }
                    catch (Throwable caught) { failure.set(caught); }
                });
                thread.start(); thread.join();
                require(failure.get() instanceof IOException && failure.get().getMessage().contains("different platform thread"),
                    "cross-thread access was not rejected");
                session.check(() -> false);
            }
            empty(root);
            int cancellationPoints = 0;
            for (int point = 1; point < 200; point++) {
                final int selected = point;
                var calls = new AtomicInteger();
                boolean succeeded = false;
                try (var session = LinuxMetadataVisibility.create(root,
                        () -> calls.incrementAndGet() == selected)) {
                    session.check(() -> false);
                    succeeded = true;
                }
                catch (CancellationException expected) {
                    require(expected.getSuppressed().length == 0, "cancelled creation cleanup failed");
                    cancellationPoints++;
                }
                empty(root);
                if (succeeded) break;
            }
            require(cancellationPoints > 10 && cancellationPoints < 199, "creation cancellation points not exercised");
            var closed = LinuxMetadataVisibility.create(root, () -> false);
            closed.close(); closed.close();
            refused(() -> closed.check(() -> false), IOException.class, "closed");
            empty(root);
            // Mutated bytes must be retained, including when close is attempted.
            var altered = LinuxMetadataVisibility.create(root, () -> false);
            Path workspace;
            try (var entries = Files.list(root)) { workspace = entries.findFirst().orElseThrow(); }
            Path canary = workspace.resolve("canary");
            Files.writeString(canary, "preserve changed bytes");
            refused(() -> altered.check(() -> false), IOException.class, "canary changed");
            refused(altered::close, IOException.class, "canary changed");
            require(Files.readString(canary).equals("preserve changed bytes"), "changed canary was removed");
            // These are explicit disposable test fixtures, not session cleanup.
            Files.delete(canary); Files.delete(workspace);
            empty(root);
            try (var warm = LinuxMetadataVisibility.create(root, () -> false)) { warm.check(() -> false); }
            long descriptors = descriptors();
            for (int i = 0; i < 128; i++) {
                try (var session = LinuxMetadataVisibility.create(root, () -> false)) { session.check(() -> false); }
            }
            require(descriptors() == descriptors, "native descriptor growth");
            empty(root);
        }
        System.out.println("visibility-session=" + args[0] + " checks=" + checks + " PASS");
    }

    private static long descriptors() throws IOException {
        try (var paths = Files.list(Path.of("/proc/self/fd"))) { return paths.count(); }
    }

    /** Reject unsuitable owned files before any protected-namespace write is attempted. */
    private static void canaryPreconditions(Path root) throws Exception {
        var metadata = new LinuxFileMetadata();
        Path file = root.resolve("precondition-canary");
        Path alias = root.resolve("precondition-alias");
        Files.createFile(file, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
            java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
        try {
            var empty = metadata.inspect(file, () -> false);
            for (int length : new int[] {0, 1, 31, 33, 64}) {
                refused(() -> metadata.markOwnedCanary(file, empty, new byte[length], () -> false),
                    IOException.class, "nonce must contain 32 bytes");
                require(metadata.inspect(file, () -> false).equals(empty), "invalid nonce changed canary metadata");
                require(Files.size(file) == 0, "invalid nonce changed canary bytes");
            }
            Files.write(file, new byte[] {42});
            var nonempty = metadata.inspect(file, () -> false);
            refused(() -> metadata.markOwnedCanary(file, nonempty, new byte[32], () -> false),
                IOException.class, "canary must be empty, private and single-link");
            require(Files.readAllBytes(file)[0] == 42 && metadata.inspect(file, () -> false).equals(nonempty),
                "nonempty canary was changed");
            Files.write(file, new byte[0]);
            Files.createLink(alias, file);
            var linked = metadata.inspect(file, () -> false);
            require(linked.facts().links() == 2, "hardlink premise missing");
            refused(() -> metadata.markOwnedCanary(file, linked, new byte[32], () -> false),
                IOException.class, "canary must be empty, private and single-link");
            require(metadata.inspect(alias, () -> false).equals(linked), "linked canary was changed");
            Files.delete(alias);
            Files.setPosixFilePermissions(file, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
            var publicFile = metadata.inspect(file, () -> false);
            refused(() -> metadata.markOwnedCanary(file, publicFile, new byte[32], () -> false),
                IOException.class, "canary must be empty, private and single-link");
            require(metadata.inspect(file, () -> false).equals(publicFile), "public canary was changed");

            // These are explicit metadata-policy values, not claims about inode
            // features on this filesystem. An unpreserved allocation policy must
            // not be accepted merely because ordinary stat fields are unchanged.
            int rejected = 0;
            for (int field = 0; field < 5; field++) {
                for (int bit = 0; bit < 32; bit++) {
                    long[] values = new long[5];
                    values[field] = 1L << bit;
                    var policy = new LinuxFileMetadata.InodePolicy(values[0], values[1], values[2], values[3], values[4]);
                    var snapshot = new LinuxFileMetadata.Snapshot(empty.facts(), empty.visibleAttributes(), policy);
                    boolean allowed = field == 0 && bit == 19 || field == 1 && bit == 31;
                    if (allowed) {
                        LinuxFileMetadata.supported(snapshot);
                        checks++;
                    }
                    else {
                        refused(() -> LinuxFileMetadata.supported(snapshot), IOException.class,
                            "unsupported inode flags, project ID or allocation policy");
                        rejected++;
                    }
                }
            }
            require(rejected == 158, "inode policy matrix is incomplete");
            LinuxFileMetadata.supported(new LinuxFileMetadata.Snapshot(empty.facts(), empty.visibleAttributes(),
                new LinuxFileMetadata.InodePolicy(0x80000L, 0x80000000L, 0, 0, 0)));
            checks++;
            System.out.println("metadata-canary-preconditions=PASS invalidFiles=3 invalidNonces=5 policyRefusals=" + rejected);
        }
        finally {
            Files.deleteIfExists(alias);
            Files.deleteIfExists(file);
        }
        empty(root);
    }
    private static void empty(Path root) throws IOException {
        try (var paths = Files.list(root)) { require(paths.findAny().isEmpty(), "owned workspace leaked"); }
    }
    private static void refused(Action action, Class<? extends Throwable> kind, String message) throws Exception {
        try { action.run(); }
        catch (Exception failure) {
            require(kind.isInstance(failure) && failure.getMessage().contains(message), "wrong failure: " + failure);
            require(failure.getSuppressed().length == 0, "cleanup failed: " + failure);
            return;
        }
        throw new AssertionError("operation unexpectedly succeeded");
    }
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }
}
