package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;

/** Launch admission using the actual native owner, without fabricated success records. */
final class ValidatorLaunchBoundarySmoke {
    private static int checks;

    private ValidatorLaunchBoundarySmoke() { }

    /** Isolated negative admission checks for mutation testing; no success protocol is fabricated. */
    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !System.getProperty("os.name").equals("Linux")) {
            throw new IllegalArgumentException("supply a new Linux fixture directory");
        }
        Path root = Files.createDirectory(Path.of(args[0]));
        Path tool = Files.writeString(root.resolve("owned-tool"), "#!/bin/sh\nexit 0\n");
        Files.setPosixFilePermissions(tool, Set.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
        provenanceRaces(tool, root);
    }

    static void run(ValidatorSupervisor runner, Path python, Path script, Path root) throws Exception {
        checks = 0;
        Path evidence = Files.createDirectory(root.resolve("launch-boundaries"));
        List<String> quiet = List.of(script.toString(), "quiet", root.resolve("unused-launch-marker").toString());
        for (long millis : List.of(-1L, 0L, 3_600_001L)) {
            invalidArgument(evidence, () -> runner.run(python, quiet, evidence, Duration.ofMillis(millis), 1, () -> false));
        }
        for (long cap : List.of(-1L, 0L, 268_435_457L)) {
            invalidArgument(evidence, () -> runner.run(python, quiet, evidence, Duration.ofSeconds(5), cap, () -> false));
        }
        for (String value : Arrays.asList(null, "zero\0byte", "x".repeat(32768))) {
            invalidArgument(evidence, () -> runner.run(python, Arrays.asList(value), evidence, Duration.ofSeconds(5), 1, () -> false));
        }
        try {
            runner.run(python, quiet, evidence, Duration.ofSeconds(5), 1, () -> true);
            throw new AssertionError("prelaunch cancellation ignored");
        }
        catch (CancellationException expected) { checks++; }
        requireEmpty(evidence);
        for (String role : List.of("directory", "empty", "oversize")) {
            Path bad = root.resolve("invalid-validator-" + role);
            if (role.equals("directory")) Files.createDirectory(bad);
            else if (role.equals("empty")) Files.createFile(bad);
            else {
                // One allocated byte beyond the bound; no large download or filled fixture.
                try (var output = FileChannel.open(bad, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                    output.position(128L * 1024 * 1024);
                    output.write(ByteBuffer.wrap(new byte[] { 0 }));
                }
            }
            try {
                invalidTool(evidence, () -> runner.run(bad, quiet, evidence, Duration.ofSeconds(5), 1, () -> false));
                invalidTool(evidence, () -> new ValidatorSupervisor(bad));
            }
            finally { Files.delete(bad); }
        }
        if (System.getProperty("os.name").equals("Linux")) {
            Path bad = Files.writeString(root.resolve("nonexecutable-validator"), "not an executable\n");
            try {
                Files.setPosixFilePermissions(bad, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
                invalidTool(evidence, () -> runner.run(bad, quiet, evidence, Duration.ofSeconds(5), 1, () -> false));
            }
            finally { Files.delete(bad); }
            provenanceRaces(python, root);
        }

        var minimumStream = runner.run(python, quiet, evidence, Duration.ofSeconds(5), 1, () -> false);
        require(minimumStream.status().cleanupComplete() && minimumStream.stdoutDigest().byteCount() == 0 &&
            minimumStream.stderrDigest().byteCount() == 0, "one-byte retention limit permits a silent validator");
        var arguments = new ArrayList<>(quiet);
        var maximumBounds = runner.run(python, arguments, evidence, Duration.ofHours(1), 256L * 1024 * 1024, () -> false);
        arguments.clear();
        require(maximumBounds.status().cleanupComplete() && maximumBounds.command().subList(8, maximumBounds.command().size()).equals(quiet),
            "exact maximum bounds admitted and command evidence owns its argument snapshot");
        try { maximumBounds.command().clear(); throw new AssertionError("command evidence mutable"); }
        catch (UnsupportedOperationException expected) { checks++; }
        // Windows has a smaller aggregate CreateProcess command limit. Do not
        // turn this per-argument Linux check into an unsupported Windows claim.
        if (System.getProperty("os.name").equals("Linux")) {
            var longest = runner.run(python, List.of(script.toString(), "ok", root.resolve("unused").toString(), "x".repeat(32767)),
                evidence, Duration.ofSeconds(5), 65536, () -> false);
            String retained = com.google.gson.JsonParser.parseString(Files.readString(longest.stdout())).getAsJsonArray().get(0).getAsString();
            require(retained.equals("x".repeat(32767)), "longest admitted argument reaches actual tool unchanged");
        }
        try {
            var quickest = runner.run(python, quiet, evidence, Duration.ofMillis(1), 1, () -> false);
            require(quickest.status().cleanupComplete(), "minimum deadline success still requires cleanup");
        }
        catch (ValidatorSupervisor.Failure expected) {
            require(expected.evidence() != null && expected.evidence().status().cleanupComplete() &&
                expected.evidence().status().reason().equals("timeout"), "minimum deadline is admitted and safely times out");
            require(expected.directory().equals(expected.evidence().directory()), "failure exposes its actual retained evidence directory");
        }
        System.out.println("validator-launch-boundaries=PASS checks=" + checks);
    }

    /** Real file changes synchronized at digest cancellation polls, before any child is launched. */
    private static void provenanceRaces(Path tool, Path root) throws Exception {
        for (String mode : List.of("identity", "size", "modified", "read-length")) {
            Path directory = Files.createDirectory(root.resolve("provenance-" + mode));
            Path evidence = Files.createDirectory(directory.resolve("evidence"));
            Path helper = Files.writeString(directory.resolve("owned-helper"), "#!/bin/sh\nexit 0\n");
            var permissions = Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE);
            Files.setPosixFilePermissions(helper, permissions);
            byte[] bytes = Files.readAllBytes(helper);
            var before = Files.readAttributes(helper, java.nio.file.attribute.BasicFileAttributes.class);
            require(before.fileKey() != null, "provenance fixture needs observable file identity");
            var runner = new ValidatorSupervisor(helper);
            var polls = new java.util.concurrent.atomic.AtomicInteger();
            var changes = new java.util.concurrent.atomic.AtomicInteger();
            try {
                runner.run(tool, List.of(), evidence, Duration.ofSeconds(5), 1, () -> {
                    int poll = polls.incrementAndGet();
                    try {
                        // Poll 1 admits the request; poll 2 precedes the helper's digest open.
                        if (poll == 2 && !mode.equals("read-length")) {
                            switch (mode) {
                                case "identity" -> {
                                    Files.move(helper, directory.resolve("previous-helper"));
                                    Files.write(helper, bytes, StandardOpenOption.CREATE_NEW);
                                    Files.setPosixFilePermissions(helper, permissions);
                                    Files.setLastModifiedTime(helper, before.lastModifiedTime());
                                }
                                case "size" -> {
                                    Files.write(helper, new byte[] {32}, StandardOpenOption.APPEND);
                                    Files.setLastModifiedTime(helper, before.lastModifiedTime());
                                }
                                case "modified" -> Files.setLastModifiedTime(helper,
                                    java.nio.file.attribute.FileTime.fromMillis(before.lastModifiedTime().toMillis() + 2000));
                                default -> throw new AssertionError(mode);
                            }
                            changes.incrementAndGet();
                        }
                        // The small file fits one digest buffer. Append before its read, then
                        // restore length/mtime before EOF: equal stat snapshots cannot justify
                        // accepting a digest that observed a different byte count.
                        if (mode.equals("read-length") && poll == 3) {
                            Files.write(helper, new byte[] {32}, StandardOpenOption.APPEND);
                            changes.incrementAndGet();
                        }
                        if (mode.equals("read-length") && poll == 4) {
                            try (var channel = FileChannel.open(helper, StandardOpenOption.WRITE)) {
                                channel.truncate(bytes.length);
                            }
                            Files.setLastModifiedTime(helper, before.lastModifiedTime());
                            changes.incrementAndGet();
                        }
                    }
                    catch (IOException failure) { throw new java.io.UncheckedIOException(failure); }
                    return false;
                });
                throw new AssertionError("changed helper admitted: " + mode);
            }
            catch (IOException expected) {
                require(expected.getMessage().contains("changed while observing provenance"),
                    "wrong provenance refusal for " + mode + ": " + expected);
            }
            require(changes.get() == (mode.equals("read-length") ? 2 : 1), "provenance race was not exercised");
            requireEmpty(evidence);
            var after = Files.readAttributes(helper, java.nio.file.attribute.BasicFileAttributes.class);
            require(before.fileKey().equals(after.fileKey()) == !mode.equals("identity"), "wrong identity control");
            require((before.size() == after.size()) == !mode.equals("size"), "wrong size control");
            require(before.lastModifiedTime().equals(after.lastModifiedTime()) == !mode.equals("modified"), "wrong timestamp control");
            if (mode.equals("read-length")) require(Arrays.equals(bytes, Files.readAllBytes(helper)),
                "read-length race did not restore the complete fixture bytes");
        }
        System.out.println("validator-provenance-races=PASS cases=4 scope=prelaunch-linux");
    }

    @FunctionalInterface
    private interface Operation { void run() throws Exception; }

    private static void invalidArgument(Path evidence, Operation operation) throws Exception {
        try { operation.run(); throw new AssertionError("invalid launch bounds/argument admitted"); }
        catch (IllegalArgumentException expected) { checks++; }
        requireEmpty(evidence);
    }

    private static void invalidTool(Path evidence, Operation operation) throws Exception {
        try { operation.run(); throw new AssertionError("invalid tool admitted"); }
        catch (IOException expected) {
            require(expected.getMessage().contains("bounded executable regular file"), "tool rejected for executable-file contract");
        }
        requireEmpty(evidence);
    }

    private static void requireEmpty(Path evidence) throws IOException {
        try (var files = Files.list(evidence)) { require(files.findAny().isEmpty(), "rejected launch creates no evidence or child output"); }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
