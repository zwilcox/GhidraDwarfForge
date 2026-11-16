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
