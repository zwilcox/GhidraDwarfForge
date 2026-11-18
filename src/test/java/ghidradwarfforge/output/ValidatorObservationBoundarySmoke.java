package ghidradwarfforge.output;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Mutation/cancellation at every observable boundary of real file inspection. */
public final class ValidatorObservationBoundarySmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-validator-observation-");
        try { exercise(root); }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    static void exercise(Path root) throws Exception {
        for (String identity : new String[] {"", "device:inode"}) {
            for (long links : new long[] {-1, 0, 1, Long.MAX_VALUE}) {
                for (long bytes : new long[] {-1, 0, Long.MAX_VALUE}) {
                    boolean valid = !identity.isEmpty() && links > 0 && bytes >= 0;
                    try {
                        var observation = new ValidatorInput.Observation(identity, links, bytes, "");
                        require(valid, "invalid file observation accepted");
                        require(observation.identity().equals(identity) && observation.links() == links &&
                            observation.bytes() == bytes, "file observation narrowed or changed");
                    }
                    catch (IllegalArgumentException refused) {
                        require(!valid, "valid file observation rejected");
                    }
                }
            }
        }
        byte[] original = new byte[131_073];
        for (int i = 0; i < original.length; i++) original[i] = (byte) (i * 31);
        Path input = root.resolve("validator-tool");
        Files.write(input, original);
        var polls = new AtomicInteger();
        var stable = ValidatorInput.observe(input, () -> { polls.incrementAndGet(); return false; });
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(original));
        require(stable.digest().sha256().equals(digest) && stable.digest().byteCount() == original.length &&
            stable.observation().bytes() == original.length, "stable observation changed tool contents");
        for (int stop = 1; stop <= polls.get(); stop++) {
            int cancelAt = stop;
            var counter = new AtomicInteger();
            try {
                ValidatorInput.observe(input, () -> counter.incrementAndGet() >= cancelAt);
                throw new AssertionError("observation cancellation ignored at " + stop);
            }
            catch (CancellationException expected) { checks++; }
            require(Arrays.equals(original, Files.readAllBytes(input)), "cancelled observation modified input");
            ValidatorInput.unchanged(stable, () -> false);
        }
        byte[] changed = Arrays.copyOf(original, original.length + 1);
        changed[original.length] = 93;
        String changedDigest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(changed));
        int refused = 0;
        int nativeRefused = 0;
        for (int at = 1; at <= polls.get(); at++) {
            Files.write(input, original);
            int mutateAt = at;
            var counter = new AtomicInteger();
            try {
                var observed = ValidatorInput.observe(input, () -> {
                    if (counter.incrementAndGet() == mutateAt) {
                        try { Files.write(input, new byte[] {93}, StandardOpenOption.APPEND); }
                        catch (IOException failure) { throw new UncheckedIOException(failure); }
                    }
                    return false;
                });
                // Edits before the first facts read or after the final facts
                // read can be accepted: this API does not promise atomicity.
                String actual = observed.digest().sha256();
                boolean old = actual.equals(digest);
                require(old || actual.equals(changedDigest), "observation accepted a mixed byte digest");
                long size = old ? original.length : changed.length;
                require(observed.digest().byteCount() == size && observed.observation().bytes() == size,
                    "observation accepted inconsistent file size and digest");
            }
            catch (IOException expected) {
                // Windows also rechecks the selected path inside each facts
                // read. A mutation there is refused before the outer snapshot
                // comparison. Accept only those two explicit change diagnoses.
                Throwable cause = expected.getCause();
                String reason = cause == null ? "" : cause.getMessage();
                boolean outerChange = "validator input changed during observation".equals(reason);
                boolean nativeChange = com.sun.jna.Platform.isWindows() &&
                    "Windows selected metadata path changed".equals(reason);
                require(outerChange || nativeChange,
                    "unexpected observation refusal at poll " + at + ": " + expected);
                if (outerChange) refused++;
                else nativeRefused++;
            }
            require(Arrays.equals(changed, Files.readAllBytes(input)), "observation changed the injected input");
            var retry = ValidatorInput.observe(input, () -> false);
            require(retry.digest().sha256().equals(changedDigest), "stable retry failed after mutation");
        }
        require(refused > 0, "concurrent changes were never refused");
        require(!com.sun.jna.Platform.isWindows() || nativeRefused > 0,
            "Windows selected-path changes were never refused");
        System.out.println("validator-observation-boundaries=PASS checks=" + checks +
            " mutation-refusals=" + refused + " native-mutation-refusals=" + nativeRefused);
    }

    private static void require(boolean condition, String diagnostic) {
        if (!condition) throw new AssertionError(diagnostic);
        checks++;
    }
}
