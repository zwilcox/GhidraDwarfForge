package ghidradwarfforge.output;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

/**
 * Executes a selected validator through the native process owner. Lifecycle
 * success is not DWARF validity: the caller must interpret the retained output
 * and bind it to unchanged selected artifacts before attachment.
 */
public final class ValidatorSupervisor {
    private static final long CLEANUP_ALLOWANCE_MILLIS = 7000;
    private static final long MAX_TOOL_BYTES = 128L * 1024 * 1024;
    private static final long MAX_STREAM_BYTES = 256L * 1024 * 1024;
    private final Path helper;

    public record Status(String reason, long exitCode, long exitSignal, boolean cleanupComplete,
            long stdoutObserved, long stdoutRetained, long stderrObserved, long stderrRetained) { }

    public record Evidence(Path directory, List<String> command, Path helper, String helperSha256,
            Path tool, String toolSha256, Path stdout, FileDigests.Result stdoutDigest,
            Path stderr, FileDigests.Result stderrDigest, Status status) {
        public Evidence { command = List.copyOf(command); }
    }

    public static final class Failure extends IOException {
        private final Path directory;
        private final Evidence evidence;
        Failure(String message, Path directory, Evidence evidence) {
            super(message + "; retained validator evidence: " + directory);
            this.directory = directory;
            this.evidence = evidence;
        }
        public Path directory() { return directory; }
        public Evidence evidence() { return evidence; }
    }

    public static final class Cancelled extends CancellationException {
        private final Path directory;
        Cancelled(Path directory) {
            super("validator cancelled after process cleanup; retained evidence: " + directory);
            this.directory = directory;
        }
        public Path directory() { return directory; }
    }

    /** The caller selects a verified packaged helper or an explicit development path. */
    public ValidatorSupervisor(Path helper) throws IOException {
        String host = System.getProperty("os.name");
        if (!host.equals("Linux") && !host.startsWith("Windows")) {
            throw new IOException("validator supervision requires a supported Linux or Windows host");
        }
        // ProcessBuilder on Linux uses the native/JNU encoding, independently
        // of file.encoding. Refuse a lossy locale before opening evidence files.
        if (host.equals("Linux") && !Charset.forName(System.getProperty("sun.jnu.encoding", "US-ASCII"))
                .equals(StandardCharsets.UTF_8)) {
            throw new IOException("validator supervision requires a UTF-8 Linux native filename/argument encoding");
        }
        this.helper = Objects.requireNonNull(helper).toRealPath();
        toolState(this.helper, () -> false);
    }

    public Evidence run(Path selectedTool, List<String> arguments, Path evidenceParent,
            Duration timeout, long streamByteCap, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(arguments);
        Objects.requireNonNull(cancelled);
        long timeoutMillis = timeout.toMillis();
        if (timeoutMillis < 1 || timeoutMillis > 3_600_000 || streamByteCap < 1 || streamByteCap > MAX_STREAM_BYTES) {
            throw new IllegalArgumentException("invalid validator deadline/output bounds");
        }
        for (String argument : arguments) {
            if (argument == null || argument.indexOf('\0') >= 0 || argument.length() > 32767) {
                throw new IllegalArgumentException("invalid validator argument");
            }
        }
        check(cancelled);
        Path tool = selectedTool.toRealPath();
        ToolState beforeHelper = toolState(helper, cancelled);
        ToolState beforeTool = toolState(tool, cancelled);
        Path directory = Files.createTempDirectory(evidenceParent.toRealPath(), ".forge-validation-");
        Path stdout = directory.resolve("tool.stdout");
        Path stderr = directory.resolve("tool.stderr");
        Path statusPath = directory.resolve("status.json");
        Path helperOut = Files.createFile(directory.resolve("supervisor.stdout"));
        Path helperErr = Files.createFile(directory.resolve("supervisor.stderr"));
        var command = new ArrayList<String>();
        command.add(helper.toString());
        command.add(Long.toString(timeoutMillis));
        command.add(Long.toString(streamByteCap));
        command.add(statusPath.toString());
        command.add(stdout.toString());
        command.add(stderr.toString());
        command.add("--");
        command.add(tool.toString());
        command.addAll(arguments);
        Process process;
        try {
            check(cancelled);
            var builder = new ProcessBuilder(command).directory(directory.toFile())
                .redirectOutput(helperOut.toFile()).redirectError(helperErr.toFile());
            // Keep diagnostic grammar stable independently of the user's UI
            // locale. This does not change the JVM's native argument encoding.
            builder.environment().put("LC_ALL", "C");
            builder.environment().put("LANG", "C");
            builder.environment().put("LANGUAGE", "C");
            process = builder.start();
        }
        catch (IOException failure) {
            throw new Failure("validator supervisor could not start: " + failure.getMessage(), directory, null);
        }
        boolean requestedCancellation = false;
        boolean interrupted = false;
        RuntimeException cancellationFailure = null;
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis + CLEANUP_ALLOWANCE_MILLIS);
        try {
            for (;;) {
                boolean cancelNow = interrupted;
                if (!requestedCancellation) {
                    try { cancelNow |= cancelled.getAsBoolean(); }
                    catch (RuntimeException failure) { cancellationFailure = failure; cancelNow = true; }
                }
                if (!requestedCancellation && cancelNow) {
                    requestedCancellation = true;
                    process.getOutputStream().close();
                    deadline = Math.min(deadline, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(CLEANUP_ALLOWANCE_MILLIS));
                }
                try {
                    if (process.waitFor(25, TimeUnit.MILLISECONDS)) break;
                }
                catch (InterruptedException signal) {
                    interrupted = true;
                    continue;
                }
                if (System.nanoTime() - deadline >= 0) {
                    // Never kill the Linux subreaper and thereby orphan the very
                    // processes it owns. Close its cancellation pipe, retain the
                    // PID/evidence and refuse attachment. Stalled filesystem or
                    // uninterruptible-kernel calls are not a cleanup success.
                    process.getOutputStream().close();
                    throw new Failure("validator supervisor did not establish cleanup; supervisor PID=" + process.pid(), directory, null);
                }
            }
            process.getOutputStream().close();
            if (Files.size(helperOut) != 0 || Files.size(helperErr) != 0) {
                throw new Failure("validator supervisor reported an internal/setup failure", directory, null);
            }
            Status status = readStatus(statusPath);
            if (Files.size(stdout) != status.stdoutRetained() || Files.size(stderr) != status.stderrRetained() ||
                    status.stdoutRetained() > streamByteCap || status.stderrRetained() > streamByteCap) {
                throw new Failure("validator output counters or bounds disagree", directory, null);
            }
            // Recheck tool provenance after execution without allowing late
            // cancellation to skip resource/status reconciliation.
            if (!beforeHelper.equals(toolState(helper, () -> false)) || !beforeTool.equals(toolState(tool, () -> false))) {
                throw new Failure("validator/helper changed during execution", directory, null);
            }
            var evidence = new Evidence(directory, command, helper, beforeHelper.sha256(), tool, beforeTool.sha256(),
                stdout, FileDigests.read(stdout), stderr, FileDigests.read(stderr), status);
            if (!status.cleanupComplete()) throw new Failure("validator process cleanup is incomplete", directory, evidence);
            if (cancellationFailure != null) {
                var failure = new Failure("validator cancellation callback failed after cleanup", directory, evidence);
                failure.initCause(cancellationFailure);
                throw failure;
            }
            if (requestedCancellation || cancelled.getAsBoolean() || status.reason().equals("cancelled")) throw new Cancelled(directory);
            if (process.exitValue() != 0 || !status.reason().equals("completed") || status.exitCode() != 0 || status.exitSignal() != 0) {
                throw new Failure("validator process failed: " + status.reason(), directory, evidence);
            }
            return evidence;
        }
        catch (IOException failure) {
            if (failure instanceof Failure) throw failure;
            var retained = new Failure("validator evidence or supervision failed: " + failure.getMessage(), directory, null);
            retained.initCause(failure);
            throw retained;
        }
        finally {
            try { process.getOutputStream().close(); }
            finally { if (interrupted) Thread.currentThread().interrupt(); }
        }
    }

    private record ToolState(String sha256, long bytes, Object identity, Object modified) { }

    private static ToolState toolState(Path tool, BooleanSupplier cancelled) throws IOException {
        BasicFileAttributes before = Files.readAttributes(tool, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.size() == 0 || before.size() > MAX_TOOL_BYTES || !Files.isExecutable(tool)) {
            throw new IOException("validator/helper must be a bounded executable regular file: " + tool);
        }
        var digest = FileDigests.read(tool, cancelled);
        BasicFileAttributes after = Files.readAttributes(tool, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!Objects.equals(before.fileKey(), after.fileKey()) || before.size() != after.size() ||
                !before.lastModifiedTime().equals(after.lastModifiedTime()) || after.size() != digest.byteCount()) {
            throw new IOException("validator/helper changed while observing provenance: " + tool);
        }
        return new ToolState(digest.sha256(), digest.byteCount(), after.fileKey(), after.lastModifiedTime());
    }

    static Status readStatus(Path path) throws IOException {
        byte[] bytes;
        try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { bytes = input.readNBytes(4097); }
        if (bytes.length > 4096) throw new IOException("supervisor status exceeds its bound");
        for (byte value : bytes) if (value < 0) throw new IOException("supervisor status is not ASCII");
        Set<String> seen = new HashSet<>();
        Map<String, Long> numbers = new HashMap<>();
        String reason = null;
        Boolean complete = null;
        try (var reader = new JsonReader(new StringReader(new String(bytes, StandardCharsets.US_ASCII)))) {
            reader.setLenient(false);
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                if (!seen.add(name)) throw new IOException("duplicate supervisor status field");
                if (name.equals("reason")) {
                    if (reader.peek() != JsonToken.STRING) throw new IOException("invalid supervisor reason");
                    reason = reader.nextString();
                }
                else if (name.equals("cleanupComplete")) {
                    if (reader.peek() != JsonToken.BOOLEAN) throw new IOException("invalid cleanup status");
                    complete = reader.nextBoolean();
                }
                else {
                    if (reader.peek() != JsonToken.NUMBER) throw new IOException("invalid supervisor numeric field");
                    String spelling = reader.nextString();
                    if (!spelling.matches("-1|0|[1-9][0-9]{0,18}")) throw new IOException("invalid supervisor numeric spelling");
                    numbers.put(name, Long.parseLong(spelling));
                }
            }
            reader.endObject();
            if (reader.peek() != JsonToken.END_DOCUMENT || !numbers.keySet().equals(Set.of("schemaVersion", "exitCode",
                    "exitSignal", "stdoutObserved", "stdoutRetained", "stderrObserved", "stderrRetained")) ||
                    numbers.get("schemaVersion") != 1 || complete == null || reason == null ||
                    !Set.of("completed", "tool_error", "cancelled", "timeout", "output_limit", "descendants", "internal_error").contains(reason)) {
                throw new IOException("invalid supervisor status schema");
            }
            for (var entry : numbers.entrySet()) {
                if (entry.getValue() < (entry.getKey().equals("exitCode") ? -1 : 0)) throw new IOException("negative supervisor counter");
            }
            if (numbers.get("stdoutObserved") < numbers.get("stdoutRetained") ||
                    numbers.get("stderrObserved") < numbers.get("stderrRetained") ||
                    numbers.get("exitCode") > 0xffff_ffffL || numbers.get("exitSignal") > 64) {
                throw new IOException("inconsistent supervisor status counters");
            }
            return new Status(reason, numbers.get("exitCode"), numbers.get("exitSignal"), complete,
                numbers.get("stdoutObserved"), numbers.get("stdoutRetained"), numbers.get("stderrObserved"), numbers.get("stderrRetained"));
        }
        catch (IllegalStateException | NumberFormatException invalid) {
            throw new IOException("invalid supervisor status", invalid);
        }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("validator cancelled before launch");
    }
}
