package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.jna.Platform;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/**
 * Standalone, explicitly authorized attachment entry point. Never invoke main
 * inside Ghidra. No privilege acquisition, shell evaluation, captured validator
 * approval or permissive host fallback occurs here. Output is one JSON result;
 * the transaction's durable receipts remain authoritative if stdout is lost.
 */
public final class AttachmentHelper {
    private static final int REQUEST_LIMIT = 256 * 1024;
    private static final String HELP = "Attachment changes the selected executable and retains an independent backup.\n" +
        "Usage: AttachmentHelper --request ABSOLUTE_JSON --request-sha256 SHA256 --confirm-target-change " +
        "[--cancel-on-stdin]\n" +
        "Run only in a separately authorized process. This command never requests elevation.\n" +
        "--cancel-on-stdin: any input byte or EOF requests cancellation; keep stdin open while running.\n" +
        "Retain the request, backups, validation evidence and transaction/recovery receipts on failure.\n";

    record Command(Path request, String sha256, boolean cancelOnStdin) { }
    record Admitted(Command command, AttachmentInvocation invocation, AttachmentPaths.Plan plan) { }

    private AttachmentHelper() { }

    public static void main(String[] args) {
        var cancelled = new AtomicBoolean();
        // The opt-in channel is deliberately inert data: no command, path or
        // receipt is ever interpreted from stdin. Closing the launcher cancels.
        if (java.util.Arrays.asList(args).contains("--cancel-on-stdin")) {
            Thread watcher = new Thread(() -> {
                try { System.in.read(); }
                catch (IOException closed) { /* A lost control channel cancels. */ }
                finally { cancelled.set(true); }
            }, "forge-attachment-cancel");
            watcher.setDaemon(true);
            watcher.start();
        }
        int status = run(args, cancelled::get, System.out);
        System.exit(status);
    }

    static int run(String[] args, BooleanSupplier cancelled, PrintStream output) {
        if (args.length == 1 && args[0].equals("--help")) {
            output.print(HELP);
            return output.checkError() ? 1 : 0;
        }
        AttachmentOperation.Result completed = null;
        AttachmentInvocation invocation = null;
        JsonObject response = new JsonObject();
        response.addProperty("schemaVersion", 1);
        int status;
        try {
            var admitted = admit(args, cancelled);
            invocation = admitted.invocation();
            response.addProperty("requestSha256", admitted.command().sha256());
            response.add("selection", JsonParser.parseString(invocation.toJson()));
            admitted.plan().recheck();
            try (var session = open(invocation.operation(), cancelled)) {
                admitted.plan().recheck();
                var host = session.host();
                // Hold just the immutable helper inputs after preparation starts;
                // NEW_FILE roles and the target intentionally change in the transaction.
                var inputSelections = admitted.plan().selections().stream().filter(selection ->
                    selection.role().equals("invocation") || selection.role().startsWith("tool")).toList();
                var inputPlan = AttachmentPaths.preflight(inputSelections);
                var inputs = new HashMap<String, AttachmentFileStore.Snapshot>();
                for (var entry : inputPlan.paths().entrySet()) {
                    inputs.put(entry.getKey(), AttachmentFileStore.observe(entry.getValue(), host, cancelled));
                }
                if (!inputs.get("invocation").digest().sha256().equals(admitted.command().sha256())) {
                    throw new IOException("attachment request changed after explicit selection");
                }
                var validator = invocation.validator();
                AttachmentOperation.Validator guarded = (binding, evidence, selectedHost, stop) -> {
                    recheck(inputPlan, inputs, selectedHost, stop);
                    validator.validate(binding, evidence, selectedHost, stop);
                    recheck(inputPlan, inputs, selectedHost, stop);
                };
                completed = AttachmentOperation.execute(invocation.operation(), host, guarded, cancelled,
                    boundary -> recheck(inputPlan, inputs, host, cancelled));
            }
            status = completed.transaction().outcome() == AttachmentReceipt.Phase.COMMITTED ? 0 :
                completed.transaction().cancelled() ? 130 : 1;
        }
        catch (IOException | RuntimeException failure) {
            // In particular, host cleanup failure after COMMITTED must not be
            // presented as an unchanged executable or erase the committed outcome.
            response.addProperty("error", failure.toString());
            if (failure.getCause() != null) response.addProperty("cause", failure.getCause().toString());
            if (failure instanceof AttachmentOperation.PreparationFailure preparation) {
                response.add("retainedPaths", paths(preparation.selected()));
            }
            status = failure instanceof CancellationException ||
                failure instanceof AttachmentOperation.PreparationFailure preparation && preparation.cancelled() ? 130 : 1;
        }
        if (completed != null) {
            response.addProperty("outcome", completed.transaction().outcome().name());
            response.addProperty("cancelled", completed.transaction().cancelled());
            response.addProperty("diagnostic", completed.transaction().diagnostic());
            response.add("retainedPaths", paths(completed.selected()));
            var recovery = new JsonObject();
            recovery.add("prepared", JsonParser.parseString(completed.recoveryRequest().prepared().toJson()));
            recovery.add("files", paths(completed.recoveryRequest().files()));
            recovery.addProperty("receipt", completed.recoveryRequest().receipt().toString());
            recovery.addProperty("recoveryReceipt", completed.recoveryRequest().recoveryReceipt().toString());
            recovery.addProperty("restoreImage", completed.recoveryRequest().restoreImage().toString());
            response.add("recoverySelection", recovery);
        }
        else response.addProperty("outcome", status == 130 ? "CANCELLED" : "FAILED");
        response.addProperty("exitCode", status);
        output.println(response);
        return output.checkError() ? 1 : status;
    }

    static Admitted admit(String[] args, BooleanSupplier cancelled) throws IOException {
        Command command = command(args);
        check(cancelled);
        if (!Files.isRegularFile(command.request(), LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("attachment request must be a regular non-link file");
        }
        byte[] bytes;
        try (var input = Files.newInputStream(command.request(), LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(REQUEST_LIMIT + 1);
        }
        check(cancelled);
        if (bytes.length > REQUEST_LIMIT || !sha256(bytes).equals(command.sha256())) {
            throw new IOException("attachment request exceeds limit or differs from the explicitly selected SHA-256");
        }
        var invocation = AttachmentInvocation.read(new ByteArrayInputStream(bytes), cancelled);
        return new Admitted(command, invocation, invocation.preflight(command.request()));
    }

    static Command command(String[] args) throws IOException {
        Path request = null;
        String sha = null;
        boolean confirmed = false;
        boolean control = false;
        for (int index = 0; index < args.length; index++) {
            switch (args[index]) {
                case "--request" -> {
                    if (request != null || ++index == args.length) throw new IOException("select exactly one request");
                    request = Path.of(args[index]);
                }
                case "--request-sha256" -> {
                    if (sha != null || ++index == args.length) throw new IOException("select exactly one request SHA-256");
                    sha = args[index];
                }
                case "--confirm-target-change" -> {
                    if (confirmed) throw new IOException("duplicate target-change confirmation");
                    confirmed = true;
                }
                case "--cancel-on-stdin" -> {
                    if (control) throw new IOException("duplicate cancellation channel");
                    control = true;
                }
                default -> throw new IOException("unknown attachment helper argument");
            }
        }
        if (!confirmed || request == null || !request.isAbsolute() || sha == null || !sha.matches("[0-9a-f]{64}")) {
            throw new IOException("explicit --confirm-target-change, absolute --request and lowercase --request-sha256 are required");
        }
        return new Command(request, sha, control);
    }

    private record Session(AttachmentOperation.Host host, AutoCloseable lifetime) implements AutoCloseable {
        @Override public void close() throws IOException {
            try { lifetime.close(); }
            catch (IOException failure) { throw failure; }
            catch (Exception failure) { throw new IOException("attachment host cleanup failed", failure); }
        }
    }

    private static Session open(AttachmentOperation.Request request, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        if (Platform.isLinux()) {
            var host = LinuxAttachmentHost.open(request, cancelled);
            return new Session(host, host);
        }
        if (Platform.isWindows()) return new Session(new WindowsAttachmentHost(), () -> { });
        throw new IOException("attachment helper requires a validated Linux or Windows native host");
    }

    private static void recheck(AttachmentPaths.Plan plan, Map<String, AttachmentFileStore.Snapshot> inputs,
            AttachmentOperation.Host host, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        plan.recheck();
        for (var input : inputs.values()) AttachmentFileStore.unchanged(input, host, cancelled);
    }

    private static JsonObject paths(Map<String, Path> paths) {
        var json = new JsonObject();
        for (var entry : new TreeMap<>(paths).entrySet()) json.addProperty(entry.getKey(), entry.getValue().toString());
        return json;
    }

    private static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("attachment helper cancelled");
    }
}
