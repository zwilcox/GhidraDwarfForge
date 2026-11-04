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
import java.nio.charset.StandardCharsets;
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
        "[--cancel-on-stdin] [--cancel-file ABSOLUTE_EMPTY_FILE] [--recover] [--preview] [--enable-security-privilege]\n" +
        "Run only in a separately authorized process. This command never requests elevation.\n" +
        "--cancel-on-stdin: any input byte or EOF requests cancellation; keep stdin open while running.\n" +
        "--cancel-file: changes/removal of the caller's fresh empty file request cooperative cancellation.\n" +
        "Windows launchers use --request-utf8-base64 and --cancel-file-utf8-base64 for lossless path transport.\n" +
        "Retain the request, backups, validation evidence and transaction/recovery receipts on failure.\n";

    record Command(Path request, String sha256, boolean cancelOnStdin, boolean recovery, boolean preview, boolean securityPrivilege,
            Path cancelFile) { }
    record Admitted(Command command, AttachmentInvocation invocation, AttachmentPaths.Plan plan) { }

    private AttachmentHelper() { }

    public static void main(String[] args) {
        // Windows console/pipe encodings must not corrupt literal selected paths
        // in the launcher protocol, even when the host uses a legacy code page.
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(System.err, true, StandardCharsets.UTF_8));
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
        try {
            var command = command(args);
            if (command.cancelFile() != null) {
                var file = new AttachmentCancellationFile(command.cancelFile());
                var external = cancelled;
                cancelled = () -> external.getAsBoolean() || file.getAsBoolean();
            }
        }
        catch (IOException | RuntimeException failure) {
            var response = new JsonObject();
            response.addProperty("schemaVersion", 1);
            response.addProperty("outcome", "FAILED");
            response.addProperty("error", failure.toString());
            response.addProperty("exitCode", 1);
            output.println(response);
            return 1;
        }
        return execute(args, cancelled, output);
    }

    private static int execute(String[] args, BooleanSupplier cancelled, PrintStream output) {
        if (java.util.Arrays.asList(args).contains("--preview")) return preview(args, cancelled, output);
        if (java.util.Arrays.asList(args).contains("--recover")) return recover(args, cancelled, output);
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
            try (var session = open(invocation.operation(), cancelled, admitted.command().securityPrivilege())) {
                admitted.plan().recheck();
                var host = session.host();
                // Hold just the immutable helper inputs after preparation starts;
                // NEW_FILE roles and the target intentionally change in the transaction.
                var inputSelections = admitted.plan().selections().stream().filter(selection ->
                    selection.role().equals("invocation") || selection.role().startsWith("tool")).toList();
                var inputPlan = AttachmentPaths.preflight(inputSelections);
                var inputs = new HashMap<String, AttachmentFileStore.Snapshot>();
                var tools = new HashMap<String, ValidatorInput.Snapshot>();
                for (var entry : inputPlan.paths().entrySet()) {
                    if (entry.getKey().startsWith("tool")) {
                        tools.put(entry.getKey(), ValidatorInput.observe(entry.getValue(), cancelled));
                    }
                    else inputs.put(entry.getKey(), AttachmentFileStore.observe(entry.getValue(), host, cancelled));
                }
                if (!inputs.get("invocation").digest().sha256().equals(admitted.command().sha256())) {
                    throw new IOException("attachment request changed after explicit selection");
                }
                var validator = invocation.validator();
                AttachmentOperation.Validator guarded = (binding, evidence, selectedHost, stop) -> {
                    recheck(inputPlan, inputs, tools, selectedHost, stop);
                    validator.validate(binding, evidence, selectedHost, stop);
                    recheck(inputPlan, inputs, tools, selectedHost, stop);
                };
                Path savedRecovery = admitted.plan().paths().get("recoveryInvocation");
                var recoveryDestination = AttachmentPaths.preflight(java.util.List.of(new AttachmentPaths.Selection(
                    "recoveryInvocation", savedRecovery, AttachmentPaths.Kind.NEW_FILE)));
                completed = AttachmentOperation.execute(invocation.operation(), host, guarded, cancelled,
                    boundary -> recheck(inputPlan, inputs, tools, host, cancelled), prepared -> {
                        recoveryDestination.recheck();
                        recheck(inputPlan, inputs, tools, host, cancelled);
                        inputs.put("savedRecovery", AttachmentRecoveryFile.publish(savedRecovery, prepared, host, cancelled));
                    });
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
            if (completed.transaction().outcome() == AttachmentReceipt.Phase.COMMITTED && completed.transaction().receipt() != null) {
                var selected = new TreeMap<>(completed.recoveryRequest().files());
                selected.put("receipt", completed.recoveryRequest().receipt());
                selected.put("recoveryReceipt", completed.recoveryRequest().recoveryReceipt());
                selected.put("restoreImage", completed.recoveryRequest().restoreImage());
                response.add("recoveryInvocation", JsonParser.parseString(new AttachmentRecoveryInvocation(selected,
                    completed.transaction().receipt().sha256()).toJson()));
            }
        }
        else response.addProperty("outcome", status == 130 ? "CANCELLED" : "FAILED");
        response.addProperty("exitCode", status);
        output.println(response);
        return output.checkError() ? 1 : status;
    }

    static Admitted admit(String[] args, BooleanSupplier cancelled) throws IOException {
        Command command = command(args);
        byte[] bytes = readPinned(command.request(), command.sha256(), REQUEST_LIMIT, cancelled);
        var invocation = AttachmentInvocation.read(new ByteArrayInputStream(bytes), cancelled);
        return new Admitted(command, invocation, withCancellation(invocation.preflight(command.request()), command));
    }

    private static AttachmentPaths.Plan withCancellation(AttachmentPaths.Plan plan, Command command) throws IOException {
        if (command.cancelFile() == null) return plan;
        var selections = new java.util.ArrayList<>(plan.selections());
        selections.add(new AttachmentPaths.Selection("cancellation", command.cancelFile(), AttachmentPaths.Kind.INPUT));
        return AttachmentPaths.preflight(selections);
    }

    static Command command(String[] args) throws IOException {
        Path request = null;
        String sha = null;
        boolean confirmed = false;
        boolean control = false;
        boolean recovery = false;
        boolean preview = false;
        boolean securityPrivilege = false;
        Path cancelFile = null;
        for (int index = 0; index < args.length; index++) {
            switch (args[index]) {
                case "--cancel-file", "--cancel-file-utf8-base64" -> {
                    boolean encoded = args[index].equals("--cancel-file-utf8-base64");
                    if (cancelFile != null || ++index == args.length) throw new IOException("select exactly one cancellation file");
                    cancelFile = Path.of(encoded ? AttachmentPathArgument.decode(args[index]) : args[index]);
                    if (!cancelFile.isAbsolute()) throw new IOException("cancellation file must be absolute");
                }
                case "--request", "--request-utf8-base64" -> {
                    boolean encoded = args[index].equals("--request-utf8-base64");
                    if (request != null || ++index == args.length) throw new IOException("select exactly one request");
                    request = Path.of(encoded ? AttachmentPathArgument.decode(args[index]) : args[index]);
                }
                case "--request-sha256" -> {
                    if (sha != null || ++index == args.length) throw new IOException("select exactly one request SHA-256");
                    sha = args[index];
                }
                case "--confirm-target-change" -> {
                    if (confirmed) throw new IOException("duplicate target-change confirmation");
                    confirmed = true;
                }
                case "--enable-security-privilege" -> {
                    if (securityPrivilege) throw new IOException("duplicate security privilege selection");
                    securityPrivilege = true;
                }
                case "--preview" -> {
                    if (preview) throw new IOException("duplicate preview action");
                    preview = true;
                }
                case "--recover" -> {
                    if (recovery) throw new IOException("duplicate recovery action");
                    recovery = true;
                }
                case "--cancel-on-stdin" -> {
                    if (control) throw new IOException("duplicate cancellation channel");
                    control = true;
                }
                default -> throw new IOException("unknown attachment helper argument");
            }
        }
        if ((!confirmed && !preview) || request == null || !request.isAbsolute() || sha == null || !sha.matches("[0-9a-f]{64}")) {
            throw new IOException("explicit --confirm-target-change, absolute --request and lowercase --request-sha256 are required");
        }
        return new Command(request, sha, control, recovery, preview, securityPrivilege, cancelFile);
    }

    /** Read-only user review, including path/receipt checks but no native host or validator execution. */
    private static int preview(String[] args, BooleanSupplier cancelled, PrintStream output) {
        var response = new JsonObject();
        response.addProperty("schemaVersion", 1);
        int status;
        try {
            var command = command(args);
            if (command.recovery()) {
                var invocation = AttachmentRecoveryInvocation.read(new ByteArrayInputStream(
                    readPinned(command.request(), command.sha256(), REQUEST_LIMIT, cancelled)), cancelled);
                withCancellation(invocation.preview(invocation.transaction(cancelled), command.request()), command).recheck();
                response.add("selection", JsonParser.parseString(invocation.toJson()));
                var deferred = new com.google.gson.JsonArray();
                deferred.add("targetAfter");
                response.add("deferredPathChecks", deferred);
            }
            else {
                var admitted = admit(args, cancelled);
                admitted.plan().recheck();
                response.add("selection", JsonParser.parseString(admitted.invocation().toJson()));
            }
            response.addProperty("requestSha256", command.sha256());
            response.addProperty("outcome", "PREVIEW");
            response.addProperty("notice", command.recovery() ?
                "Read-only review: private candidate path checks are deferred until authorization. All selected paths, the native target and backups must pass verification before recovery writes." :
                "This selection changes the executable only after explicit confirmation and successful live validation. Preview is read-only.");
            status = 0;
        }
        catch (IOException | RuntimeException failure) {
            status = failure instanceof CancellationException ? 130 : 1;
            response.addProperty("outcome", status == 130 ? "CANCELLED" : "FAILED");
            response.addProperty("error", failure.toString());
        }
        response.addProperty("exitCode", status);
        output.println(response);
        return output.checkError() ? 1 : status;
    }

    private static int recover(String[] args, BooleanSupplier cancelled, PrintStream output) {
        var response = new JsonObject();
        response.addProperty("schemaVersion", 1);
        AttachmentTransaction.Result completed = null;
        int status;
        try {
            var command = command(args);
            byte[] bytes = readPinned(command.request(), command.sha256(), REQUEST_LIMIT, cancelled);
            var invocation = AttachmentRecoveryInvocation.read(new ByteArrayInputStream(bytes), cancelled);
            var transaction = invocation.transaction(cancelled);
            var plan = withCancellation(invocation.preflight(transaction, command.request()), command);
            response.addProperty("requestSha256", command.sha256());
            response.add("selection", JsonParser.parseString(invocation.toJson()));
            plan.recheck();
            check(cancelled);
            try (var session = openRecovery(transaction, command.securityPrivilege())) {
                plan.recheck();
                var host = session.host();
                var request = AttachmentFileStore.observe(plan.paths().get("invocation"), host, cancelled);
                if (!request.digest().sha256().equals(command.sha256()) ||
                        !invocation.acceptsReceiptSha256(AttachmentReceiptStore.read(transaction.receipt(), host, cancelled).sha256())) {
                    throw new IOException("recovery request or interrupted receipt changed");
                }
                AttachmentFileStore.unchanged(request, host, cancelled);
                check(cancelled);
                // Recovery cannot be cancelled halfway through restoring an image.
                // It rechecks native backup/target/receipt bindings internally.
                completed = AttachmentTransaction.recoverInterrupted(transaction, host);
            }
            status = completed.outcome() == AttachmentReceipt.Phase.ROLLED_BACK ? 0 : 1;
        }
        catch (IOException | RuntimeException failure) {
            response.addProperty("error", failure.toString());
            if (failure.getCause() != null) response.addProperty("cause", failure.getCause().toString());
            status = failure instanceof CancellationException ? 130 : 1;
        }
        response.addProperty("outcome", completed != null ? completed.outcome().name() : status == 130 ? "CANCELLED" : "FAILED");
        if (completed != null) {
            response.addProperty("diagnostic", completed.diagnostic());
            if (completed.recoveryReceipt() != null) {
                response.add("recoveryReceipt", JsonParser.parseString(completed.recoveryReceipt().receipt().toJson()));
            }
        }
        response.addProperty("exitCode", status);
        output.println(response);
        return output.checkError() ? 1 : status;
    }

    static byte[] readPinned(Path selected, String sha, int limit, BooleanSupplier cancelled) throws IOException {
        return readPinned(selected, sha::equals, limit, cancelled);
    }

    static byte[] readPinned(Path selected, java.util.function.Predicate<String> accepted, int limit,
            BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        if (!Files.isRegularFile(selected, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("attachment selection must be a regular non-link file");
        }
        byte[] bytes;
        try (var input = Files.newInputStream(selected, LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(limit + 1);
        }
        check(cancelled);
        if (bytes.length > limit || !accepted.test(sha256(bytes))) {
            throw new IOException("attachment selection exceeds limit or differs from the explicitly selected SHA-256");
        }
        return bytes;
    }

    private static Session openRecovery(AttachmentTransaction.Request request, boolean securityPrivilege) throws IOException {
        requireWindowsPrivilegeOption(securityPrivilege);
        if (Platform.isLinux()) {
            var host = LinuxAttachmentHost.openRecovery(request);
            return new Session(host, host);
        }
        if (Platform.isWindows()) return windowsSession(securityPrivilege);
        throw new IOException("attachment recovery requires a validated Linux or Windows native host");
    }

    private record Session(AttachmentOperation.Host host, AutoCloseable lifetime) implements AutoCloseable {
        @Override public void close() throws IOException {
            try { lifetime.close(); }
            catch (IOException failure) { throw failure; }
            catch (Exception failure) { throw new IOException("attachment host cleanup failed", failure); }
        }
    }

    private static Session open(AttachmentOperation.Request request, BooleanSupplier cancelled, boolean securityPrivilege) throws IOException {
        requireWindowsPrivilegeOption(securityPrivilege);
        check(cancelled);
        if (Platform.isLinux()) {
            var host = LinuxAttachmentHost.open(request, cancelled);
            return new Session(host, host);
        }
        if (Platform.isWindows()) return windowsSession(securityPrivilege);
        throw new IOException("attachment helper requires a validated Linux or Windows native host");
    }

    private static void requireWindowsPrivilegeOption(boolean requested) throws IOException {
        if (requested && !Platform.isWindows()) throw new IOException("--enable-security-privilege is Windows-only");
    }

    private static Session windowsSession(boolean securityPrivilege) throws IOException {
        WindowsAttachmentPrivilege privilege = securityPrivilege ? new WindowsAttachmentPrivilege() : null;
        try { return new Session(new WindowsAttachmentHost(), privilege == null ? () -> { } : privilege); }
        catch (IOException | RuntimeException failure) {
            if (privilege != null) {
                try { privilege.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            }
            throw failure;
        }
    }

    private static void recheck(AttachmentPaths.Plan plan, Map<String, AttachmentFileStore.Snapshot> inputs,
            Map<String, ValidatorInput.Snapshot> tools, AttachmentOperation.Host host, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        plan.recheck();
        for (var input : inputs.values()) AttachmentFileStore.unchanged(input, host, cancelled);
        for (var tool : tools.values()) ValidatorInput.unchanged(tool, cancelled);
    }

    private static JsonObject paths(Map<String, Path> paths) {
        var json = new JsonObject();
        for (var entry : new TreeMap<>(paths).entrySet()) json.addProperty(entry.getKey(), entry.getValue().toString());
        return json;
    }

    static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("attachment helper cancelled");
    }
}
