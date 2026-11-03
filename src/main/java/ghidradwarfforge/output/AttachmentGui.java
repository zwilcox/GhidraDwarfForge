package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.util.task.TaskMonitor;

import java.awt.BorderLayout;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

/** Script Manager review/consent front end. All modifying/native work runs in a separate JVM. */
public final class AttachmentGui {
    private static final int OUTPUT_LIMIT = 4 * 1024 * 1024;
    record ProcessResult(int exitCode, String output, String errors, boolean cancellationRequested) { }

    private AttachmentGui() { }

    public static void run(GhidraScript script, TaskMonitor monitor, boolean recovery) throws Exception {
        if (script.isRunningHeadless()) throw new IOException("Use the attachment launcher for headless operation");
        Path request = script.askFile(recovery ? "Select saved attachment recovery request" :
            "Select attachment or refresh request", "Select").toPath().toAbsolutePath();
        // Read a bounded, non-link selection. The helper checks the same digest
        // both during preview and again after the consent/authorization dialogs.
        if (!Files.isRegularFile(request, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Select a regular request file");
        byte[] bytes;
        try (var input = Files.newInputStream(request, LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(256 * 1024 + 1);
        }
        if (bytes.length > 256 * 1024) throw new IOException("Attachment request exceeds 256 KiB");
        String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        Path module = Application.getModuleRootDir("GhidraDwarfForge").getFile(false).toPath();
        Path ghidra = Application.getInstallationDirectory().getFile(false).toPath();
        boolean windows = System.getProperty("os.name").startsWith("Windows");
        if (!windows && !System.getProperty("os.name").equals("Linux")) {
            throw new IOException("Attachment requires a validated Linux or Windows host");
        }
        Path java = Path.of(System.getProperty("java.home"), "bin", windows ? "java.exe" : "java");
        var dependencies = List.of(module.resolve("lib/GhidraDwarfForge.jar"),
            ghidra.resolve("Ghidra/Framework/Pty/lib/jna-5.14.0.jar"),
            ghidra.resolve("Ghidra/Framework/Generic/lib/gson-2.9.0.jar"));
        for (var path : dependencies) {
            if (!Files.isRegularFile(path) || path.toString().contains(File.pathSeparator)) {
                throw new IOException("Missing or ambiguous installed helper dependency: " + path);
            }
        }
        var previewCommand = new ArrayList<>(List.of(java.toString(), "-cp",
            String.join(File.pathSeparator, dependencies.stream().map(Path::toString).toList()),
            "ghidradwarfforge.output.AttachmentHelper", "--request", request.toString(), "--request-sha256", sha,
            "--preview"));
        if (recovery) previewCommand.add("--recover");
        monitor.setMessage("Checking attachment selections without changing the executable");
        ProcessResult preview = process(previewCommand, monitor::isCancelled, null, true);
        script.println(preview.output());
        if (preview.exitCode() != 0) throw new IOException("Attachment preview failed: " + preview.output() + preview.errors());
        JsonObject review = JsonParser.parseString(preview.output()).getAsJsonObject();
        if (!"PREVIEW".equals(review.get("outcome").getAsString())) throw new IOException("Helper did not confirm a read-only preview");
        monitor.checkCancelled();
        if (!confirm(review.getAsJsonObject("selection"), recovery)) {
            script.println("GhidraDwarfForge attachment declined; modifying helper was not started.");
            return;
        }
        String authorization = script.askChoice("Attachment helper authorization",
            "Ghidra stays unprivileged. Choose permissions for the separate helper.",
            List.of("Cancel", "Use current permissions", "Request OS authorization"), "Cancel");
        if (authorization.equals("Cancel")) {
            script.println("GhidraDwarfForge attachment declined; modifying helper was not started.");
            return;
        }
        Path powershell = windows ? script.askFile("Select PowerShell 7 executable", "Select").toPath().toAbsolutePath() : null;
        monitor.checkCancelled();
        Path controlDirectory = Files.createTempDirectory("forge-attachment-control-");
        Path control = controlDirectory.resolve("cancel");
        try (var channel = FileChannel.open(control, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            var command = launcher(windows, powershell, module, ghidra, java, request, sha, control,
                recovery, authorization.equals("Request OS authorization"));
            script.println("Starting explicit target change. Preserve the selected request, saved recovery request, backups and receipts.");
            monitor.setMessage(recovery ? "Recovering attachment; restoration completes before cancellation" :
                "Attaching sidecar; Cancel requests safe rollback");
            ProcessResult result = process(command, () -> {
                if (monitor.isCancelled()) monitor.setMessage("Cancellation requested; waiting for a safe helper outcome");
                return monitor.isCancelled();
            }, channel, false);
            script.println(result.output());
            if (!result.errors().isBlank()) script.printerr(result.errors());
            script.println("Attachment helper exit=" + result.exitCode() + "; cancellation requested=" + result.cancellationRequested() +
                ". Durable transaction/recovery receipts determine the target's final state.");
            if (result.exitCode() != 0) {
                throw new IOException("Attachment helper did not report success. Preserve the selected files and inspect the receipts; " +
                    "use RecoverGhidraDwarfForgeAttachment.java with the saved recovery request if recovery is required.");
            }
        }
        finally {
            // Only the private control file is temporary. Never remove selected
            // requests, backups, validator evidence or transaction artifacts.
            Files.deleteIfExists(control);
            Files.deleteIfExists(controlDirectory);
        }
    }

    static List<String> launcher(boolean windows, Path powershell, Path module, Path ghidra, Path java,
            Path request, String sha, Path control, boolean recovery, boolean authorize) {
        var command = new ArrayList<String>();
        if (windows) {
            command.addAll(List.of(powershell.toString(), "-NoProfile", "-NonInteractive", "-File",
                module.resolve("support/ghidra-dwarf-forge-attach.ps1").toString(),
                "-RequestFile", request.toString(), "-RequestSha256", sha, "-GhidraDirectory", ghidra.toString(),
                "-ExtensionDirectory", module.toString(), "-JavaExecutable", java.toString(),
                "-CancellationFile", control.toString(), "-ConfirmTargetChange"));
            if (recovery) command.add("-Recover");
            if (authorize) command.add("-Authorize");
        }
        else {
            command.addAll(List.of(module.resolve("support/ghidra-dwarf-forge-attach").toString(),
                "--request=" + request, "--request-sha256=" + sha, "--ghidra-dir=" + ghidra,
                "--extension-dir=" + module, "--java=" + java, "--cancel-file=" + control, "--confirm-target-change"));
            if (recovery) command.add("--recover");
            if (authorize) command.add("--authorize=pkexec");
        }
        return List.copyOf(command);
    }

    private static boolean confirm(JsonObject selection, boolean recovery) throws Exception {
        var result = new FutureTask<Boolean>(() -> {
            JTextArea paths = new JTextArea(selectionSummary(selection), 22, 95);
            paths.setEditable(false);
            paths.setLineWrap(true);
            paths.setCaretPosition(0);
            JPanel content = new JPanel(new BorderLayout(0, 10));
            content.add(new JLabel(recovery ? "Recovery changes the executable back to the selected pre-operation image." :
                "Attachment changes the selected executable. Live validation and an independent backup are required."), BorderLayout.NORTH);
            content.add(new JScrollPane(paths), BorderLayout.CENTER);
            content.add(new JLabel("Keep all backups and receipts. Cancel is the default; ordinary export remains unchanged."), BorderLayout.SOUTH);
            String action = recovery ? "Restore selected image" : "Attach selected sidecar";
            return JOptionPane.showOptionDialog(null, content, "Review GhidraDwarfForge target change",
                JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, null, new String[] {"Cancel", action}, "Cancel") == 1;
        });
        if (SwingUtilities.isEventDispatchThread()) result.run();
        else SwingUtilities.invokeLater(result);
        return result.get();
    }

    private static String selectionSummary(JsonObject selection) {
        var text = new StringBuilder("Operation: ").append(selection.get("operation").getAsString()).append("\n\n");
        var paths = selection.getAsJsonObject("paths");
        for (String role : List.of("target", "targetBefore", "sidecar", "source", "originalBackup", "priorTargetBackup",
                "receipt", "recoveryInvocation", "recoveryReceipt", "restoreImage", "previousReceipt", "previousSidecar",
                "previousSource", "exportReport", "validationEvidence", "targetAfter")) {
            if (!paths.has(role)) continue;
            String label = switch (role) {
                case "target", "targetBefore" -> "Executable";
                case "sidecar" -> "Sidecar";
                case "source" -> "Synthetic source";
                case "originalBackup" -> "Original backup";
                case "priorTargetBackup" -> "Backup of previous attached executable";
                case "receipt" -> "Receipt";
                case "recoveryInvocation" -> "Saved recovery request";
                case "recoveryReceipt" -> "Recovery receipt";
                case "restoreImage" -> "Recovery staging image";
                case "previousReceipt" -> "Previous receipt to retain";
                case "previousSidecar" -> "Previous sidecar to retain";
                case "previousSource" -> "Previous source to retain";
                case "exportReport" -> "Export report";
                case "validationEvidence" -> "Validation evidence";
                case "targetAfter" -> "Prepared replacement path";
                default -> throw new IllegalStateException("unlabelled selected path");
            };
            text.append(label).append(":\n").append(displayPath(paths.get(role).getAsString())).append("\n\n");
        }
        if (selection.has("validatorTools")) {
            text.append("Selected validation tools (run by the separate helper):\n");
            for (var entry : selection.getAsJsonObject("validatorTools").entrySet()) {
                text.append(entry.getKey()).append(": ").append(displayPath(entry.getValue().getAsString())).append("\n");
            }
        }
        return text.toString();
    }

    private static String displayPath(String path) {
        var text = new StringBuilder();
        path.codePoints().forEach(character -> {
            if (Character.isISOControl(character)) text.append(String.format("\\u%04x", character));
            else text.appendCodePoint(character);
        });
        return text.toString();
    }

    static ProcessResult process(List<String> command, BooleanSupplier cancelled, FileChannel channel,
            boolean readOnly) throws Exception {
        Process child = new ProcessBuilder(command).start();
        child.getOutputStream().close(); // No stdin control flag; UAC cannot forward stdin.
        var stdout = drain(child.getInputStream());
        var stderr = drain(child.getErrorStream());
        boolean requested = false;
        boolean interrupted = false;
        IOException signalFailure = null;
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        try {
            while (true) {
                try { if (child.waitFor(100, TimeUnit.MILLISECONDS)) break; }
                catch (InterruptedException interruption) { interrupted = true; }
                if ((cancelled.getAsBoolean() || interrupted || readOnly && System.nanoTime() >= deadline) && !requested) {
                    requested = true;
                    if (readOnly) child.destroyForcibly();
                    else {
                        // Do not kill a modifying helper, including while it is
                        // in an OS prompt or restoring the previous generation.
                        try {
                            channel.write(ByteBuffer.wrap(new byte[] {1}));
                            channel.force(true);
                        }
                        catch (IOException failure) {
                            // A signalling error must not abandon a still-live
                            // modifying child or hide its eventual receipt state.
                            signalFailure = failure;
                        }
                    }
                }
            }
            String output = stdout.get(10, TimeUnit.SECONDS);
            String errors = stderr.get(10, TimeUnit.SECONDS);
            if (signalFailure != null) errors += "\nCancellation signal failed: " + signalFailure;
            return new ProcessResult(child.exitValue(), output, errors, requested);
        }
        finally { if (interrupted) Thread.currentThread().interrupt(); }
    }

    private static CompletableFuture<String> drain(InputStream input) {
        var result = new CompletableFuture<String>();
        Thread.ofVirtual().start(() -> {
            try (input; var bytes = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                boolean overflow = false;
                for (int count; (count = input.read(buffer)) != -1;) {
                    if (count <= OUTPUT_LIMIT - bytes.size()) bytes.write(buffer, 0, count);
                    else overflow = true; // Continue draining so a helper can finish safely.
                }
                if (overflow) throw new IOException("Helper output exceeded 4 MiB; inspect retained receipts");
                result.complete(bytes.toString(StandardCharsets.UTF_8));
            }
            catch (Exception failure) { result.completeExceptionally(failure); }
        });
        return result;
    }
}
