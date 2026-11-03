package ghidradwarfforge.output;

import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

/** Owned native Windows real-ELF fixtures exercise both explicit public permission choices. */
public final class WindowsAttachmentOperationProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 13) throw new IllegalArgumentException(
            "report original sidecar source helper readelf llvm strict configuration fresh-results ghidra-directory extension-directory powershell-executable");
        if (!System.getProperty("os.name").startsWith("Windows")) throw new IllegalStateException("requires native Windows");
        // Test-only adjustment of an already owned token privilege. Production
        // host/validator code does not enable privileges or request elevation.
        try (var privilege = new WindowsFileSecurityProbe.OwnPrivilege(true)) {
            var host = new WindowsAttachmentHost();
            Path root = Files.createDirectory(Path.of(args[9]).toAbsolutePath());
            var originals = new LinkedHashMap<String, AttachmentFileStore.Snapshot>();
            String[] roles = { "exportReport", "exportOriginal", "sidecar", "source" };
            for (int index = 0; index < roles.length; index++) {
                originals.put(roles[index], AttachmentFileStore.observe(Path.of(args[index]), host, () -> false));
            }
            var validator = new AttachmentValidator(Path.of(args[4]), Path.of(args[5]), Path.of(args[6]),
                Path.of(args[7]), Path.of(args[8]));
            var outcomes = new ArrayList<Object>();
            // Separate targets, never an automatic retry with different permissions.
            // Current-permission output stays redirected and diagnoses failures
            // before a receipt exists; the RunAs fixture remains mandatory.
            for (String action : java.util.List.of("current-permissions", "commit", "rollback")) {
                boolean rollback = action.equals("rollback");
                Path directory = Files.createDirectory(root.resolve(action));
                var selected = new LinkedHashMap<String, Path>();
                for (var entry : originals.entrySet()) {
                    if (entry.getKey().equals("source")) {
                        // DWARF and the immutable export report refer to this
                        // exact source path. Attachment does not relocate source.
                        selected.put(entry.getKey(), entry.getValue().path());
                        continue;
                    }
                    Path copy = directory.resolve(entry.getValue().path().getFileName());
                    Files.copy(entry.getValue().path(), copy);
                    selected.put(entry.getKey(), copy);
                }
                Path target = selected.get("exportOriginal");
                var before = AttachmentFileStore.observe(target, host, () -> false);
                var request = new AttachmentOperation.Request(target, selected.get("sidecar"), selected.get("source"),
                    selected.get("exportReport"), directory.resolve("original.backup"), directory.resolve("validation.json"),
                    directory.resolve("transaction.json"), directory.resolve("recovery.json"), directory.resolve("restore.elf"), null);
                var result = rollback ? AttachmentOperation.execute(request, host, validator, () -> false, boundary -> {
                    if (boundary == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                        throw new IOException("owned Windows real-ELF rollback control");
                    }
                }) : launchPublic(request, args, host, before, action.equals("commit"));
                var expected = rollback ? AttachmentReceipt.Phase.ROLLED_BACK : AttachmentReceipt.Phase.COMMITTED;
                require(result.transaction().outcome() == expected, "unexpected native ELF outcome: " + result.transaction());
                var after = AttachmentFileStore.observe(target, host, () -> false);
                var backup = AttachmentFileStore.observe(request.originalBackup(), host, () -> false);
                require(before.digest().equals(backup.digest()), "independent original backup differs");
                require(before.fingerprint().metadataSha256().equals(backup.fingerprint().metadataSha256()) &&
                    before.fingerprint().metadataSha256().equals(after.fingerprint().metadataSha256()), "metadata preservation differs");
                require(!backup.fingerprint().identity().equals(after.fingerprint().identity()), "backup aliases installed image");
                if (rollback) require(after.digest().equals(before.digest()), "rollback did not restore original ELF bytes");
                else require(after.digest().sha256().equals(result.recoveryRequest().prepared().files().get("targetAfter").sha256()),
                    "installed ELF differs from validated candidate");
                for (var input : originals.values()) AttachmentFileStore.unchanged(input, host, () -> false);
                outcomes.add(Map.of("case", action, "before", before, "after", after,
                    "backup", backup, "operation", result));
                Files.writeString(root.resolve("progress.json"), json(outcomes));
            }
            Files.writeString(root.resolve("result.json"), json(Map.of("outcomes", outcomes,
                "scope", "Real Windows exporter artifact, production Host/Operation/live validators; explicit current permissions and RunAs initial commits, plus rollback")),
                StandardOpenOption.CREATE_NEW);
            System.out.println("windows-attachment-operation=PASS cases=3");
        }
    }

    private static String json(Object value) {
        return new GsonBuilder().registerTypeHierarchyAdapter(Path.class,
            (com.google.gson.JsonSerializer<Path>) (path, type, context) -> new com.google.gson.JsonPrimitive(path.toString()))
            .setPrettyPrinting().create().toJson(value);
    }

    private static AttachmentOperation.Result launchPublic(AttachmentOperation.Request request, String[] args,
            WindowsAttachmentHost host, AttachmentFileStore.Snapshot before, boolean authorize) throws Exception {
        Path directory = request.target().getParent();
        var tools = Map.of("helper", Path.of(args[4]), "readelf", Path.of(args[5]), "llvm", Path.of(args[6]),
            "strict", Path.of(args[7]), "configuration", Path.of(args[8]));
        Path saved = directory.resolve("saved-recovery.json");
        var invocation = new AttachmentInvocation(request, tools, saved);
        Path transport = Files.writeString(directory.resolve("attachment-request-λ space.json"), invocation.toJson(), StandardOpenOption.CREATE_NEW);
        var command = new ArrayList<String>(java.util.List.of(args[12], "-NoLogo", "-NoProfile", "-File",
            Path.of(args[11], "support", "ghidra-dwarf-forge-attach.ps1").toString(), "-GhidraDirectory", args[10],
            "-ExtensionDirectory", args[11], "-JavaExecutable", Path.of(System.getProperty("java.home"), "bin", "java.exe").toString(),
            "-RequestFile", transport.toString(), "-RequestSha256", FileDigests.read(transport, () -> false).sha256()));
        for (String mode : java.util.List.of("preview", "no-consent", "execute")) {
            var actual = new ArrayList<>(command);
            if (mode.equals("preview")) actual.add("-Preview");
            if (mode.equals("execute")) {
                actual.add("-ConfirmTargetChange");
                if (authorize) actual.add("-Authorize");
            }
            Path stdout = directory.resolve("launcher-" + mode + ".stdout");
            Files.writeString(directory.resolve("launcher-" + mode + ".argv.json"),
                new com.google.gson.Gson().toJson(actual), StandardOpenOption.CREATE_NEW);
            var child = new ProcessBuilder(actual).redirectOutput(stdout.toFile())
                .redirectError(directory.resolve("launcher-" + mode + ".stderr").toFile()).start();
            try {
                require(child.waitFor(180, java.util.concurrent.TimeUnit.SECONDS), "public Windows launcher timed out");
                require(child.exitValue() == (mode.equals("no-consent") ? 64 : 0),
                    "public Windows launcher failed: " + mode + " exit=" + child.exitValue());
            }
            finally {
                if (child.isAlive()) {
                    child.destroyForcibly();
                    require(child.waitFor(5, java.util.concurrent.TimeUnit.SECONDS), "launcher did not exit after timeout");
                }
            }
            var records = Files.readAllLines(stdout).stream().filter(line -> !line.isBlank())
                .map(com.google.gson.JsonParser::parseString).map(com.google.gson.JsonElement::getAsJsonObject).toList();
            require(records.stream().filter(record -> record.has("outcome") && record.get("outcome").getAsString().equals("PREVIEW"))
                .count() == 1, "launcher did not preview the selection exactly once");
            if (!mode.equals("execute")) {
                AttachmentFileStore.unchanged(before, host, () -> false);
                require(!Files.exists(request.originalBackup()) && !Files.exists(request.receipt()) && !Files.exists(saved),
                    "read-only launcher created transaction outputs");
            }
            else if (authorize) require(records.stream().anyMatch(record -> record.has("launcherExitCode") &&
                record.get("launcherExitCode").getAsInt() == 0), "missing successful explicit RunAs result");
            else require(records.stream().anyMatch(record -> record.has("outcome") &&
                record.get("outcome").getAsString().equals("COMMITTED")), "missing current-permission helper result");
        }
        var recovery = AttachmentRecoveryInvocation.read(Files.newInputStream(saved), () -> false).transaction(() -> false);
        var receipt = AttachmentReceiptStore.read(request.receipt(), host, () -> false);
        require(receipt.receipt().phase() == AttachmentReceipt.Phase.COMMITTED, "launcher did not commit native receipt");
        var selected = new LinkedHashMap<>(recovery.files());
        selected.put("receipt", request.receipt());
        selected.put("recoveryReceipt", request.recoveryReceipt());
        selected.put("restoreImage", request.restoreImage());
        return new AttachmentOperation.Result(new AttachmentTransaction.Result(receipt.receipt().phase(), receipt, null,
            AttachmentFileStore.observe(request.target(), host, () -> false), false, null), recovery, selected);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
