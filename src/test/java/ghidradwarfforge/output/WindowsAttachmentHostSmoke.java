package ghidradwarfforge.output;

import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.concurrent.CancellationException;

/** Actual store/host integration in an isolated JVM, using exclusively owned files. */
public final class WindowsAttachmentHostSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        if (!System.getProperty("os.name").startsWith("Windows")) throw new IllegalStateException("requires Windows");
        if (args.length != 1) throw new IllegalArgumentException("fresh evidence directory required");
        Path root = Files.createDirectory(Path.of(args[0]).toAbsolutePath());
        var facts = new LinkedHashMap<String, Object>();
        try (var privilege = new WindowsFileSecurityProbe.OwnPrivilege(true)) {
            var host = new WindowsAttachmentHost();
            var metadata = new WindowsAttachmentMetadata();
            Path target = root.resolve("original target");
            Path stageParent = Files.createDirectory(root.resolve("owned stage"));
            Path stage = stageParent.resolve("candidate");
            Files.writeString(target, "original complete executable sentinel", StandardOpenOption.CREATE_NEW);
            Files.writeString(stage, "different complete candidate sentinel with a different length", StandardOpenOption.CREATE_NEW);
            var original = AttachmentFileStore.observe(target, host, () -> false);
            var originalMetadata = metadata.inspect(target, () -> false);
            facts.put("original", original);
            facts.put("originalMetadata", originalMetadata);
            var backup = AttachmentFileStore.backup(original, root.resolve("retained backup"), host, () -> false);
            facts.put("backup", backup);
            require(!backup.fingerprint().identity().equals(original.fingerprint().identity()), "backup aliases original");
            require(backup.digest().sha256().equals(original.digest().sha256()), "backup bytes differ");
            reject(() -> AttachmentFileStore.backup(original, backup.path(), host, () -> false), "exists");
            AttachmentFileStore.unchanged(original, host, () -> false);
            AttachmentFileStore.unchanged(backup, host, () -> false);

            reject(() -> host.replaceAtomic(stage, target), "would change metadata");
            AttachmentFileStore.unchanged(original, host, () -> false);
            try (var channel = FileChannel.open(stage, StandardOpenOption.WRITE)) {
                host.preserveMetadata(target, original.fingerprint(), stage);
                channel.force(true);
            }
            host.syncDirectory(stageParent);
            var candidate = AttachmentFileStore.observe(stage, host, () -> false);
            facts.put("candidate", candidate);
            facts.put("candidateMetadata", metadata.inspect(stage, () -> false));
            try {
                AttachmentTargetStore.replace(original, candidate, host, () -> true);
                throw new AssertionError("cancelled replacement succeeded");
            }
            catch (CancellationException expected) { checks++; }
            AttachmentFileStore.unchanged(original, host, () -> false);
            AttachmentFileStore.unchanged(candidate, host, () -> false);
            var installed = AttachmentTargetStore.replace(original, candidate, host, () -> false);
            require(installed.digest().sha256().equals(candidate.digest().sha256()), "installed bytes differ");
            require(installed.fingerprint().equals(candidate.fingerprint()), "installed metadata or identity differs");
            require(!Files.exists(stage), "stage remains after replacement");
            facts.put("installed", installed);
            facts.put("installedMetadata", metadata.inspect(target, () -> false));
            AttachmentFileStore.unchanged(backup, host, () -> false);
            var restored = AttachmentTargetStore.restore(installed, backup, root.resolve("owned restore"), host, () -> false);
            require(restored.digest().sha256().equals(original.digest().sha256()), "restore bytes differ");
            require(restored.fingerprint().metadataSha256().equals(original.fingerprint().metadataSha256()), "restore metadata differs");
            require(!restored.fingerprint().identity().equals(backup.fingerprint().identity()), "restore consumed backup");
            AttachmentFileStore.unchanged(backup, host, () -> false);
            facts.put("restored", restored);
            facts.put("restoredMetadata", metadata.inspect(target, () -> false));
            facts.put("directory", host.directoryIdentity(root));
            facts.put("contract", host.contract());
            facts.put("durability", host.durability());
            var observer = new WindowsFileMetadata();
            for (int i = 0; i < 32; i++) host.inspect(target);
            long handles = observer.processHandleCount();
            for (int i = 0; i < 128; i++) {
                require(host.inspect(target).equals(restored.fingerprint()), "repeated host fingerprint changed");
                require(observer.processHandleCount() == handles, "host inspection leaked handles");
            }
            facts.put("handleCycles", 128);
            facts.put("handleCount", handles);
        }
        try (var privilege = new WindowsFileSecurityProbe.OwnPrivilege(false)) {
            var host = new WindowsAttachmentHost();
            try {
                host.inspect(root.resolve("original target"));
                throw new AssertionError("complete metadata accepted without security privilege");
            }
            catch (IOException expected) {
                require(expected.getMessage().contains("error=1314"), "unexpected missing-privilege refusal: " + expected);
                facts.put("missingPrivilege", expected.getMessage());
            }
        }
        facts.put("checks", checks);
        facts.put("scope", "Native Host with backup/replace/restore stores; not public attachment or power-loss recovery acceptance");
        var json = new GsonBuilder().registerTypeHierarchyAdapter(Path.class,
            (com.google.gson.JsonSerializer<Path>) (value, type, context) -> new com.google.gson.JsonPrimitive(value.toString()))
            .setPrettyPrinting().create();
        Files.writeString(root.resolve("result.json"), json.toJson(facts),
            StandardOpenOption.CREATE_NEW);
        System.out.println("windows-attachment-host=PASS checks=" + checks);
    }

    @FunctionalInterface private interface Action { void run() throws IOException; }
    private static void reject(Action action, String reason) throws IOException {
        try { action.run(); throw new AssertionError("accepted " + reason); }
        catch (IOException expected) {
            require(expected.getMessage().contains(reason), "unexpected refusal: " + expected);
        }
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
