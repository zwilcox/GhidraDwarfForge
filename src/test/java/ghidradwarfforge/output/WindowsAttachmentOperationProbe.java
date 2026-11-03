package ghidradwarfforge.output;

import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

/** Owned native Windows real-ELF fixture; the public attachment entry point is separate. */
public final class WindowsAttachmentOperationProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 10) throw new IllegalArgumentException(
            "report original sidecar source helper readelf llvm strict configuration fresh-results");
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
            for (boolean rollback : new boolean[] { false, true }) {
                Path directory = Files.createDirectory(root.resolve(rollback ? "rollback" : "commit"));
                var selected = new LinkedHashMap<String, Path>();
                for (var entry : originals.entrySet()) {
                    Path copy = directory.resolve(entry.getValue().path().getFileName());
                    Files.copy(entry.getValue().path(), copy);
                    selected.put(entry.getKey(), copy);
                }
                Path target = selected.get("exportOriginal");
                var before = AttachmentFileStore.observe(target, host, () -> false);
                var request = new AttachmentOperation.Request(target, selected.get("sidecar"), selected.get("source"),
                    selected.get("exportReport"), directory.resolve("original.backup"), directory.resolve("validation.json"),
                    directory.resolve("transaction.json"), directory.resolve("recovery.json"), directory.resolve("restore.elf"), null);
                var result = AttachmentOperation.execute(request, host, validator, () -> false, boundary -> {
                    if (rollback && boundary == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                        throw new IOException("owned Windows real-ELF rollback control");
                    }
                });
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
                outcomes.add(Map.of("case", rollback ? "rollback" : "commit", "before", before, "after", after,
                    "backup", backup, "operation", result));
                Files.writeString(root.resolve("progress.json"), json(outcomes));
            }
            Files.writeString(root.resolve("result.json"), json(Map.of("outcomes", outcomes,
                "scope", "Real Windows exporter artifact, production Host/Operation/live validators; initial commit and rollback only")),
                StandardOpenOption.CREATE_NEW);
            System.out.println("windows-attachment-operation=PASS cases=2");
        }
    }

    private static String json(Object value) {
        return new GsonBuilder().registerTypeHierarchyAdapter(Path.class,
            (com.google.gson.JsonSerializer<Path>) (path, type, context) -> new com.google.gson.JsonPrimitive(path.toString()))
            .setPrettyPrinting().create().toJson(value);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
