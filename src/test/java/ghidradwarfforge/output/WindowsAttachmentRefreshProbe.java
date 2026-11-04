package ghidradwarfforge.output;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;

/** Owned saved-program refresh fixture; privilege adjustment is test-only. */
public final class WindowsAttachmentRefreshProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !System.getProperty("os.name").startsWith("Windows")) {
            throw new IllegalArgumentException("native Windows: owned request JSON and new result JSON required");
        }
        var selected = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        var refresh = new AttachmentOperation.Refresh(path(selected, "previousReceipt"),
            path(selected, "previousSidecar"), path(selected, "previousSource"), path(selected, "priorTargetBackup"));
        var request = new AttachmentOperation.Request(path(selected, "target"), path(selected, "sidecar"),
            path(selected, "source"), path(selected, "exportReport"), path(selected, "originalBackup"),
            path(selected, "validationEvidence"), path(selected, "receipt"), path(selected, "recoveryReceipt"),
            path(selected, "restoreImage"), refresh);
        var tools = selected.getAsJsonObject("validatorTools");
        var validator = new AttachmentValidator(path(tools, "helper"), path(tools, "readelf"), path(tools, "llvm"),
            path(tools, "strict"), path(tools, "configuration"));
        try (var privilege = new WindowsFileSecurityProbe.OwnPrivilege(true)) {
            var host = new WindowsAttachmentHost();
            var before = AttachmentFileStore.observe(request.target(), host, () -> false);
            var protectedFiles = new LinkedHashMap<Path, AttachmentFileStore.Snapshot>();
            for (Path file : new Path[] { refresh.previousReceipt(), refresh.previousSidecar(), refresh.previousSource(),
                    request.originalBackup(), request.sidecar(), request.source(), request.exportReport() }) {
                protectedFiles.put(file, AttachmentFileStore.observe(file, host, () -> false));
            }
            require(protectedFiles.get(refresh.previousSidecar()).digest().gnuDebuglinkCrc32() !=
                protectedFiles.get(request.sidecar()).digest().gnuDebuglinkCrc32(), "refresh must change CRC");
            var result = AttachmentOperation.execute(request, host, validator, () -> false);
            require(result.transaction().outcome() == AttachmentReceipt.Phase.COMMITTED, "refresh failed: " + result.transaction());
            var after = AttachmentFileStore.observe(request.target(), host, () -> false);
            var prior = AttachmentFileStore.observe(refresh.priorTargetBackup(), host, () -> false);
            require(prior.digest().equals(before.digest()), "prior image backup differs");
            require(before.fingerprint().metadataSha256().equals(prior.fingerprint().metadataSha256()) &&
                before.fingerprint().metadataSha256().equals(after.fingerprint().metadataSha256()), "refresh metadata differs");
            require(!prior.fingerprint().identity().equals(after.fingerprint().identity()), "backup aliases target");
            for (var file : protectedFiles.values()) AttachmentFileStore.unchanged(file, host, () -> false);
            var gson = new GsonBuilder().registerTypeHierarchyAdapter(Path.class,
                (com.google.gson.JsonSerializer<Path>) (path, type, context) -> new com.google.gson.JsonPrimitive(path.toString()))
                .setPrettyPrinting().create();
            Files.writeString(Path.of(args[1]), gson.toJson(Map.of("before", before, "after", after,
                "priorBackup", prior, "operation", result, "protectedFiles", protectedFiles.values())), StandardOpenOption.CREATE_NEW);
            System.out.println("windows-attachment-curated-refresh=PASS changed-crc=true");
        }
    }

    private static Path path(JsonObject object, String name) { return Path.of(object.get(name).getAsString()); }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
