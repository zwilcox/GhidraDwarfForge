package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.file.Files;
import java.nio.file.Path;

/** Test-only explicit paths for the saved-program integration harness. */
public final class AttachmentCuratedRefreshProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("supply the owned fixture request JSON");
        JsonObject selected = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        boolean productionHost = Boolean.getBoolean("forge.test.attachment.productionLinuxHost");
        var refresh = selected.has("previousReceipt") ? new AttachmentOperation.Refresh(
            path(selected, "previousReceipt"), path(selected, "previousSidecar"),
            path(selected, "previousSource"), path(selected, "priorTargetBackup")) : null;
        var request = new AttachmentOperation.Request(path(selected, "target"), path(selected, "sidecar"),
            path(selected, "source"), path(selected, "exportReport"), path(selected, "originalBackup"),
            path(selected, "validationEvidence"), path(selected, "receipt"), path(selected, "recoveryReceipt"),
            path(selected, "restoreImage"), refresh);
        JsonObject tools = selected.getAsJsonObject("validatorTools");
        if (tools == null) throw new IllegalArgumentException("curated refresh requires live validator tools");
        var validator = new AttachmentValidator(path(tools, "helper"), path(tools, "readelf"), path(tools, "llvm"),
            path(tools, "strict"), path(tools, "configuration"));
        try (var nativeHost = productionHost ? LinuxAttachmentHost.open(request, () -> false) : null) {
            AttachmentOperation.Host host = nativeHost == null ? new AttachmentElfTransactionProbe.Host() : nativeHost;
            Path missing = selected.has("missingDependency") ? path(selected, "missingDependency") : null;
            Path hidden = missing == null ? null : missing.resolveSibling(missing.getFileName() + ".test-hidden");
            if (missing != null && (!SourceBundleFiles.open(request.source(), () -> false).orElseThrow().files().contains(missing) ||
                    missing.equals(request.source()) || Files.exists(hidden))) {
                throw new IllegalArgumentException("fault must select one existing bundle dependency and a fresh hidden name");
            }
            try {
                var result = AttachmentOperation.execute(request, host, validator, () -> false, boundary -> {
                    if (missing != null && boundary.name().equals(selected.get("faultBoundary").getAsString())) {
                        Files.move(missing, hidden);
                    }
                });
                var expected = missing == null ? AttachmentReceipt.Phase.COMMITTED : AttachmentReceipt.Phase.ROLLED_BACK;
                if (result.transaction().outcome() != expected) throw new AssertionError(result.transaction());
                System.out.println("attachment-curated-refresh=" + expected + " mode=" + (refresh == null ? "initial" : "refresh") +
                    " host=" + (productionHost ? "production-linux" : "test-only"));
            }
            finally {
                if (hidden != null && Files.exists(hidden)) Files.move(hidden, missing);
            }
        }
    }

    private static Path path(JsonObject selected, String name) {
        return Path.of(selected.get(name).getAsString());
    }
}
