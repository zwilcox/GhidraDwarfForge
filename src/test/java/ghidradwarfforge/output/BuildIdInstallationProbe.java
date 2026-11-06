package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

/** Real filesystem/validator probe; production hosts require an explicit test selection. */
public final class BuildIdInstallationProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("configuration root install|update|remove|recover");
        JsonObject config = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        Path root = Path.of(args[1]);
        String action = args[2];
        var cancelled = new AtomicBoolean();
        var published = new AtomicBoolean();
        AttachmentOperation.Host delegate = switch (System.getProperty("forge.test.buildId.host", "model")) {
            case "model" -> new AttachmentElfTransactionProbe.Host();
            case "linux" -> new LinuxBuildIdHost();
            case "windows" -> new WindowsAttachmentHost();
            default -> throw new IllegalArgumentException("unknown build-ID test host");
        };
        AttachmentOperation.Host host = new AttachmentOperation.Host() {
            public String contract() { return delegate.contract(); }
            public String durability() { return delegate.durability(); }
            public byte[] debuglinkBasename(Path path) throws IOException { return delegate.debuglinkBasename(path); }
            public AttachmentReceiptStore.Fingerprint inspect(Path path) throws IOException { return delegate.inspect(path); }
            public String directoryIdentity(Path path) throws IOException { return delegate.directoryIdentity(path); }
            public void preserveMetadata(Path source, AttachmentReceiptStore.Fingerprint before, Path stage) throws IOException {
                delegate.preserveMetadata(source, before, stage);
            }
            public void publishNew(Path stage, Path target) throws IOException { delegate.publishNew(stage, target); }
            public void replaceAtomic(Path stage, Path target) throws IOException { delegate.replaceAtomic(stage, target); }
            public void syncDirectory(Path directory) throws IOException {
                if (published.get() && Boolean.getBoolean("forge.test.buildId.failPublicationSync")) {
                    throw new IOException("injected publication sync failure");
                }
                delegate.syncDirectory(directory);
            }
        };
        BuildIdInstallation.Hook hook = boundary -> {
            if (boundary == BuildIdInstallation.Boundary.PUBLISHED) published.set(true);
            if (boundary.name().equals(System.getProperty("forge.test.buildId.crash"))) Runtime.getRuntime().halt(73);
            if (boundary.name().equals(System.getProperty("forge.test.buildId.fail"))) throw new IOException("injected " + boundary);
            if (boundary.name().equals(System.getProperty("forge.test.buildId.cancel"))) cancelled.set(true);
        };
        String buildId = config.get("buildId").getAsString();
        BuildIdInstallation.Result result;
        switch (action) {
            case "remove" -> result = BuildIdInstallation.remove(root, buildId, host, cancelled::get, hook);
            case "recover" -> result = BuildIdInstallation.recover(root, buildId, host, cancelled::get);
            case "install", "update" -> {
                JsonObject files = config.getAsJsonObject("files"), tools = config.getAsJsonObject("tools");
                var validator = new AttachmentValidator(path(tools, "helper"), path(tools, "readelf"),
                    path(tools, "llvm"), path(tools, "strict"), path(tools, "configuration"));
                var request = new BuildIdInstallation.Request(root, path(files, "original"), path(files, "sidecar"),
                    path(files, "source"), path(files, "report"), action.equals("install")
                        ? BuildIdInstallation.Mode.INSTALL : BuildIdInstallation.Mode.UPDATE);
                result = BuildIdInstallation.install(request, host, validator, cancelled::get, hook);
            }
            default -> throw new IllegalArgumentException("unknown test action");
        }
        var json = new JsonObject();
        json.addProperty("outcome", result.outcome().name());
        json.addProperty("buildId", result.buildId());
        json.addProperty("registration", result.registration().toString());
        json.addProperty("source", result.source() == null ? null : result.source().toString());
        json.addProperty("state", result.state().toString());
        json.addProperty("host", host.contract());
        json.addProperty("durability", host.durability());
        System.out.println(json);
    }

    private static Path path(JsonObject object, String key) { return Path.of(object.get(key).getAsString()); }
}
