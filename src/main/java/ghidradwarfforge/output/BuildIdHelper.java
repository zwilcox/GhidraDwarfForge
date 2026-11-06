package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.sun.jna.Platform;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

import static ghidradwarfforge.output.BuildIdRecords.*;

/** Standalone explicit installer. Never enables elevation or runs a shell; original ELF stays read-only. */
public final class BuildIdHelper {
    private static final int REQUEST_LIMIT = 1024 * 1024;
    private static final String HELP = "Usage: BuildIdHelper --request ABSOLUTE_JSON --request-sha256 SHA256 " +
        "[--preview] [--cancel-file ABSOLUTE_EMPTY_FILE] [--cancel-on-stdin] [--enable-security-privilege]\n" +
        "Request action: install, update, remove or recover. The original executable is never modified.\n" +
        "Preview checks selections only; it does not run validators or approve installation.\n" +
        "Retain the debug root and its state/generations after an interruption. Recovery is explicit.\n" +
        "--cancel-on-stdin: any input byte or EOF requests cooperative cancellation.\n" +
        "--enable-security-privilege: Windows-only, enables an existing token privilege without elevation.\n";

    record Command(Path request, String sha256, Path cancelFile, boolean preview, boolean securityPrivilege) { }
    record Invocation(String action, Path root, Map<String, Path> files, Map<String, Path> tools, String id,
            AttachmentPaths.Plan plan) { }
    private record Session(AttachmentOperation.Host host, AutoCloseable lifetime) implements AutoCloseable {
        @Override public void close() throws IOException {
            try { lifetime.close(); }
            catch (IOException failure) { throw failure; }
            catch (Exception failure) { throw new IOException("build-ID host cleanup failed", failure); }
        }
    }

    private BuildIdHelper() { }

    public static void main(String[] args) {
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(System.err, true, StandardCharsets.UTF_8));
        var cancelled = new AtomicBoolean();
        if (java.util.Arrays.asList(args).contains("--cancel-on-stdin")) {
            var watcher = new Thread(() -> {
                try { System.in.read(); }
                catch (IOException closed) { /* A closed control channel cancels. */ }
                finally { cancelled.set(true); }
            }, "forge-build-id-cancel");
            watcher.setDaemon(true);
            watcher.start();
        }
        System.exit(run(args, cancelled::get, System.out));
    }

    static int run(String[] args, BooleanSupplier cancelled, PrintStream output) {
        if (args.length == 1 && args[0].equals("--help")) {
            output.print(HELP);
            return output.checkError() ? 1 : 0;
        }
        var response = new JsonObject();
        response.addProperty("schemaVersion", 1);
        response.addProperty("modifiesOriginal", false);
        int status = 0;
        try {
            Command command = command(args);
            if (command.cancelFile() != null) {
                var file = new AttachmentCancellationFile(command.cancelFile());
                var outer = cancelled;
                cancelled = () -> outer.getAsBoolean() || file.getAsBoolean();
            }
            Invocation invocation = read(command, cancelled);
            response.addProperty("action", invocation.action());
            response.addProperty("root", invocation.root().toString());
            response.addProperty("requestSha256", command.sha256());
            if (command.preview()) {
                response.addProperty("outcome", "PREVIEW_NOT_VALIDATED");
                response.add("files", paths(invocation.files()));
                response.add("tools", paths(invocation.tools()));
                response.addProperty("buildId", invocation.id());
            }
            else {
                check(cancelled);
                invocation.plan().recheck();
                readRequest(command, cancelled);
                boolean sectionless = invocation.files().containsKey("original") &&
                    ghidradwarfforge.elf.ElfImage.read(invocation.files().get("original")).sections().isEmpty();
                try (var session = open(command.securityPrivilege())) {
                    var host = session.host();
                    BuildIdInstallation.Result result = switch (invocation.action()) {
                        case "install", "update" -> {
                            var files = invocation.files();
                            var tools = invocation.tools();
                            var validator = new AttachmentValidator(tools.get("helper"), tools.get("readelf"), tools.get("llvm"),
                                tools.get("strict"), tools.get("configuration"));
                            var request = new BuildIdInstallation.Request(invocation.root(), files.get("original"),
                                files.get("sidecar"), files.get("source"), files.get("report"),
                                invocation.action().equals("install") ? BuildIdInstallation.Mode.INSTALL : BuildIdInstallation.Mode.UPDATE);
                            yield BuildIdInstallation.install(request, host, validator, cancelled);
                        }
                        case "remove" -> BuildIdInstallation.remove(invocation.root(), invocation.id(), host, cancelled);
                        case "recover" -> BuildIdInstallation.recover(invocation.root(), invocation.id(), host, cancelled);
                        default -> throw new AssertionError(invocation.action());
                    };
                    response.addProperty("outcome", result.outcome().name());
                    response.addProperty("buildId", result.buildId());
                    response.addProperty("registration", result.registration().toString());
                    response.addProperty("source", result.source() == null ? null : result.source().toString());
                    response.addProperty("state", result.state().toString());
                    response.addProperty("host", host.contract());
                    response.addProperty("durability", host.durability());
                    if (result.source() != null) {
                        String root = invocation.root().toString();
                        if (java.io.File.separatorChar == '\\') root = root.replace('\\', '/');
                        response.addProperty("gdbSetupCommand", "set debug-file-directory " + root);
                        response.addProperty("consumerSetup", "Apply the GDB search path before loading the original in a fresh session. " +
                            "Installation does not change debugger settings; retained source generations must remain in place.");
                        if (sectionless) {
                            response.addProperty("gdbAutomaticDiscovery", "UNAVAILABLE_IN_TESTED_GDB_FOR_SECTIONLESS_ELF");
                            response.addProperty("consumerSetup", "The original ELF has no section-header table. " +
                                "The tested GDB cannot discover its debug sidecar by build ID, including compiler-generated sidecars. " +
                                "Load the original with file, then load the returned registration path with symbol-file, " +
                                "or use the Forge loader. Installation and retained source remain valid; " +
                                "the original executable is unchanged.");
                        }
                    }
                }
            }
        }
        catch (CancellationException stopped) {
            status = 130;
            response.addProperty("outcome", "CANCELLED");
            response.addProperty("error", stopped.toString());
        }
        catch (IOException | RuntimeException | LinkageError failure) {
            status = 1;
            response.addProperty("outcome", "FAILED");
            response.addProperty("error", failure.toString());
        }
        response.addProperty("exitCode", status);
        output.println(response);
        return output.checkError() ? 1 : status;
    }

    static Command command(String[] args) throws IOException {
        Path request = null, cancelFile = null;
        String sha = null;
        boolean preview = false, security = false;
        var seen = new HashSet<String>();
        for (int index = 0; index < args.length; index++) {
            String key = args[index];
            boolean encoded = key.endsWith("-utf8-base64");
            if (encoded) key = key.substring(0, key.length() - "-utf8-base64".length());
            require(seen.add(key), "duplicate build-ID helper option: " + key);
            if (key.equals("--preview") || key.equals("--cancel-on-stdin") || key.equals("--enable-security-privilege")) {
                require(!encoded, "only pathname options accept encoded transport");
                if (key.equals("--preview")) preview = true;
                if (key.equals("--enable-security-privilege")) security = true;
                continue;
            }
            require(key.equals("--request") || key.equals("--request-sha256") || key.equals("--cancel-file"), "unknown build-ID helper option");
            require(++index < args.length, "missing build-ID helper option value");
            String value = encoded ? AttachmentPathArgument.decode(args[index]) : args[index];
            switch (key) {
                case "--request" -> request = absolute(value);
                case "--cancel-file" -> cancelFile = absolute(value);
                case "--request-sha256" -> { require(!encoded, "SHA-256 must be literal hex"); sha = value; }
                default -> throw new AssertionError(key);
            }
        }
        require(request != null && sha != null && sha.matches("[0-9a-f]{64}"), "select an absolute request and lowercase --request-sha256");
        require(!security || Platform.isWindows(), "--enable-security-privilege is Windows-only");
        return new Command(request, sha, cancelFile, preview, security);
    }

    static Invocation read(Command command, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        Path requestPath = FileSystemPaths.resolveLeaf(command.request(), "build-ID request");
        byte[] bytes = readRequest(command, cancelled);
        var json = BuildIdRecords.read(bytes, cancelled);
        require(text(json, "schema").equals("forge-build-id-request-v1"), "unknown build-ID request schema");
        String action = text(json, "action");
        boolean installing = action.equals("install") || action.equals("update");
        require(installing || action.equals("remove") || action.equals("recover"), "unknown build-ID action");
        if (installing) keys(json, "schema", "action", "root", "files", "tools");
        else keys(json, "schema", "action", "root", "buildId");
        Path root = absolute(text(json, "root")).toRealPath();
        require(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS), "debug root must exist");
        String rootText = root.toString();
        require(rootText.indexOf(java.io.File.pathSeparatorChar) < 0 && rootText.indexOf('\n') < 0 &&
            rootText.indexOf('\r') < 0 && rootText.equals(rootText.strip()),
            "debug root cannot contain a search-path separator, line break or boundary whitespace");
        var selections = new ArrayList<AttachmentPaths.Selection>();
        selections.add(new AttachmentPaths.Selection("request", requestPath, AttachmentPaths.Kind.INPUT));
        if (command.cancelFile() != null) selections.add(new AttachmentPaths.Selection("cancelFile", command.cancelFile(), AttachmentPaths.Kind.INPUT));
        Map<String, Path> files = Map.of(), tools = Map.of();
        String id = null;
        if (installing) {
            var selectedFiles = object(json, "files");
            var selectedTools = object(json, "tools");
            keys(selectedFiles, "original", "sidecar", "source", "report");
            keys(selectedTools, "helper", "readelf", "llvm", "strict", "configuration");
            files = selectedPaths(selectedFiles, false, selections);
            tools = selectedPaths(selectedTools, true, selections);
        }
        else { id = text(json, "buildId"); BuildIdInstallation.validateId(id); }
        var plan = AttachmentPaths.preflight(selections);
        readRequest(command, cancelled);
        check(cancelled);
        return new Invocation(action, root, files, tools, id, plan);
    }

    /** Every read, including rechecks, is bounded before hashing or parsing. */
    private static byte[] readRequest(Command command, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        Path path = FileSystemPaths.resolveLeaf(command.request(), "build-ID request");
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS), "build-ID request must be a regular non-link file");
        byte[] bytes;
        try (var input = Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(REQUEST_LIMIT + 1);
        }
        check(cancelled);
        require(bytes.length <= REQUEST_LIMIT, "build-ID request exceeds 1 MiB");
        require(hash(bytes).equals(command.sha256()), "build-ID request differs from selected SHA-256");
        return bytes;
    }

    private static Map<String, Path> selectedPaths(JsonObject object, boolean tools, ArrayList<AttachmentPaths.Selection> selections)
            throws IOException {
        var values = new TreeMap<String, Path>();
        for (String key : object.keySet()) {
            Path path = absolute(text(object, key));
            if (tools) path = path.toRealPath();
            values.put(key, path);
            selections.add(new AttachmentPaths.Selection(key, path, AttachmentPaths.Kind.INPUT));
        }
        return Map.copyOf(values);
    }

    private static Path absolute(String value) throws IOException {
        require(!value.isEmpty() && value.length() <= 16384 && value.indexOf('\0') < 0, "invalid build-ID pathname");
        Path path = Path.of(value);
        require(path.isAbsolute(), "build-ID paths must be absolute");
        return path;
    }

    private static Session open(boolean security) throws IOException {
        if (Platform.isLinux()) return new Session(new LinuxBuildIdHost(), () -> { });
        if (!Platform.isWindows()) throw new IOException("build-ID installation requires a Linux or Windows host");
        WindowsAttachmentPrivilege privilege = security ? new WindowsAttachmentPrivilege() : null;
        try { return new Session(new WindowsAttachmentHost(), privilege == null ? () -> { } : privilege); }
        catch (IOException | RuntimeException failure) {
            if (privilege != null) try { privilege.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    private static JsonObject paths(Map<String, Path> paths) {
        var result = new JsonObject();
        new TreeMap<>(paths).forEach((key, value) -> result.addProperty(key, value.toString()));
        return result;
    }

    private static String hash(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("build-ID command cancelled");
    }
}
