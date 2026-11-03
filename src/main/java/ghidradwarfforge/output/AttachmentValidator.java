package ghidradwarfforge.output;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

/**
 * Mandatory fresh GNU/LLVM/pinned-libdwarf policy for explicit attachment.
 * All tools are selected by the caller; no report-supplied path is executed.
 * This does not supply a host metadata adapter or enable a public attach action.
 */
public final class AttachmentValidator implements AttachmentOperation.Validator {
    private static final int OUTPUT_LIMIT = 32 * 1024 * 1024;
    private static final Duration DEADLINE = Duration.ofMinutes(2);
    private final Map<String, Path> tools;

    /** Select raw executables and the pinned strict-checker configuration. */
    public AttachmentValidator(Path helper, Path readelf, Path llvm, Path strict, Path configuration) throws IOException {
        var selected = new LinkedHashMap<String, Path>();
        selected.put("validatorHelper", helper);
        selected.put("gnuReadelf", readelf);
        selected.put("llvmDwarfdump", llvm);
        selected.put("strictDwarfdump", strict);
        selected.put("strictConfiguration", configuration);
        var resolved = new LinkedHashMap<String, Path>();
        for (var entry : selected.entrySet()) resolved.put(entry.getKey(), Objects.requireNonNull(entry.getValue()).toRealPath());
        tools = Map.copyOf(resolved);
    }

    @Override
    public void validate(AttachmentExportBinding binding, Path selectedEvidence, AttachmentOperation.Host host,
            BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var selections = new ArrayList<AttachmentPaths.Selection>();
        for (var entry : binding.files().entrySet()) {
            selections.add(new AttachmentPaths.Selection(entry.getKey(), entry.getValue().path(), AttachmentPaths.Kind.INPUT));
        }
        for (var entry : tools.entrySet()) selections.add(new AttachmentPaths.Selection(entry.getKey(), entry.getValue(), AttachmentPaths.Kind.INPUT));
        selections.add(new AttachmentPaths.Selection("validationEvidence", selectedEvidence, AttachmentPaths.Kind.NEW_FILE));
        var plan = AttachmentPaths.preflight(selections);
        Path evidence = plan.paths().get("validationEvidence");
        var toolFiles = new LinkedHashMap<String, AttachmentFileStore.Snapshot>();
        for (var entry : tools.entrySet()) toolFiles.put(entry.getKey(), AttachmentFileStore.observe(entry.getValue(), host, cancelled));
        StrictDwarfCheck.requireConfiguration(toolFiles.get("strictConfiguration"));
        binding.recheck(host, cancelled);
        String parentIdentity = host.directoryIdentity(evidence.getParent());
        Path workspace = Files.createTempDirectory(evidence.getParent(), ".forge-attachment-validation-");
        try {
            String workspaceIdentity = host.directoryIdentity(workspace);
            var supervisor = new ValidatorSupervisor(tools.get("validatorHelper"));
            var runs = new LinkedHashMap<String, ValidatorSupervisor.Evidence>();
            var versions = Map.of("gnuReadelf", "(?m)^GNU readelf ", "llvmDwarfdump", "(?m)^.*LLVM version [0-9]+\\.",
                "strictDwarfdump", "libdwarf 2\\.3\\.2 dwarfdump 2\\.3\\.2");
            for (String role : List.of("gnuReadelf", "llvmDwarfdump", "strictDwarfdump")) {
                var run = execute(supervisor, tools.get(role), List.of("--version"), workspace, cancelled);
                require(Pattern.compile(versions.get(role)).matcher(read(run)).find(), "unrecognized validator version: " + role);
                runs.put(role + "Version", run);
            }
            Path sidecar = binding.files().get("sidecar").path();
            var gnu = execute(supervisor, tools.get("gnuReadelf"), List.of("--wide", "-h", "-S", "-n",
                "--debug-dump=no-follow-links", "--debug-dump=info,abbrev,aranges,decodedline,loc,Ranges",
                "--", sidecar.toString()), workspace, cancelled);
            String gnuText = read(gnu);
            for (String header : List.of("ELF Header:", "Section Headers:", "Contents of the .debug_info section:",
                    "Contents of the .debug_abbrev section:", "Contents of the .debug_line section:")) {
                require(gnuText.contains(header), "GNU readelf report is missing " + header);
            }
            runs.put("gnuReadelf", gnu);
            var llvm = execute(supervisor, tools.get("llvmDwarfdump"), List.of("--verify", sidecar.toString()), workspace, cancelled);
            String llvmText = read(llvm);
            require(llvmText.contains("Verifying .debug_info Unit Header Chain...") &&
                llvmText.contains("Verifying unit:") && llvmSuccess(llvmText),
                "LLVM report lacks complete successful unit verification");
            runs.put("llvmDwarfdump", llvm);
            var strict = StrictDwarfCheck.run(binding, host, supervisor, tools.get("strictDwarfdump"),
                tools.get("strictConfiguration"), workspace, cancelled);
            runs.put("strictSidecar", strict.sidecar());
            if (strict.original() != null) runs.put("strictOriginal", strict.original());
            if (strict.originalView() != null) {
                Path view = strict.originalView().path();
                var frameGnu = execute(supervisor, tools.get("gnuReadelf"), List.of("--wide", "-h", "-S", "-l",
                    "--debug-dump=no-follow-links", "--debug-dump=frames", "--", view.toString()), workspace, cancelled);
                require(read(frameGnu).contains("Contents of the .eh_frame section:"), "original-frame GNU report is incomplete");
                runs.put("originalFrameViewGnu", frameGnu);
                var frameLlvm = execute(supervisor, tools.get("llvmDwarfdump"), List.of("--verify", view.toString()), workspace, cancelled);
                require(llvmSuccess(read(frameLlvm)), "original-frame LLVM verification failed");
                runs.put("originalFrameViewLlvm", frameLlvm);
                AttachmentFileStore.unchanged(strict.originalView(), host, cancelled);
            }
            binding.recheck(host, cancelled);
            for (var file : toolFiles.values()) AttachmentFileStore.unchanged(file, host, cancelled);
            plan.recheck();
            require(parentIdentity.equals(host.directoryIdentity(evidence.getParent())) &&
                workspaceIdentity.equals(host.directoryIdentity(workspace)), "validation directory identity changed");

            var record = new JsonObject();
            record.addProperty("schemaVersion", 1);
            record.addProperty("policy", "gnu-llvm-libdwarf-2.3.2-v1");
            record.addProperty("status", "PASS");
            record.addProperty("hostContract", host.contract());
            record.addProperty("exportStatus", binding.claims().status().name());
            record.addProperty("exportValidationStatus", binding.claims().validationStatus().name());
            record.addProperty("deadlineMillisPerProcess", DEADLINE.toMillis());
            record.addProperty("streamByteLimit", OUTPUT_LIMIT);
            record.add("inputs", artifacts(binding.files()));
            record.add("tools", artifacts(toolFiles));
            var checkedRuns = new JsonObject();
            var rawFiles = new ArrayList<AttachmentFileStore.Snapshot>();
            if (strict.originalView() != null) {
                rawFiles.add(strict.originalView());
                record.add("originalFrameView", artifacts(Map.of("image", strict.originalView())).get("image"));
            }
            for (var entry : runs.entrySet()) {
                checkedRuns.add(entry.getKey(), retain(entry.getValue(), toolFiles, host, cancelled, rawFiles));
            }
            record.add("checks", checkedRuns);
            var diagnostics = new JsonArray();
            strict.corroboratedDiagnostics().forEach(diagnostics::add);
            record.add("corroboratedFrameDiagnostics", diagnostics);
            if (strict.inheritedFrame() != null) {
                var frame = new JsonObject();
                frame.addProperty("address", strict.inheritedFrame().address());
                frame.addProperty("bytes", strict.inheritedFrame().bytes());
                frame.addProperty("sha256", strict.inheritedFrame().sha256());
                frame.addProperty("originalOffset", strict.inheritedFrame().originalOffset());
                frame.addProperty("fromProgramHeaders", strict.inheritedFrame().fromProgramHeaders());
                record.add("inheritedFrame", frame);
            }
            byte[] bytes = (record + "\n").getBytes(StandardCharsets.UTF_8);
            require(bytes.length <= 1024 * 1024, "combined validation evidence exceeds 1 MiB");
            Path stage = workspace.resolve("complete-evidence.json");
            try (var output = FileChannel.open(stage, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                var buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    check(cancelled);
                    require(output.write(buffer) > 0, "validation evidence write made no progress");
                }
                output.force(true);
            }
            var staged = AttachmentFileStore.observe(stage, host, cancelled);
            host.syncDirectory(workspace);
            for (var file : rawFiles) AttachmentFileStore.unchanged(file, host, cancelled);
            for (var file : toolFiles.values()) AttachmentFileStore.unchanged(file, host, cancelled);
            binding.recheck(host, cancelled);
            plan.recheck();
            require(parentIdentity.equals(host.directoryIdentity(evidence.getParent())) &&
                workspaceIdentity.equals(host.directoryIdentity(workspace)), "validation directory changed before publication");
            // The file store exclusively publishes an independent, forced and
            // verified copy. It never overwrites an existing success record.
            AttachmentFileStore.backup(staged, evidence, host, cancelled);
            binding.recheck(host, cancelled);
        }
        catch (IOException failure) {
            throw new IOException("attachment validation failed; retain evidence workspace " + workspace + ": " +
                failure.getMessage(), failure);
        }
        catch (CancellationException cancelledRun) {
            var retained = new CancellationException("attachment validation cancelled; retained workspace " + workspace);
            retained.initCause(cancelledRun);
            throw retained;
        }
    }

    private static boolean llvmSuccess(String report) {
        return report.stripTrailing().endsWith("\nNo errors.") &&
            Pattern.compile("(?m)^No errors\\.$").matcher(report).results().count() == 1 &&
            !Pattern.compile("(?im)^\\s*(?:warning|error|fatal(?: error)?):").matcher(report).find();
    }

    private static ValidatorSupervisor.Evidence execute(ValidatorSupervisor supervisor, Path tool, List<String> arguments,
            Path workspace, BooleanSupplier cancelled) throws IOException {
        var result = supervisor.run(tool, arguments, workspace, DEADLINE, OUTPUT_LIMIT, cancelled);
        require(result.stderrDigest().byteCount() == 0, "validator wrote unexplained stderr: " + result.directory());
        return result;
    }

    private static String read(ValidatorSupervisor.Evidence evidence) throws IOException {
        byte[] bytes;
        try (var input = Files.newInputStream(evidence.stdout(), LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(OUTPUT_LIMIT + 1);
        }
        require(bytes.length <= OUTPUT_LIMIT, "validator output exceeds bound");
        return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
    }

    private static JsonObject retain(ValidatorSupervisor.Evidence run, Map<String, AttachmentFileStore.Snapshot> tools,
            AttachmentOperation.Host host, BooleanSupplier cancelled, List<AttachmentFileStore.Snapshot> rawFiles)
            throws IOException {
        require(run.helperSha256().equals(tools.get("validatorHelper").digest().sha256()), "supervisor changed between checks");
        require(tools.values().stream().anyMatch(file -> file.path().equals(run.tool()) &&
            file.digest().sha256().equals(run.toolSha256())), "validator changed between checks");
        require(ValidatorSupervisor.readStatus(run.directory().resolve("status.json")).equals(run.status()),
            "supervisor status changed after execution");
        var logs = new LinkedHashMap<String, AttachmentFileStore.Snapshot>();
        for (String name : List.of("tool.stdout", "tool.stderr", "status.json", "supervisor.stdout", "supervisor.stderr")) {
            Path path = run.directory().resolve(name);
            try (var file = FileChannel.open(path, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) { file.force(true); }
            var snapshot = AttachmentFileStore.observe(path, host, cancelled);
            if (name.equals("tool.stdout")) require(snapshot.digest().equals(run.stdoutDigest()), "validator stdout changed");
            else if (name.equals("tool.stderr")) require(snapshot.digest().equals(run.stderrDigest()), "validator stderr changed");
            else if (name.startsWith("supervisor.")) require(snapshot.digest().byteCount() == 0, "supervisor emitted diagnostics");
            logs.put(name, snapshot);
            rawFiles.add(snapshot);
        }
        host.syncDirectory(run.directory());
        var result = new JsonObject();
        var command = new JsonArray();
        run.command().forEach(command::add);
        result.add("command", command);
        result.addProperty("toolSha256", run.toolSha256());
        result.addProperty("helperSha256", run.helperSha256());
        result.addProperty("reason", run.status().reason());
        result.addProperty("exitCode", run.status().exitCode());
        result.addProperty("cleanupComplete", run.status().cleanupComplete());
        result.add("logs", artifacts(logs));
        return result;
    }

    private static JsonObject artifacts(Map<String, AttachmentFileStore.Snapshot> files) {
        var result = new JsonObject();
        for (var entry : files.entrySet()) {
            var file = entry.getValue();
            var value = new JsonObject();
            value.addProperty("path", file.path().toString());
            value.addProperty("sha256", file.digest().sha256());
            value.addProperty("bytes", file.digest().byteCount());
            value.addProperty("crc32", file.digest().gnuDebuglinkCrc32());
            value.addProperty("identity", file.fingerprint().identity());
            value.addProperty("metadataSha256", file.fingerprint().metadataSha256());
            result.add(entry.getKey(), value);
        }
        return result;
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("attachment validation cancelled");
    }

    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }
}
