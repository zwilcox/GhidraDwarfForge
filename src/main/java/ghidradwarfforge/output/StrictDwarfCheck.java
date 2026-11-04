package ghidradwarfforge.output;

import ghidradwarfforge.elf.InheritedFrameBytes;
import ghidradwarfforge.elf.OriginalFrameView;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

/** Fresh pinned-checker component of attachment validation, not the complete validator policy. */
public final class StrictDwarfCheck {
    private static final String CONFIGURATION_SHA256 = "842bba9230de82059dfcef1485114cf3c33eae8be2973c649d176f4ad18972ef";
    private static final int OUTPUT_LIMIT = 32 * 1024 * 1024;

    public record Evidence(ValidatorSupervisor.Evidence sidecar, ValidatorSupervisor.Evidence original,
            ValidatorInput.Snapshot configuration, InheritedFrameBytes.Evidence inheritedFrame,
            List<String> corroboratedDiagnostics, AttachmentFileStore.Snapshot originalView) {
        public Evidence { corroboratedDiagnostics = List.copyOf(corroboratedDiagnostics); }
    }

    private StrictDwarfCheck() { }

    /**
     * Tool must be the selected raw 2.3.2 checker, not a shell launcher that
     * selects another configuration. Arguments and the explicit configuration
     * are fixed here. Tools are selected by the caller, never by report paths.
     * GNU/LLVM checks and complete evidence publication remain the surrounding
     * validator's responsibility, including independent checks of a private
     * original-frame view when sectionless corroboration needs one.
     */
    public static Evidence run(AttachmentExportBinding binding, AttachmentReceiptStore.Host host,
            ValidatorSupervisor supervisor, Path tool, Path configuration, Path evidenceParent,
            BooleanSupplier cancelled) throws IOException {
        binding.recheck(host, cancelled);
        var selections = new ArrayList<AttachmentPaths.Selection>();
        for (var entry : binding.files().entrySet()) {
            selections.add(new AttachmentPaths.Selection(entry.getKey(), entry.getValue().path(), AttachmentPaths.Kind.INPUT));
        }
        selections.add(new AttachmentPaths.Selection("strictTool", tool, AttachmentPaths.Kind.INPUT));
        selections.add(new AttachmentPaths.Selection("strictConfiguration", configuration, AttachmentPaths.Kind.INPUT));
        var plan = AttachmentPaths.preflight(selections);
        var config = ValidatorInput.observe(plan.paths().get("strictConfiguration"), cancelled);
        requireConfiguration(config);
        Path original = binding.files().get("exportOriginal").path();
        Path sidecar = binding.files().get("sidecar").path();
        Path selectedTool = plan.paths().get("strictTool");
        var checked = execute(supervisor, selectedTool, config.path(), sidecar, evidenceParent, cancelled);
        var sidecarReport = inspect(checked, false);
        ValidatorSupervisor.Evidence originalCheck = null;
        InheritedFrameBytes.Evidence frame = null;
        AttachmentFileStore.Snapshot originalView = null;
        if (!sidecarReport.frameDiagnostics().isEmpty()) {
            frame = InheritedFrameBytes.compare(original, sidecar, cancelled);
            Path checkOriginal = original;
            if (frame.fromProgramHeaders()) {
                checkOriginal = OriginalFrameView.create(original, evidenceParent, cancelled);
                originalView = AttachmentFileStore.observe(checkOriginal, host, cancelled);
                host.syncDirectory(checkOriginal.getParent());
                host.syncDirectory(evidenceParent);
            }
            originalCheck = execute(supervisor, selectedTool, config.path(), checkOriginal, evidenceParent, cancelled);
            var originalReport = inspect(originalCheck, true);
            if (!multiplicities(sidecarReport.frameDiagnostics()).equals(multiplicities(originalReport.frameDiagnostics()))) {
                throw new IOException("strict checker frame diagnostic identities/multiplicities differ from original; " +
                    "retained reports: " + checked.directory() + " and " + originalCheck.directory());
            }
            if (!checked.toolSha256().equals(originalCheck.toolSha256()) ||
                    !checked.helperSha256().equals(originalCheck.helperSha256())) {
                throw new IOException("strict checker/helper changed between artifact and original validation");
            }
        }
        binding.recheck(host, cancelled);
        ValidatorInput.unchanged(config, cancelled);
        plan.recheck();
        recheckLogs(checked, cancelled);
        if (originalCheck != null) recheckLogs(originalCheck, cancelled);
        if (originalView != null) AttachmentFileStore.unchanged(originalView, host, cancelled);
        return new Evidence(checked, originalCheck, config, frame, sidecarReport.frameDiagnostics(), originalView);
    }

    private static ValidatorSupervisor.Evidence execute(ValidatorSupervisor supervisor, Path tool, Path configuration,
            Path artifact, Path parent, BooleanSupplier cancelled) throws IOException {
        var result = supervisor.run(tool, List.of("--file-name=" + configuration, "--no-follow-debuglink",
            "-ka", "-ki", "-kd", artifact.toString()), parent, Duration.ofMinutes(2), OUTPUT_LIMIT, cancelled);
        if (result.stderrDigest().byteCount() != 0) {
            throw new IOException("strict checker wrote unexplained stderr; retained evidence: " + result.directory());
        }
        return result;
    }

    static void requireConfiguration(ValidatorInput.Snapshot config) throws IOException {
        if (!config.digest().sha256().equals(CONFIGURATION_SHA256)) {
            throw new IOException("strict checker configuration differs from pinned libdwarf 2.3.2");
        }
    }

    private static String read(ValidatorSupervisor.Evidence evidence) throws IOException {
        byte[] bytes;
        try (var input = Files.newInputStream(evidence.stdout(), LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(OUTPUT_LIMIT + 1);
        }
        if (bytes.length > OUTPUT_LIMIT) throw new IOException("strict checker report exceeds its bound");
        // The decoder's default REPORT policy refuses malformed UTF-8.
        return StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString();
    }

    private static StrictDwarfReport.Analysis inspect(ValidatorSupervisor.Evidence evidence, boolean original)
            throws IOException {
        try { return StrictDwarfReport.inspect(read(evidence), original); }
        catch (IOException invalid) {
            throw new IOException("strict checker report rejected; retained evidence: " + evidence.directory() +
                "; " + invalid.getMessage(), invalid);
        }
    }

    private static Map<String, Integer> multiplicities(List<String> diagnostics) {
        var counts = new HashMap<String, Integer>();
        for (String diagnostic : diagnostics) counts.merge(diagnostic, 1, Integer::sum);
        return counts;
    }

    private static void recheckLogs(ValidatorSupervisor.Evidence evidence, BooleanSupplier cancelled) throws IOException {
        if (!FileDigests.read(evidence.stdout(), cancelled).equals(evidence.stdoutDigest()) ||
                !FileDigests.read(evidence.stderr(), cancelled).equals(evidence.stderrDigest())) {
            throw new IOException("strict checker evidence changed after validation: " + evidence.directory());
        }
    }
}
