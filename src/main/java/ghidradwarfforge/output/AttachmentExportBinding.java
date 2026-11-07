package ghidradwarfforge.output;

import ghidradwarfforge.elf.ElfBuildId;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.MatchedElfAllocations;
import ghidradwarfforge.elf.MatchedElfPrefix;
import ghidradwarfforge.elf.SyntheticSourceSidecar;
import ghidradwarfforge.nativeapi.DwarfTarget;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Read-only preparation binding between an actual exported ELF pair and its
 * completed report. The original is the unmodified input (the retained original
 * backup for refresh), never the currently attached image. Report paths remain
 * opaque; only explicitly selected paths are accessed. PARTIAL and NOT_RUN keep
 * their meanings. This does not validate DWARF, approve attachment, prove source
 * lookup, or replace the transaction's all-role preflight and fresh validators.
 *
 * Host identities and complete SHA/size/CRC observations bracket the ELF/report
 * checks. Later use must recheck the binding. These observations detect ordinary
 * changes, not adversarial change-and-restore races or an immutable snapshot.
 */
public final class AttachmentExportBinding {
    private final AttachmentPaths.Plan paths;
    private final String hostContract;
    private final Map<String, AttachmentFileStore.Snapshot> files;
    private final ExportReportClaims claims;
    private final List<AttachmentFileStore.Snapshot> sourceDependencies;

    private AttachmentExportBinding(AttachmentPaths.Plan paths, String hostContract,
            Map<String, AttachmentFileStore.Snapshot> files, ExportReportClaims claims,
            List<AttachmentFileStore.Snapshot> sourceDependencies) {
        this.paths = paths;
        this.hostContract = hostContract;
        this.files = Map.copyOf(files);
        this.claims = claims;
        this.sourceDependencies = List.copyOf(sourceDependencies);
    }

    public Map<String, AttachmentFileStore.Snapshot> files() { return files; }
    public ExportReportClaims claims() { return claims; }
    /** Manifest and all parts, in bundle order; the index remains the source artifact. */
    public List<AttachmentFileStore.Snapshot> sourceDependencies() { return sourceDependencies; }

    public static AttachmentExportBinding observe(Path report, Path original, Path sidecar,
            Path source, AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(cancelled, "cancelled");
        check(cancelled);
        var paths = AttachmentPaths.preflight(List.of(
            new AttachmentPaths.Selection("exportReport", report, AttachmentPaths.Kind.INPUT),
            new AttachmentPaths.Selection("exportOriginal", original, AttachmentPaths.Kind.INPUT),
            new AttachmentPaths.Selection("sidecar", sidecar, AttachmentPaths.Kind.INPUT),
            new AttachmentPaths.Selection("source", source, AttachmentPaths.Kind.INPUT)));
        Map<String, AttachmentFileStore.Snapshot> files = new HashMap<>();
        for (var entry : paths.paths().entrySet()) {
            files.put(entry.getKey(), AttachmentFileStore.observe(entry.getValue(), host, cancelled));
        }
        Path input = paths.paths().get("exportOriginal");
        Path output = paths.paths().get("sidecar");
        var observed = ExportArtifactHashBinding.observe(paths.paths().get("exportReport"),
            input, output, paths.paths().get("source"), cancelled);
        var roles = Map.of("exportOriginal", observed.original(), "sidecar", observed.sidecar(),
            "source", observed.source());
        for (var entry : roles.entrySet()) {
            if (entry.getValue().agreement() != ExportArtifactHashBinding.Agreement.MATCHING_REPORTED_SHA256 ||
                    !entry.getValue().observed().equals(files.get(entry.getKey()).digest())) {
                throw new IOException("attachment export bytes disagree with report or initial observation: " + entry.getKey());
            }
        }
        var prefix = MatchedElfPrefix.compare(input, output, cancelled);
        if (prefix.status() != MatchedElfPrefix.Status.MATCHING_COPIED_PREFIX) {
            throw new IOException("attachment sidecar copied prefix differs: " + prefix);
        }
        var allocations = MatchedElfAllocations.compare(input, output, cancelled);
        if (allocations.status() != MatchedElfAllocations.Status.MATCHING_ALLOCATED_METADATA) {
            throw new IOException("attachment sidecar allocated metadata differs: " + allocations);
        }
        var identity = ElfBuildId.compare(ElfBuildId.read(input, cancelled), ElfBuildId.read(output, cancelled));
        if (identity != ElfBuildId.Relationship.SAME_BUILD_ID && identity != ElfBuildId.Relationship.ABSENT_BOTH) {
            throw new IOException("attachment sidecar build identity differs: " + identity);
        }
        check(cancelled);
        try {
            var image = ElfImage.read(input);
            var target = DwarfTarget.fromElf(image);
            var actual = new ExportReport.TargetInfo(target.name(), target.addressBytes() * 8,
                image.byteOrder().toString());
            if (!actual.equals(observed.claims().target())) {
                throw new IOException("attachment export report target differs from original ELF");
            }
        }
        catch (IllegalArgumentException invalid) {
            throw new IOException("unsupported attachment export ELF target", invalid);
        }
        var dependencies = new ArrayList<AttachmentFileStore.Snapshot>();
        var bundle = SourceBundleFiles.open(paths.paths().get("source"), cancelled).orElse(null);
        if (bundle != null) {
            if (!bundle.manifest().inputSha256().equals(files.get("exportOriginal").digest().sha256())) {
                throw new IOException("source bundle input differs from the selected original ELF");
            }
            String directory = paths.paths().get("source").getParent().toString();
            if (java.io.File.separatorChar == '\\') directory = directory.replace('\\', '/');
            bundle.requireSourceNames(SyntheticSourceSidecar.prepare(output, directory, cancelled).sourceFiles());
            for (Path dependency : bundle.files().subList(1, bundle.files().size())) {
                dependencies.add(AttachmentFileStore.observe(dependency, host, cancelled));
            }
            // Bind the host snapshots to the inventory just read, even if a
            // source part changed between semantic verification and observation.
            bundle.verify(cancelled);
        }
        var result = new AttachmentExportBinding(paths, host.contract(), files, observed.claims(), dependencies);
        result.recheck(host, cancelled);
        return result;
    }

    public void recheck(AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        if (!hostContract.equals(host.contract())) throw new IOException("attachment export host contract changed");
        paths.recheck();
        for (var file : files.values()) AttachmentFileStore.unchanged(file, host, cancelled);
        for (var file : sourceDependencies) AttachmentFileStore.unchanged(file, host, cancelled);
        paths.recheck();
        check(cancelled);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("attachment export binding cancelled");
    }
}
