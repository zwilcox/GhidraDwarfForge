package ghidradwarfforge.output;

import ghidradwarfforge.elf.SyntheticSourceSidecar;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * Separates the reported export from a byte-proved source-relocated derivative.
 * The export report is never rewritten to certify different sidecar bytes.
 * This binding is not structural validation or installation authorization.
 */
public final class ArtifactValidationBinding {
    private final AttachmentExportBinding export;
    private final Map<String, AttachmentFileStore.Snapshot> files;
    private final AttachmentPaths.Plan paths;
    private final SyntheticSourceSidecar.Plan relocation;
    private final String hostContract;
    private final SourceBundleFiles sourceBundle;

    private ArtifactValidationBinding(AttachmentExportBinding export,
            Map<String, AttachmentFileStore.Snapshot> files, AttachmentPaths.Plan paths,
            SyntheticSourceSidecar.Plan relocation, String hostContract, SourceBundleFiles sourceBundle) {
        this.export = export;
        this.files = Map.copyOf(files);
        this.paths = paths;
        this.relocation = relocation;
        this.hostContract = hostContract;
        this.sourceBundle = sourceBundle;
    }

    public static ArtifactValidationBinding exported(AttachmentExportBinding export) {
        Objects.requireNonNull(export, "export binding");
        return new ArtifactValidationBinding(export, export.files(), null, null, null, null);
    }

    public static ArtifactValidationBinding relocated(AttachmentExportBinding export, Path sidecar, Path source,
            AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(export, "export binding");
        Objects.requireNonNull(host, "host");
        export.recheck(host, cancelled);
        var selections = new ArrayList<AttachmentPaths.Selection>();
        for (var entry : export.files().entrySet()) {
            selections.add(new AttachmentPaths.Selection(entry.getKey(), entry.getValue().path(), AttachmentPaths.Kind.INPUT));
        }
        selections.add(new AttachmentPaths.Selection("derivedSidecar", sidecar, AttachmentPaths.Kind.INPUT));
        selections.add(new AttachmentPaths.Selection("retainedSource", source, AttachmentPaths.Kind.INPUT));
        var paths = AttachmentPaths.preflight(selections);
        var candidate = AttachmentFileStore.observe(paths.paths().get("derivedSidecar"), host, cancelled);
        var retained = AttachmentFileStore.observe(paths.paths().get("retainedSource"), host, cancelled);
        if (!retained.digest().equals(export.files().get("source").digest())) {
            throw new IOException("retained source differs from reported source bytes");
        }
        String directory = retained.path().getParent().toString();
        if (java.io.File.separatorChar == '\\') directory = directory.replace('\\', '/');
        var plan = SyntheticSourceSidecar.prepare(export.files().get("sidecar").path(), directory, cancelled);
        if (!retained.path().getFileName().toString().equals(plan.fileName())) {
            throw new IOException("retained source basename differs from DWARF source name");
        }
        var sourceBundle = SourceBundleFiles.open(retained.path(), cancelled).orElse(null);
        if (sourceBundle != null) sourceBundle.requireSourceNames(plan.sourceFiles());
        else if (plan.sourceFiles().size() != 1) {
            throw new IOException("multi-file DWARF requires its complete source bundle");
        }
        plan.requireMatches(candidate.path(), cancelled);
        var selected = new LinkedHashMap<>(export.files());
        selected.put("sidecar", candidate);
        selected.put("source", retained);
        var result = new ArtifactValidationBinding(export, selected, paths, plan, host.contract(), sourceBundle);
        result.recheck(host, cancelled);
        return result;
    }

    public boolean derived() { return relocation != null; }
    public Map<String, AttachmentFileStore.Snapshot> files() { return files; }
    public Map<String, AttachmentFileStore.Snapshot> exportFiles() { return export.files(); }
    public ExportReportClaims claims() { return export.claims(); }

    public void recheck(AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException {
        export.recheck(host, cancelled);
        if (!derived()) return;
        if (!hostContract.equals(host.contract())) throw new IOException("derived artifact host contract changed");
        paths.recheck();
        AttachmentFileStore.unchanged(files.get("sidecar"), host, cancelled);
        AttachmentFileStore.unchanged(files.get("source"), host, cancelled);
        if (sourceBundle != null) sourceBundle.verify(cancelled);
        paths.recheck();
    }
}
