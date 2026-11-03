package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Unprivileged preparation of explicit selections; never modifies the executable. */
public final class AttachmentPreparation {
    public static final String EXPORT_REPORT_KEY = "GhidraDwarfForge.attachmentExportReport";

    public record Previous(Path originalBackup, Path receipt, Path sidecar, Path source) { }

    public static final class Plan {
        private final AttachmentInvocation invocation;
        private final Path exportInput;
        private final Path directory;
        private final Path request;
        private final AttachmentPaths.Plan beforeExport;
        private final AttachmentPaths.Plan inputs;

        private Plan(AttachmentInvocation invocation, Path exportInput, Path directory,
                Path request, AttachmentPaths.Plan beforeExport) throws IOException {
            this.invocation = invocation;
            this.exportInput = exportInput;
            this.directory = directory;
            this.request = request;
            this.beforeExport = beforeExport;
            this.inputs = AttachmentPaths.preflight(beforeExport.selections().stream()
                .filter(selected -> selected.kind() != AttachmentPaths.Kind.NEW_FILE).toList());
        }

        public Path exportInput() { return exportInput; }
        public Path sidecar() { return invocation.operation().sidecar(); }
        public Path directory() { return directory; }
        public Path request() { return request; }
        public AttachmentInvocation invocation() { return invocation; }

        public void recheckBeforeExport() throws IOException { beforeExport.recheck(); }

        /** Publish complete report/request files only after binding the completed export bytes. */
        public Path finish(String capturedReport, BooleanSupplier cancelled) throws Exception {
            check(cancelled);
            if (capturedReport == null || capturedReport.length() > 64 * 1024 * 1024) {
                throw new IOException("export did not provide a bounded completed report");
            }
            byte[] report = capturedReport.getBytes(StandardCharsets.UTF_8);
            if (report.length > 64 * 1024 * 1024) throw new IOException("export report exceeds 64 MiB");
            inputs.recheck();
            var selections = new ArrayList<AttachmentPaths.Selection>();
            for (var selected : beforeExport.selections()) {
                boolean exported = selected.role().equals("sidecar") || selected.role().equals("source");
                selections.add(new AttachmentPaths.Selection(selected.role(), selected.path(),
                    exported ? AttachmentPaths.Kind.INPUT : selected.kind()));
            }
            var publication = AttachmentPaths.preflight(selections);
            Path[] reportStage = new Path[1];
            ArtifactPairPublisher.stageAndPublishNew(invocation.operation().exportReport(), request,
                stage -> {
                    Files.write(stage, report);
                    reportStage[0] = stage;
                }, stage -> Files.writeString(stage, invocation.toJson(), StandardCharsets.UTF_8), () -> {
                    check(cancelled);
                    inputs.recheck();
                    publication.recheck();
                    var observed = ExportArtifactHashBinding.observe(reportStage[0], exportInput,
                        sidecar(), invocation.operation().source(), cancelled);
                    for (var artifact : List.of(observed.original(), observed.sidecar(), observed.source())) {
                        if (artifact.agreement() != ExportArtifactHashBinding.Agreement.MATCHING_REPORTED_SHA256) {
                            throw new IOException("captured export report does not match the selected completed files");
                        }
                    }
                    check(cancelled);
                });
            invocation.preflight(request).recheck();
            return request;
        }
    }

    private AttachmentPreparation() { }

    public static Plan begin(Path target, Path sidecar, Path recordsDirectory,
            Map<String, Path> validatorTools, Previous previous) throws IOException {
        Path records = recordsDirectory.toRealPath();
        if (!Files.isDirectory(records)) throw new IOException("select an existing directory for attachment records");
        Path directory = Files.createTempDirectory(records, "forge-attachment-").toRealPath();
        boolean returned = false;
        try {
            var refresh = previous == null ? null : new AttachmentOperation.Refresh(previous.receipt(),
                previous.sidecar(), previous.source(), directory.resolve("prior-target.backup"));
            Path originalBackup = previous == null ? directory.resolve("original.backup") : previous.originalBackup();
            var operation = new AttachmentOperation.Request(target, sidecar,
                sidecar.resolveSibling(sidecar.getFileName() + ".c"), directory.resolve("export.json"),
                originalBackup, directory.resolve("validation.json"), directory.resolve("receipt.json"),
                directory.resolve("recovery-receipt.json"), directory.resolve("restore-image"), refresh);
            var invocation = new AttachmentInvocation(operation, validatorTools, directory.resolve("recover.json"));
            Path request = directory.resolve("request.json");
            var selections = new ArrayList<>(AttachmentOperation.preflightExportPaths(operation).selections());
            selections.add(new AttachmentPaths.Selection("request", request, AttachmentPaths.Kind.NEW_FILE));
            selections.add(new AttachmentPaths.Selection("savedRecovery", invocation.recoveryInvocation(), AttachmentPaths.Kind.NEW_FILE));
            for (var entry : validatorTools.entrySet()) {
                selections.add(new AttachmentPaths.Selection("tool" + entry.getKey(), entry.getValue(), AttachmentPaths.Kind.INPUT));
            }
            var plan = new Plan(invocation, previous == null ? target : originalBackup, directory, request,
                AttachmentPaths.preflight(selections));
            returned = true;
            return plan;
        }
        finally {
            // Admission has written nothing inside this exclusively created
            // directory. Do not recursively delete a directory that gained files.
            if (!returned) Files.delete(directory);
        }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("attachment request preparation cancelled");
    }
}
