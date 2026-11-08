package ghidradwarfforge.output;

import ghidradwarfforge.elf.DebuglinkCandidateContent;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ExecutableProgramBytes;
import ghidradwarfforge.elf.OwnedDebuglinkCandidate;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Complete preparation/commit sequence for an explicitly requested attachment.
 * Host metadata/namespace operations and a live validator are mandatory; there
 * is no permissive default or public UI entry point. Refresh consumes a fresh
 * export made against the retained original backup. This class never changes a
 * Ghidra program's imported hash or rewrites the previous source/sidecar pair.
 */
public final class AttachmentOperation {
    public interface Host extends AttachmentTargetStore.Host {
        /** Return the basename's verified native consumer encoding, or reject it. */
        byte[] debuglinkBasename(Path sidecar) throws IOException;
    }

    @FunctionalInterface
    public interface Validator {
        /**
         * Perform fresh validation against this exact binding, retaining bounded
         * tool/output evidence. Exclusively publish a complete evidence file at
         * the selected destination only on success. Logs/stages must be in an
         * exclusively owned directory and never follow report-supplied paths.
         * Return only after processes/resources are released; throw on failure
         * or cancellation. A JSON success claim is not an implementation.
         */
        void validate(AttachmentExportBinding binding, Path evidence, Host host,
            BooleanSupplier cancelled) throws IOException;
    }

    public record Refresh(Path previousReceipt, Path previousSidecar,
            Path previousSource, Path priorTargetBackup) {
        public Refresh {
            Objects.requireNonNull(previousReceipt);
            Objects.requireNonNull(previousSidecar);
            Objects.requireNonNull(previousSource);
            Objects.requireNonNull(priorTargetBackup);
        }
    }

    public record Request(Path target, Path sidecar, Path source, Path exportReport,
            Path originalBackup, Path validationEvidence, Path receipt,
            Path recoveryReceipt, Path restoreImage, Refresh refresh) {
        public Request {
            Objects.requireNonNull(target);
            Objects.requireNonNull(sidecar);
            Objects.requireNonNull(source);
            Objects.requireNonNull(exportReport);
            Objects.requireNonNull(originalBackup);
            Objects.requireNonNull(validationEvidence);
            Objects.requireNonNull(receipt);
            Objects.requireNonNull(recoveryReceipt);
            Objects.requireNonNull(restoreImage);
        }
    }

    public record Result(AttachmentTransaction.Result transaction,
            AttachmentTransaction.Request recoveryRequest, Map<String, Path> selected) {
        public Result { selected = Map.copyOf(selected); }
    }

    /** No target replacement has occurred when this preparation exception is thrown. */
    public static final class PreparationFailure extends IOException {
        private final Map<String, Path> selected;
        private final boolean cancelled;
        private PreparationFailure(Map<String, Path> selected, Throwable failure) {
            super("attachment preparation failed; retain selected evidence/backups/stages: " + selected, failure);
            this.selected = Map.copyOf(selected);
            cancelled = failure instanceof CancellationException;
        }
        public Map<String, Path> selected() { return selected; }
        public boolean cancelled() { return cancelled; }
    }

    private AttachmentOperation() { }

    /** Read-only all-role preflight, also required before a host creates a visibility workspace. */
    public static AttachmentPaths.Plan preflightPaths(Request request) throws IOException {
        return preflightPaths(request, false);
    }

    /** Before a GUI export, require a fresh pair/report instead of existing inputs. */
    static AttachmentPaths.Plan preflightExportPaths(Request request) throws IOException {
        return preflightPaths(request, true);
    }

    private static AttachmentPaths.Plan preflightPaths(Request request, boolean beforeExport) throws IOException {
        boolean refresh = request.refresh() != null;
        var selections = new ArrayList<AttachmentPaths.Selection>();
        select(selections, "targetBefore", request.target(), AttachmentPaths.Kind.TARGET);
        var exportKind = beforeExport ? AttachmentPaths.Kind.NEW_FILE : AttachmentPaths.Kind.INPUT;
        select(selections, "sidecar", request.sidecar(), exportKind);
        select(selections, "source", request.source(), exportKind);
        select(selections, "exportReport", request.exportReport(), exportKind);
        select(selections, "originalBackup", request.originalBackup(), refresh ? AttachmentPaths.Kind.INPUT : AttachmentPaths.Kind.NEW_FILE);
        select(selections, "validationEvidence", request.validationEvidence(), AttachmentPaths.Kind.NEW_FILE);
        select(selections, "receipt", request.receipt(), AttachmentPaths.Kind.NEW_FILE);
        select(selections, "recoveryReceipt", request.recoveryReceipt(), AttachmentPaths.Kind.NEW_FILE);
        select(selections, "restoreImage", request.restoreImage(), AttachmentPaths.Kind.NEW_FILE);
        if (refresh) {
            select(selections, "previousReceipt", request.refresh().previousReceipt(), AttachmentPaths.Kind.INPUT);
            select(selections, "previousSidecar", request.refresh().previousSidecar(), AttachmentPaths.Kind.INPUT);
            select(selections, "previousSource", request.refresh().previousSource(), AttachmentPaths.Kind.INPUT);
            select(selections, "priorTargetBackup", request.refresh().priorTargetBackup(), AttachmentPaths.Kind.NEW_FILE);
        }
        var plan = AttachmentPaths.preflight(selections);
        Map<String, Path> paths = new HashMap<>(plan.paths());
        Path target = paths.get("targetBefore");
        Path parent = target.getParent();
        Path sidecar = paths.get("sidecar");
        if (!sidecar.getParent().equals(parent) && !sidecar.getParent().equals(parent.resolve(".debug"))) {
            throw new IOException("attachment sidecar must be beside the target or in its .debug directory");
        }
        if (sidecar.getParent().equals(parent.resolve(".debug"))) {
            select(selections, "discoveryShadow", parent.resolve(sidecar.getFileName()), AttachmentPaths.Kind.NEW_FILE);
            plan = AttachmentPaths.preflight(selections);
        }
        return plan;
    }

    public static Result execute(Request request, Host host, Validator validator,
            BooleanSupplier cancelled) throws IOException {
        return execute(request, host, validator, cancelled, boundary -> { });
    }

    @FunctionalInterface interface PreparedObserver {
        void prepared(AttachmentTransaction.Request request) throws IOException;
    }

    static Result execute(Request request, Host host, Validator validator,
            BooleanSupplier cancelled, AttachmentTransaction.Hook hook) throws IOException {
        return execute(request, host, validator, cancelled, hook, prepared -> { });
    }

    static Result execute(Request request, Host host, Validator validator,
            BooleanSupplier cancelled, AttachmentTransaction.Hook hook, PreparedObserver observer) throws IOException {
        Objects.requireNonNull(host);
        Objects.requireNonNull(validator);
        Objects.requireNonNull(cancelled);
        check(cancelled);
        boolean refresh = request.refresh() != null;
        var plan = preflightPaths(request);
        var selections = plan.selections();
        Map<String, Path> paths = new HashMap<>(plan.paths());
        Path target = paths.get("targetBefore");
        Path parent = target.getParent();
        Path sidecar = paths.get("sidecar");
        Map<Path, String> parents = new HashMap<>();
        Map<String, AttachmentFileStore.Snapshot> snapshots = new HashMap<>();
        for (var selected : selections) {
            Path path = paths.get(selected.role());
            parents.put(path.getParent(), host.directoryIdentity(path.getParent()));
            if (selected.kind() != AttachmentPaths.Kind.NEW_FILE) {
                snapshots.put(selected.role(), AttachmentFileStore.observe(path, host, cancelled));
            }
        }
        Path exportOriginal = refresh ? paths.get("originalBackup") : target;
        var binding = AttachmentExportBinding.observe(paths.get("exportReport"), exportOriginal,
            sidecar, paths.get("source"), host, cancelled);
        // Source relocation needs an explicit source-map operation. Attachment
        // does not silently make a selected file satisfy a different recorded path.
        if (!binding.claims().artifacts().sourcePath().equals(paths.get("source").toString())) {
            throw new IOException("selected source differs from the export's recorded source path");
        }
        byte[] basename = host.debuglinkBasename(sidecar);
        if (refresh) verifyPrevious(paths, snapshots, host, cancelled);
        else if (ElfImage.read(target).sections().stream().anyMatch(section -> section.name().equals(".gnu_debuglink"))) {
            throw new IOException("initial attachment cannot replace an existing association; select an explicit verified refresh");
        }
        recheck(paths, snapshots, parents, host, cancelled);
        AttachmentTransaction.Request prepared;
        try {
            validator.validate(binding, paths.get("validationEvidence"), host, cancelled);
            binding.recheck(host, cancelled);
            snapshots.put("validationEvidence", AttachmentFileStore.observe(paths.get("validationEvidence"), host, cancelled));
            recheck(paths, snapshots, parents, host, cancelled);
            String backupRole = refresh ? "priorTargetBackup" : "originalBackup";
            snapshots.put(backupRole, AttachmentFileStore.backup(snapshots.get("targetBefore"),
                paths.get(backupRole), host, cancelled));
            recheck(paths, snapshots, parents, host, cancelled);
            // Initial uses the new independent backup; refresh always builds
            // from the retained original, never from an already attached image.
            var candidate = OwnedDebuglinkCandidate.create(paths.get("originalBackup"), sidecar, basename, parent, cancelled);
            paths.put("targetAfter", candidate.candidate());
            parents.put(candidate.directory(), host.directoryIdentity(candidate.directory()));
            try (var output = FileChannel.open(candidate.candidate(), StandardOpenOption.WRITE)) {
                var before = snapshots.get("targetBefore");
                host.preserveMetadata(target, before.fingerprint(), candidate.candidate());
                output.force(true);
            }
            host.syncDirectory(candidate.directory());
            snapshots.put("targetAfter", AttachmentFileStore.observe(candidate.candidate(), host, cancelled));
            binding.recheck(host, cancelled);
            recheck(paths, snapshots, parents, host, cancelled);
            var claims = new HashMap<String, AttachmentReceipt.Artifact>();
            var files = new HashMap<String, Path>();
            for (var entry : snapshots.entrySet()) {
                var artifact = entry.getValue().artifact();
                if (entry.getKey().equals("targetAfter")) {
                    artifact = new AttachmentReceipt.Artifact(target.toString(), artifact.sha256(), artifact.bytes(),
                        artifact.identity(), artifact.metadataSha256());
                }
                claims.put(entry.getKey(), artifact);
                files.put(entry.getKey(), entry.getValue().path());
            }
            var receipt = new AttachmentReceipt(UUID.randomUUID().toString(), refresh ? AttachmentReceipt.Mode.REFRESH :
                AttachmentReceipt.Mode.INITIAL, AttachmentReceipt.Phase.PREPARED, paths.get("receipt").toString(),
                "owned-append-v1", host.contract(), host.durability(), snapshots.get("sidecar").digest().gnuDebuglinkCrc32(),
                claims, null);
            prepared = new AttachmentTransaction.Request(receipt, files, paths.get("receipt"),
                paths.get("recoveryReceipt"), paths.get("restoreImage"));
        }
        catch (IOException | RuntimeException failure) {
            throw new PreparationFailure(paths, failure);
        }
        try {
            observer.prepared(prepared);
            var result = AttachmentTransaction.commit(prepared, host, cancelled, hook, AttachmentTransaction.RECEIPTS);
            return new Result(result, prepared, paths);
        }
        catch (IOException | CancellationException beforePublication) {
            // The controller handles failures after PREPARED internally and
            // returns a reconciliation outcome. Its checked/cancellation exits
            // here precede publication; still report the already created files.
            throw new PreparationFailure(paths, beforePublication);
        }
    }

    private static void verifyPrevious(Map<String, Path> paths, Map<String, AttachmentFileStore.Snapshot> snapshots,
            Host host, BooleanSupplier cancelled) throws IOException {
        var previous = AttachmentReceiptStore.read(paths.get("previousReceipt"), host, cancelled).receipt();
        if (previous.phase() != AttachmentReceipt.Phase.COMMITTED || previous.recovery() != null ||
                !previous.hostContract().equals(host.contract()) || !previous.durability().equals(host.durability())) {
            throw new IOException("refresh requires a committed receipt under this host contract");
        }
        var expected = previous.files().get("targetAfter");
        var actual = snapshots.get("targetBefore").artifact();
        if (!expected.path().equals(actual.path()) || !expected.sha256().equals(actual.sha256()) ||
                expected.bytes() != actual.bytes() || !expected.metadataSha256().equals(actual.metadataSha256())) {
            throw new IOException("refresh current target differs from the previous attached image");
        }
        for (var entry : Map.of("originalBackup", "originalBackup", "previousSidecar", "sidecar", "previousSource", "source").entrySet()) {
            if (!snapshots.get(entry.getKey()).artifact().equals(previous.files().get(entry.getValue()))) {
                throw new IOException("refresh retained artifact differs: " + entry.getKey());
            }
        }
        var previousBundle = SourceBundleFiles.open(paths.get("previousSource"), cancelled).orElse(null);
        if (previousBundle != null) {
            if (!previousBundle.manifest().inputSha256().equals(snapshots.get("originalBackup").digest().sha256())) {
                throw new IOException("previous source bundle differs from the original backup");
            }
            previousBundle.verify(cancelled);
            AttachmentFileStore.unchanged(snapshots.get("previousSource"), host, cancelled);
        }
        if (paths.get("sidecar").getFileName().equals(paths.get("previousSidecar").getFileName()) ||
                paths.get("source").getFileName().equals(paths.get("previousSource").getFileName())) {
            throw new IOException("refresh requires a fresh source and sidecar basename");
        }
        var content = DebuglinkCandidateContent.observe(paths.get("originalBackup"), paths.get("targetBefore"),
            paths.get("previousSidecar"), host.debuglinkBasename(paths.get("previousSidecar")), cancelled);
        if (content.programBytes().status() != ExecutableProgramBytes.Status.MATCHING_PROGRAM_BYTES ||
                content.allocatedSections().status() != DebuglinkCandidateContent.AllocationStatus.MATCHING ||
                content.newDebuglink().status() != DebuglinkCandidateContent.DebuglinkStatus.MATCHING ||
                content.sidecarDigest().gnuDebuglinkCrc32() != previous.debuglinkCrc32()) {
            throw new IOException("refresh previous ELF/debuglink association differs from its verified receipt");
        }
    }

    private static void recheck(Map<String, Path> paths, Map<String, AttachmentFileStore.Snapshot> snapshots,
            Map<Path, String> parents, Host host, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        for (var parent : parents.entrySet()) {
            if (!parent.getValue().equals(host.directoryIdentity(parent.getKey()))) {
                throw new IOException("attachment output parent identity changed: " + parent.getKey());
            }
        }
        var selected = new ArrayList<AttachmentPaths.Selection>();
        for (var entry : paths.entrySet()) {
            var snapshot = snapshots.get(entry.getKey());
            if (snapshot != null) AttachmentFileStore.unchanged(snapshot, host, cancelled);
            select(selected, entry.getKey(), entry.getValue(), snapshot == null ? AttachmentPaths.Kind.NEW_FILE : AttachmentPaths.Kind.INPUT);
        }
        AttachmentPaths.preflight(selected).recheck();
        check(cancelled);
    }

    private static void select(ArrayList<AttachmentPaths.Selection> selections, String role, Path path, AttachmentPaths.Kind kind) {
        selections.add(new AttachmentPaths.Selection(role, path, kind));
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("attachment operation cancelled");
    }
}
