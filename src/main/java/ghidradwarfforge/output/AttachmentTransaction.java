package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Coordinates an already prepared/validated attachment's filesystem commit.
 * This is not a public attachment entry point or a DWARF validator. Preparation
 * must first validate the actual ELF/report/evidence, create and verify the
 * independent backup, construct the candidate and apply/flush host metadata.
 * Every path is explicitly selected by the caller, never followed from JSON.
 * Ordinary export does not invoke this controller.
 */
public final class AttachmentTransaction {
    public record Request(AttachmentReceipt prepared, Map<String, Path> files,
            Path receipt, Path recoveryReceipt, Path restoreImage) {
        public Request {
            Objects.requireNonNull(prepared, "prepared");
            files = Map.copyOf(files);
            Objects.requireNonNull(receipt, "receipt");
            Objects.requireNonNull(recoveryReceipt, "recovery receipt");
            Objects.requireNonNull(restoreImage, "restore image");
            if (prepared.phase() != AttachmentReceipt.Phase.PREPARED || prepared.recovery() != null ||
                    !files.keySet().equals(prepared.files().keySet())) {
                throw new IllegalArgumentException("transaction requires a normal PREPARED record and every explicit file role");
            }
        }
    }

    /** A non-COMMITTED result is a failed operation, even if its target was restored. */
    public record Result(AttachmentReceipt.Phase outcome, AttachmentReceiptStore.State receipt,
            AttachmentReceiptStore.State recoveryReceipt, AttachmentFileStore.Snapshot observedTarget,
            boolean cancelled, String diagnostic) { }

    enum Boundary { VERIFIED, PREPARED, TARGET_REPLACED, BEFORE_COMMIT, COMMITTED }
    @FunctionalInterface interface Hook {
        void at(Boundary boundary) throws IOException;
    }
    interface Receipts {
        AttachmentReceiptStore.State prepare(Path path, AttachmentReceipt receipt,
            AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException;
        AttachmentReceiptStore.State advance(AttachmentReceiptStore.State previous, AttachmentReceipt.Phase next,
            String diagnostic, AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException;
    }
    static final Receipts RECEIPTS = new Receipts() {
        public AttachmentReceiptStore.State prepare(Path path, AttachmentReceipt receipt,
                AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException {
            return AttachmentReceiptStore.prepare(path, receipt, host, cancelled);
        }
        public AttachmentReceiptStore.State advance(AttachmentReceiptStore.State previous, AttachmentReceipt.Phase next,
                String diagnostic, AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException {
            return AttachmentReceiptStore.advance(previous, next, diagnostic, host, cancelled);
        }
    };

    private record Plan(Request request, Map<String, AttachmentFileStore.Snapshot> snapshots,
            Path receipt, Path recovery, Path restore, String targetParentIdentity,
            Map<Path, String> outputParents) { }

    private AttachmentTransaction() { }

    public static Result commit(Request request, AttachmentTargetStore.Host host,
            BooleanSupplier cancelled) throws IOException {
        return commit(request, host, cancelled, boundary -> { }, RECEIPTS);
    }

    /**
     * Explicit rollback after interruption. The caller selects every path again
     * and supplies the original PREPARED claims; a current PREPARED or COMMITTED
     * record must agree with those claims. Missing/damaged new-generation inputs
     * do not prevent recovery of an independently verified prior image. No path
     * is inferred from the receipt. Existing committed records remain immutable.
     */
    public static Result recoverInterrupted(Request request, AttachmentTargetStore.Host host) throws IOException {
        var selected = new ArrayList<AttachmentPaths.Selection>();
        for (var entry : request.files().entrySet()) {
            boolean exists = Files.exists(entry.getValue(), LinkOption.NOFOLLOW_LINKS);
            selected.add(new AttachmentPaths.Selection(entry.getKey(), entry.getValue(),
                !exists ? AttachmentPaths.Kind.NEW_FILE : entry.getKey().equals("targetBefore") ?
                    AttachmentPaths.Kind.TARGET : AttachmentPaths.Kind.INPUT));
        }
        selected.add(new AttachmentPaths.Selection("receipt", request.receipt(), AttachmentPaths.Kind.INPUT));
        selected.add(new AttachmentPaths.Selection("recoveryReceipt", request.recoveryReceipt(), AttachmentPaths.Kind.NEW_FILE));
        selected.add(new AttachmentPaths.Selection("restoreImage", request.restoreImage(), AttachmentPaths.Kind.NEW_FILE));
        var paths = AttachmentPaths.preflight(selected);
        var record = AttachmentReceiptStore.read(paths.paths().get("receipt"), host, () -> false);
        if (!record.receipt().equals(request.prepared()) &&
                !record.receipt().equals(request.prepared().advance(AttachmentReceipt.Phase.COMMITTED, null))) {
            throw new IOException("interrupted receipt does not match the selected operation");
        }
        Map<String, AttachmentFileStore.Snapshot> snapshots = new HashMap<>();
        for (var entry : request.prepared().files().entrySet()) {
            Path selectedPath = paths.paths().get(entry.getKey());
            var artifact = entry.getValue();
            if (!entry.getKey().equals("targetAfter") && !selectedPath.toString().equals(artifact.path())) {
                throw new IOException("recovery path differs from the explicitly recorded role: " + entry.getKey());
            }
            // Only SHA/size and recorded identity/metadata identify the old/new
            // images here. A CRC is not reconstructed from an unauthenticated claim.
            snapshots.put(entry.getKey(), new AttachmentFileStore.Snapshot(selectedPath,
                new FileDigests.Result(artifact.sha256(), 0, artifact.bytes()),
                new AttachmentReceiptStore.Fingerprint(artifact.identity(), artifact.metadataSha256(), 1)));
        }
        String backupRole = request.prepared().mode() == AttachmentReceipt.Mode.INITIAL ? "originalBackup" : "priorTargetBackup";
        var required = new ArrayList<String>();
        required.add(backupRole);
        if (request.prepared().mode() == AttachmentReceipt.Mode.REFRESH) {
            required.addAll(java.util.List.of("originalBackup", "previousReceipt", "previousSidecar", "previousSource"));
        }
        for (String role : required) {
            var observed = AttachmentFileStore.observe(paths.paths().get(role), host, () -> false);
            if (!observed.artifact().equals(request.prepared().files().get(role))) {
                throw new IOException("recovery material changed: " + role);
            }
            snapshots.put(role, observed);
        }
        // The verified backup supplies the actual prior-image digest/CRC. Its
        // content must still agree with the separately recorded pre-operation image.
        var before = snapshots.get("targetBefore");
        var backup = snapshots.get(backupRole);
        if (!sameContent(before, backup)) throw new IOException("recovery backup does not contain the prior image");
        snapshots.put("targetBefore", new AttachmentFileStore.Snapshot(before.path(), backup.digest(), before.fingerprint()));
        if (request.prepared().mode() == AttachmentReceipt.Mode.REFRESH) verifyRefresh(request, snapshots, host, () -> false);
        paths.recheck();
        var outputs = outputParents(paths.paths(), host);
        var plan = new Plan(request, Map.copyOf(snapshots), paths.paths().get("receipt"),
            paths.paths().get("recoveryReceipt"), paths.paths().get("restoreImage"),
            host.directoryIdentity(before.path().getParent()), outputs);
        return recover(plan, host, RECEIPTS, new IOException("explicit recovery of interrupted attachment"), true, true);
    }

    static Result commit(Request request, AttachmentTargetStore.Host host, BooleanSupplier cancelled,
            Hook hook, Receipts receipts) throws IOException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(hook, "hook");
        Objects.requireNonNull(receipts, "receipts");
        // Preflight rejection cannot create a receipt, log or recovery image.
        Plan plan = verify(request, host, cancelled);
        hook.at(Boundary.VERIFIED);
        check(cancelled);
        AttachmentReceiptStore.State record = null;
        boolean replacementAttempted = false;
        try {
            checkOutputParent(plan, plan.receipt(), host);
            record = receipts.prepare(plan.receipt(), request.prepared(), host, cancelled);
            hook.at(Boundary.PREPARED);
            recheckAll(plan, host, cancelled);
            requireReceipt(record, host, cancelled);
            replacementAttempted = true;
            var installed = AttachmentTargetStore.replace(plan.snapshots().get("targetBefore"),
                plan.snapshots().get("targetAfter"), host, cancelled);
            hook.at(Boundary.TARGET_REPLACED);
            hook.at(Boundary.BEFORE_COMMIT);
            for (var entry : plan.snapshots().entrySet()) {
                if (!entry.getKey().equals("targetBefore") && !entry.getKey().equals("targetAfter")) {
                    AttachmentFileStore.unchanged(entry.getValue(), host, cancelled);
                }
            }
            check(cancelled);
            AttachmentFileStore.unchanged(installed, host, cancelled);
            requireReceipt(record, host, cancelled);
            record = receipts.advance(record, AttachmentReceipt.Phase.COMMITTED, null, host, () -> false);
            hook.at(Boundary.COMMITTED);
            return new Result(AttachmentReceipt.Phase.COMMITTED, record, null, installed, false, null);
        }
        catch (IOException | RuntimeException failure) {
            // Recovery must not be cancelled halfway through restoring an owned image.
            return recover(plan, host, receipts, failure, record != null || replacementAttempted, false);
        }
    }

    private static Plan verify(Request request, AttachmentTargetStore.Host host,
            BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var selected = new ArrayList<AttachmentPaths.Selection>();
        for (var entry : request.files().entrySet()) {
            selected.add(new AttachmentPaths.Selection(entry.getKey(), entry.getValue(),
                entry.getKey().equals("targetBefore") ? AttachmentPaths.Kind.TARGET : AttachmentPaths.Kind.INPUT));
        }
        selected.add(new AttachmentPaths.Selection("receipt", request.receipt(), AttachmentPaths.Kind.NEW_FILE));
        selected.add(new AttachmentPaths.Selection("recoveryReceipt", request.recoveryReceipt(), AttachmentPaths.Kind.NEW_FILE));
        selected.add(new AttachmentPaths.Selection("restoreImage", request.restoreImage(), AttachmentPaths.Kind.NEW_FILE));
        var paths = AttachmentPaths.preflight(selected);
        if (!paths.paths().get("receipt").toString().equals(request.prepared().receiptPath()) ||
                !host.contract().equals(request.prepared().hostContract()) ||
                !host.durability().equals(request.prepared().durability())) {
            throw new IOException("prepared attachment receipt path/host contract mismatch");
        }
        Map<String, AttachmentFileStore.Snapshot> snapshots = new HashMap<>();
        for (var entry : request.files().entrySet()) {
            var observed = AttachmentFileStore.observe(paths.paths().get(entry.getKey()), host, cancelled);
            var claimed = request.prepared().files().get(entry.getKey());
            // targetAfter describes the future final name; its explicit selected
            // file is the independently owned candidate, not the live target.
            var actual = observed.artifact();
            if (entry.getKey().equals("targetAfter")) {
                actual = new AttachmentReceipt.Artifact(request.prepared().files().get("targetBefore").path(),
                    actual.sha256(), actual.bytes(), actual.identity(), actual.metadataSha256());
            }
            if (!claimed.equals(actual)) throw new IOException("attachment file no longer matches receipt role: " + entry.getKey());
            snapshots.put(entry.getKey(), observed);
        }
        if (request.prepared().debuglinkCrc32() != snapshots.get("sidecar").digest().gnuDebuglinkCrc32()) {
            throw new IOException("prepared attachment CRC differs from selected sidecar");
        }
        if (request.prepared().mode() == AttachmentReceipt.Mode.REFRESH) verifyRefresh(request, snapshots, host, cancelled);
        paths.recheck();
        String parent = host.directoryIdentity(snapshots.get("targetBefore").path().getParent());
        return new Plan(request, Map.copyOf(snapshots), paths.paths().get("receipt"),
            paths.paths().get("recoveryReceipt"), paths.paths().get("restoreImage"), parent,
            outputParents(paths.paths(), host));
    }

    private static void verifyRefresh(Request request, Map<String, AttachmentFileStore.Snapshot> snapshots,
            AttachmentTargetStore.Host host, BooleanSupplier cancelled) throws IOException {
        var previous = AttachmentReceiptStore.read(snapshots.get("previousReceipt").path(), host, cancelled).receipt();
        var current = request.prepared();
        if (previous.phase() != AttachmentReceipt.Phase.COMMITTED || previous.recovery() != null ||
                previous.operationId().equals(current.operationId()) ||
                !sameClaimImage(previous.files().get("targetAfter"), current.files().get("targetBefore")) ||
                !previous.files().get("originalBackup").equals(current.files().get("originalBackup")) ||
                !previous.files().get("sidecar").equals(current.files().get("previousSidecar")) ||
                !previous.files().get("source").equals(current.files().get("previousSource")) ||
                previous.debuglinkCrc32() != snapshots.get("previousSidecar").digest().gnuDebuglinkCrc32()) {
            throw new IOException("refresh does not retain the verified previous association and original backup");
        }
    }

    private static void recheckAll(Plan plan, AttachmentTargetStore.Host host,
            BooleanSupplier cancelled) throws IOException {
        for (var snapshot : plan.snapshots().values()) AttachmentFileStore.unchanged(snapshot, host, cancelled);
        if (!plan.targetParentIdentity().equals(host.directoryIdentity(plan.snapshots().get("targetBefore").path().getParent()))) {
            throw new IOException("attachment target parent changed");
        }
    }

    private static Result recover(Plan plan, AttachmentTargetStore.Host host, Receipts receipts, Throwable failure,
            boolean preparationEstablished, boolean allowAlreadyRestored) {
        boolean cancelled = failure instanceof CancellationException;
        String reason = diagnostic(failure);
        AttachmentFileStore.Snapshot observed = null;
        AttachmentReceipt.Phase outcome = AttachmentReceipt.Phase.RECOVERY_REQUIRED;
        AttachmentReceiptStore.State record = null;
        AttachmentReceiptStore.State recovery = null;
        AttachmentReceipt recoveryClaims = null;
        AttachmentReceipt intendedRecovery = null;
        var before = plan.snapshots().get("targetBefore");
        var after = plan.snapshots().get("targetAfter");
        try {
            if (!plan.targetParentIdentity().equals(host.directoryIdentity(before.path().getParent()))) {
                throw new IOException("target parent changed; recovery will not write through it");
            }
            try {
                observed = AttachmentFileStore.observe(before.path(), host, () -> false);
            }
            catch (NoSuchFileException missing) {
                // Confirm leaf absence; a dangling link is never a missing target.
                if (Files.exists(before.path(), LinkOption.NOFOLLOW_LINKS)) throw missing;
            }
            if (observed != null && (sameImage(observed, before) || allowAlreadyRestored &&
                    observed.path().equals(before.path()) && sameContent(observed, before) &&
                    observed.fingerprint().metadataSha256().equals(before.fingerprint().metadataSha256()))) {
                outcome = AttachmentReceipt.Phase.ROLLED_BACK;
            }
            else if (observed == null || sameImage(observed, after)) {
                // A refresh may restore only its intact previous debug association.
                if (plan.request().prepared().mode() == AttachmentReceipt.Mode.REFRESH) {
                    for (String role : new String[] { "previousReceipt", "previousSidecar", "previousSource", "originalBackup" }) {
                        AttachmentFileStore.unchanged(plan.snapshots().get(role), host, () -> false);
                    }
                }
                var backup = plan.snapshots().get(plan.request().prepared().mode() == AttachmentReceipt.Mode.INITIAL ?
                    "originalBackup" : "priorTargetBackup");
                AttachmentFileStore.unchanged(backup, host, () -> false);
                if (observed == null) observed = AttachmentFileStore.backup(backup, before.path(), host, () -> false);
                else {
                    checkOutputParent(plan, plan.restore(), host);
                    observed = AttachmentTargetStore.restore(observed, backup, plan.restore(), host, () -> false);
                }
                if (!observed.path().equals(before.path()) || !observed.digest().equals(before.digest()) ||
                        !observed.fingerprint().metadataSha256().equals(before.fingerprint().metadataSha256())) {
                    throw new IOException("restored target failed original image/metadata verification");
                }
                outcome = AttachmentReceipt.Phase.ROLLED_BACK;
            }
            else {
                throw new IOException("target changed concurrently; recovery preserved it");
            }
        }
        catch (IOException | RuntimeException recoveryFailure) {
            reason = diagnostic(new IOException(reason + "; recovery: " + recoveryFailure));
            outcome = AttachmentReceipt.Phase.RECOVERY_REQUIRED;
            // Retain only a fresh observation, never label a stale pre-restore
            // snapshot as the current target after an uncertain native result.
            try { observed = AttachmentFileStore.observe(before.path(), host, () -> false); }
            catch (IOException | RuntimeException unavailable) { observed = null; }
        }
        try {
            var observedRecord = AttachmentReceiptStore.read(plan.receipt(), host, () -> false);
            var prepared = plan.request().prepared();
            if (!observedRecord.receipt().equals(prepared) &&
                    !observedRecord.receipt().equals(prepared.advance(AttachmentReceipt.Phase.COMMITTED, null))) {
                throw new IOException("operation receipt changed concurrently; it was preserved");
            }
            record = observedRecord;
            var originalRecord = AttachmentFileStore.observe(plan.receipt(), host, () -> false);
            if (!record.sha256().equals(originalRecord.digest().sha256()) ||
                    !record.fingerprint().equals(originalRecord.fingerprint())) {
                throw new IOException("operation receipt changed during recovery observation");
            }
            recoveryClaims = prepared.forRecovery(plan.recovery().toString(), originalRecord.artifact(),
                observed == null ? null : observed.artifact());
            intendedRecovery = recoveryClaims.advance(outcome, reason);
            checkOutputParent(plan, plan.recovery(), host);
            recovery = receipts.prepare(plan.recovery(), recoveryClaims, host, () -> false);
            recovery = receipts.advance(recovery, outcome, reason, host, () -> false);
        }
        catch (IOException | RuntimeException journalFailure) {
            // A failed final journal flush may have published the terminal record.
            // Report a fresh owned observation, without calling it durable success.
            recovery = null;
            if (recoveryClaims != null) {
                try {
                    var current = AttachmentReceiptStore.read(plan.recovery(), host, () -> false);
                    if (current.receipt().equals(recoveryClaims) || current.receipt().equals(intendedRecovery)) recovery = current;
                }
                catch (IOException | RuntimeException unavailable) { /* No verified recovery observation. */ }
            }
            reason = diagnostic(new IOException(reason + "; recovery journal: " + journalFailure));
            // An absent preparation record before any target replacement is an
            // ordinary failed preparation, with the complete original retained.
            boolean noRecord = !preparationEstablished && journalFailure instanceof NoSuchFileException && record == null &&
                !Files.exists(plan.receipt(), LinkOption.NOFOLLOW_LINKS);
            if (!noRecord || outcome != AttachmentReceipt.Phase.ROLLED_BACK) {
                outcome = AttachmentReceipt.Phase.RECOVERY_REQUIRED;
            }
        }
        return new Result(outcome, record, recovery, observed, cancelled, reason);
    }

    private static boolean sameImage(AttachmentFileStore.Snapshot actual, AttachmentFileStore.Snapshot expected) {
        return sameContent(actual, expected) && actual.fingerprint().equals(expected.fingerprint());
    }

    private static boolean sameContent(AttachmentFileStore.Snapshot first, AttachmentFileStore.Snapshot second) {
        return first.digest().sha256().equals(second.digest().sha256()) && first.digest().byteCount() == second.digest().byteCount();
    }

    private static boolean sameClaimImage(AttachmentReceipt.Artifact previous, AttachmentReceipt.Artifact current) {
        // A prior rollback creates a new inode. Historical identity is not an
        // authorization token: match the complete image/metadata and selected
        // path, then protect the freshly observed identity throughout this operation.
        return previous.path().equals(current.path()) && previous.sha256().equals(current.sha256()) &&
            previous.bytes() == current.bytes() && previous.metadataSha256().equals(current.metadataSha256());
    }

    private static Map<Path, String> outputParents(Map<String, Path> paths, AttachmentTargetStore.Host host) throws IOException {
        Map<Path, String> result = new HashMap<>();
        for (String role : new String[] { "receipt", "recoveryReceipt", "restoreImage" }) {
            Path parent = paths.get(role).getParent();
            result.put(parent, host.directoryIdentity(parent));
        }
        return Map.copyOf(result);
    }

    private static void checkOutputParent(Plan plan, Path output, AttachmentTargetStore.Host host) throws IOException {
        if (!plan.outputParents().get(output.getParent()).equals(host.directoryIdentity(output.getParent()))) {
            throw new IOException("transaction output parent changed: " + output);
        }
    }

    private static void requireReceipt(AttachmentReceiptStore.State expected, AttachmentReceiptStore.Host host,
            BooleanSupplier cancelled) throws IOException {
        if (!expected.equals(AttachmentReceiptStore.read(expected.path(), host, cancelled))) {
            throw new IOException("prepared operation receipt changed");
        }
    }

    private static String diagnostic(Throwable failure) {
        String value = failure.toString();
        StringBuilder safe = new StringBuilder();
        for (int index = 0; index < value.length() && safe.length() < 8000; index++) {
            char character = value.charAt(index);
            safe.append(character < 32 || character == 127 || Character.isSurrogate(character) ? ' ' : character);
        }
        return safe.toString();
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("attachment transaction cancelled");
    }
}
