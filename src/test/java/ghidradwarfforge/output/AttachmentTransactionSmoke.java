package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/** Filesystem-controller fixtures, deliberately not ELF/DWARF validation evidence. */
public final class AttachmentTransactionSmoke {
    private static final Host HOST = new Host();
    private static int checks;
    private record Fixture(Path root, AttachmentTransaction.Request request,
            Map<String, AttachmentFileStore.Snapshot> snapshots) { }

    public static void main(String[] args) throws Exception {
        if (!System.getProperty("os.name").equals("Linux")) throw new IllegalStateException("requires Linux");
        if (args.length != 0) {
            crashChild(args);
            return;
        }
        Path root = Files.createTempDirectory("forge-transaction-smoke-");
        try {
            for (boolean refresh : new boolean[] { false, true }) {
                success(root, refresh);
                faults(root, refresh);
                cancellations(root, refresh);
                commitPublicationFailure(root, refresh);
                conflicts(root, refresh);
                crashes(root, refresh);
            }
            sourceBundles(root);
            preflight(root);
            failedPreparation(root);
            missingTarget(root);
            refreshAfterRollback(root);
            recoveryJournalFailure(root);
            preparedClaimBoundaries(root);
            recoveryClaimBoundaries(root);
            refreshClaimBoundaries(root);
            alreadyRestoredBoundaries(root);
            changedOperationRecord(root);
            recoveryRecordObservation(root);
            recoveryDiagnosticBoundaries(root);
            System.out.println("attachment-transaction-smoke=PASS checks=" + checks +
                " abrupt-process-exits=8 initial-and-refresh=true native-windows=false elf-validation=false");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    /** A syntactically valid receipt still needs agreement with selected files and host. */
    private static void preparedClaimBoundaries(Path root) throws Exception {
        for (String mismatch : new String[] { "receipt", "contract", "durability", "crc" }) {
            var fixture = fixture(root, "prepared-mismatch-" + mismatch, false);
            var request = fixture.request();
            var p = request.prepared();
            var claims = new AttachmentReceipt(p.operationId(), p.mode(), p.phase(),
                mismatch.equals("receipt") ? fixture.root().resolve("other-receipt").toString() : p.receiptPath(),
                p.backend(), mismatch.equals("contract") ? "other-host" : p.hostContract(),
                mismatch.equals("durability") ? "other-durability" : p.durability(),
                mismatch.equals("crc") ? p.debuglinkCrc32() ^ 1L : p.debuglinkCrc32(), p.files(), null);
            rejectContaining(() -> AttachmentTransaction.commit(withClaims(request, claims), HOST, () -> false),
                mismatch.equals("crc") ? "CRC differs" : "path/host contract mismatch");
            equal(false, Files.exists(request.receipt()));
            equal(false, Files.exists(request.recoveryReceipt()));
            equal(false, Files.exists(request.restoreImage()));
            equal(fixture.snapshots().get("targetBefore"),
                AttachmentFileStore.observe(request.files().get("targetBefore"), HOST, () -> false));
            retained(fixture);
        }
    }

    private static AttachmentTransaction.Request withClaims(AttachmentTransaction.Request request,
            AttachmentReceipt claims) {
        return new AttachmentTransaction.Request(claims, request.files(), request.receipt(),
            request.recoveryReceipt(), request.restoreImage());
    }

    private static AttachmentReceipt withFiles(AttachmentReceipt p, Map<String, AttachmentReceipt.Artifact> files) {
        return new AttachmentReceipt(p.operationId(), p.mode(), p.phase(), p.receiptPath(),
            p.backend(), p.hostContract(), p.durability(), p.debuglinkCrc32(), files, p.diagnostic(), p.recovery());
    }

    private static void recoveryClaimBoundaries(Path root) throws Exception {
        for (boolean refresh : new boolean[] { false, true }) {
            for (String mismatch : refresh ? java.util.List.of("operation", "selected-path", "originalBackup",
                    "priorTargetBackup", "previousReceipt", "previousSidecar", "previousSource") :
                    java.util.List.of("operation", "selected-path", "originalBackup")) {
                var fixture = fixture(root, "recovery-mismatch-" + refresh + "-" + mismatch, refresh);
                var request = fixture.request();
                equal(AttachmentReceipt.Phase.COMMITTED,
                    AttachmentTransaction.commit(request, HOST, () -> false).outcome());
                var before = AttachmentFileStore.observe(request.files().get("targetBefore"), HOST, () -> false);
                if (mismatch.equals("operation")) {
                    var p = request.prepared();
                    request = withClaims(request, new AttachmentReceipt(UUID.randomUUID().toString(), p.mode(),
                        p.phase(), p.receiptPath(), p.backend(), p.hostContract(), p.durability(),
                        p.debuglinkCrc32(), p.files(), null));
                }
                else if (mismatch.equals("selected-path")) {
                    var files = new HashMap<>(request.files());
                    // Even a byte-identical independent copy cannot silently replace an explicit role.
                    Path copy = fixture.root().resolve("selected-other-sidecar");
                    Files.copy(files.get("sidecar"), copy);
                    files.put("sidecar", copy);
                    request = new AttachmentTransaction.Request(request.prepared(), files, request.receipt(),
                        request.recoveryReceipt(), request.restoreImage());
                }
                else Files.writeString(request.files().get(mismatch), "changed recovery material");
                var selected = request;
                var receiptBefore = FileDigests.read(request.receipt(), () -> false);
                rejectContaining(() -> AttachmentTransaction.recoverInterrupted(selected, HOST),
                    mismatch.equals("operation") ? "does not match the selected operation" :
                    mismatch.equals("selected-path") ? "path differs" : "recovery material changed: " + mismatch);
                equal(before, AttachmentFileStore.observe(request.files().get("targetBefore"), HOST, () -> false));
                equal(receiptBefore, FileDigests.read(request.receipt(), () -> false));
                equal(false, Files.exists(request.recoveryReceipt()));
                equal(false, Files.exists(request.restoreImage()));
            }
        }
    }

    /** Refresh cannot substitute an otherwise well-formed previous association. */
    private static void refreshClaimBoundaries(Path root) throws Exception {
        for (String mismatch : new String[] { "phase", "operation", "target-path", "originalBackup",
                "sidecar", "source", "crc" }) {
            var fixture = fixture(root, "refresh-claims-" + mismatch, true);
            var request = fixture.request();
            var old = AttachmentReceipt.read(request.files().get("previousReceipt"), () -> false);
            var files = new HashMap<>(old.files());
            if (mismatch.equals("target-path")) {
                for (String role : java.util.List.of("targetBefore", "targetAfter")) {
                    var value = files.get(role);
                    files.put(role, new AttachmentReceipt.Artifact(fixture.root().resolve("other-target").toString(),
                        value.sha256(), value.bytes(), value.identity(), value.metadataSha256()));
                }
            }
            else if (java.util.List.of("originalBackup", "sidecar", "source").contains(mismatch)) {
                var value = files.get(mismatch);
                files.put(mismatch, new AttachmentReceipt.Artifact(fixture.root().resolve("other-" + mismatch).toString(),
                    value.sha256(), value.bytes(), value.identity(), value.metadataSha256()));
            }
            var changed = new AttachmentReceipt(mismatch.equals("operation") ? request.prepared().operationId() : old.operationId(),
                old.mode(), mismatch.equals("phase") ? AttachmentReceipt.Phase.PREPARED : old.phase(),
                old.receiptPath(), old.backend(), old.hostContract(), old.durability(),
                mismatch.equals("crc") ? old.debuglinkCrc32() ^ 1L : old.debuglinkCrc32(), files, null);
            Files.writeString(request.files().get("previousReceipt"), changed.toJson());
            var currentFiles = new HashMap<>(request.prepared().files());
            currentFiles.put("previousReceipt", AttachmentFileStore.observe(
                request.files().get("previousReceipt"), HOST, () -> false).artifact());
            var selected = withClaims(request, withFiles(request.prepared(), currentFiles));
            var targetBefore = AttachmentFileStore.observe(request.files().get("targetBefore"), HOST, () -> false);
            rejectContaining(() -> AttachmentTransaction.commit(selected, HOST, () -> false),
                "refresh does not retain the verified previous association");
            equal(targetBefore, AttachmentFileStore.observe(request.files().get("targetBefore"), HOST, () -> false));
            equal(changed, AttachmentReceipt.read(request.files().get("previousReceipt"), () -> false));
            equal(false, Files.exists(request.receipt()));
            equal(false, Files.exists(request.recoveryReceipt()));
        }
    }

    private static void alreadyRestoredBoundaries(Path root) throws Exception {
        for (boolean refresh : new boolean[] { false, true }) {
            for (String state : new String[] { "restored", "changed-content", "changed-mode", "dangling" }) {
                var fixture = fixture(root, "already-restored-" + refresh + "-" + state, refresh);
                var request = fixture.request();
                equal(AttachmentReceipt.Phase.COMMITTED,
                    AttachmentTransaction.commit(request, HOST, () -> false).outcome());
                var record = AttachmentReceiptStore.read(request.receipt(), HOST, () -> false);
                Path target = request.files().get("targetBefore");
                Files.move(target, target.resolveSibling("retained-installed-image"));
                if (state.equals("dangling")) Files.createSymbolicLink(target, target.resolveSibling("missing"));
                else {
                    var backup = fixture.snapshots().get(refresh ? "priorTargetBackup" : "originalBackup");
                    var restored = AttachmentFileStore.backup(backup, target, HOST, () -> false);
                    equal(false, restored.fingerprint().identity().equals(fixture.snapshots().get("targetBefore").fingerprint().identity()));
                    if (state.equals("changed-content")) Files.writeString(target, "foreign replacement content");
                    if (state.equals("changed-mode")) Files.setPosixFilePermissions(target,
                        java.nio.file.attribute.PosixFilePermissions.fromString("r--------"));
                }
                if (state.equals("dangling")) {
                    reject(() -> AttachmentTransaction.recoverInterrupted(request, HOST));
                    equal(true, Files.isSymbolicLink(target));
                    equal(false, Files.exists(request.recoveryReceipt()));
                }
                else {
                    var targetBefore = AttachmentFileStore.observe(target, HOST, () -> false);
                    var result = AttachmentTransaction.recoverInterrupted(request, HOST);
                    equal(state.equals("restored") ? AttachmentReceipt.Phase.ROLLED_BACK :
                        AttachmentReceipt.Phase.RECOVERY_REQUIRED, result.outcome());
                    equal(targetBefore, result.observedTarget());
                    equal(targetBefore, AttachmentFileStore.observe(target, HOST, () -> false));
                    equal(result.outcome(), result.recoveryReceipt().receipt().phase());
                }
                equal(record, AttachmentReceiptStore.read(request.receipt(), HOST, () -> false));
                retained(fixture);
            }
        }
    }

    private static void changedOperationRecord(Path root) throws Exception {
        for (var boundary : new AttachmentTransaction.Boundary[] {
                AttachmentTransaction.Boundary.PREPARED, AttachmentTransaction.Boundary.TARGET_REPLACED }) {
            var fixture = fixture(root, "changed-operation-" + boundary, false);
            var p = fixture.request().prepared();
            var foreign = new AttachmentReceipt(UUID.randomUUID().toString(), p.mode(), p.phase(),
                p.receiptPath(), p.backend(), p.hostContract(), p.durability(), p.debuglinkCrc32(), p.files(), null);
            var result = AttachmentTransaction.commit(fixture.request(), HOST, () -> false, point -> {
                if (point == boundary) Files.writeString(fixture.request().receipt(), foreign.toJson());
            }, AttachmentTransaction.RECEIPTS);
            equal(AttachmentReceipt.Phase.RECOVERY_REQUIRED, result.outcome());
            equal(foreign, AttachmentReceipt.read(fixture.request().receipt(), () -> false));
            equal(null, result.receipt());
            equal(null, result.recoveryReceipt());
            equal(false, Files.exists(fixture.request().recoveryReceipt()));
            equal(fixture.snapshots().get("targetBefore").digest(), result.observedTarget().digest());
            retained(fixture);
        }
    }

    /** Change actual bytes or identity between the two independent recovery reads. */
    private static void recoveryRecordObservation(Path root) throws Exception {
        for (boolean refresh : new boolean[] {false, true}) {
            for (String change : new String[] {"content", "identity", "metadata"}) {
                var fixture = fixture(root, "recovery-observation-" + refresh + "-" + change, refresh);
                var request = fixture.request();
                var armed = new AtomicBoolean();
                var hits = new int[1];
                var changed = new byte[1][];
                var saved = new byte[1][];
                var fingerprints = new AttachmentReceiptStore.Fingerprint[2];
                var host = new Host() {
                    @Override public AttachmentReceiptStore.Fingerprint inspect(Path path) throws IOException {
                        // ReceiptStore.read observes twice; FileStore.observe then
                        // starts an independent read used to bind the recovery record.
                        if (armed.get() && path.equals(request.receipt()) && ++hits[0] == 3) {
                            saved[0] = Files.readAllBytes(path);
                            fingerprints[0] = super.inspect(path);
                            if (change.equals("content")) {
                                // Trailing JSON whitespace changes the digest while
                                // keeping the receipt's semantic claims valid.
                                var time = Files.getLastModifiedTime(path);
                                Files.writeString(path, "\n", StandardOpenOption.APPEND);
                                Files.setLastModifiedTime(path, time);
                            }
                            else if (change.equals("identity")) {
                                var time = Files.getLastModifiedTime(path);
                                var permissions = Files.getPosixFilePermissions(path);
                                // Retain the old inode so the new one cannot reuse it.
                                Files.move(path, path.resolveSibling("retained-operation-record"));
                                Files.write(path, saved[0], StandardOpenOption.CREATE_NEW);
                                Files.setPosixFilePermissions(path, permissions);
                                Files.setLastModifiedTime(path, time);
                            }
                            else {
                                Files.setLastModifiedTime(path, java.nio.file.attribute.FileTime.fromMillis(
                                    Files.getLastModifiedTime(path).toMillis() + 10000));
                            }
                            changed[0] = Files.readAllBytes(path);
                            fingerprints[1] = super.inspect(path);
                        }
                        return super.inspect(path);
                    }
                };
                var result = AttachmentTransaction.commit(request, host, () -> false, point -> {
                    if (point == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                        armed.set(true);
                        throw new IOException("controlled failure after replacement");
                    }
                }, AttachmentTransaction.RECEIPTS);
                equal(4, hits[0]);
                equal(change.equals("content"), fingerprints[0].equals(fingerprints[1]));
                equal(!change.equals("content"), java.util.Arrays.equals(saved[0], changed[0]));
                equal(!change.equals("identity"), fingerprints[0].identity().equals(fingerprints[1].identity()));
                equal(!change.equals("metadata"), fingerprints[0].metadataSha256().equals(fingerprints[1].metadataSha256()));
                equal(AttachmentReceipt.Phase.RECOVERY_REQUIRED, result.outcome());
                equal(true, result.diagnostic().contains("operation receipt changed during recovery observation"));
                equal(null, result.recoveryReceipt());
                equal(false, Files.exists(request.recoveryReceipt()));
                equal(true, java.util.Arrays.equals(changed[0], Files.readAllBytes(request.receipt())));
                equal(fixture.snapshots().get("targetBefore").digest(), result.observedTarget().digest());
                equal(result.observedTarget(), AttachmentFileStore.observe(request.files().get("targetBefore"), HOST, () -> false));
                retained(fixture);

                // Explicitly reconcile the selected receipt, then prove that the
                // preserved inputs still permit a successful recovery retry.
                Files.write(request.receipt(), saved[0]);
                var retried = AttachmentTransaction.recoverInterrupted(request, HOST);
                equal(AttachmentReceipt.Phase.ROLLED_BACK, retried.outcome());
                equal(AttachmentReceipt.Phase.ROLLED_BACK, retried.recoveryReceipt().receipt().phase());
                equal(fixture.snapshots().get("targetBefore").digest(), retried.observedTarget().digest());
                retained(fixture);
            }
        }
    }

    private static void recoveryDiagnosticBoundaries(Path root) throws Exception {
        String[][] cases = {
            {"controls:\u0000\t\n\r\u007f\ud800\udfff:end", "java.io.IOException: controls:       :end"},
            {"high:\ud800:end", "java.io.IOException: high: :end"},
            {"low:\udfff:end", "java.io.IOException: low: :end"},
            {"valid unicode: café Ω", "java.io.IOException: valid unicode: café Ω"},
            {"x".repeat(8001), "java.io.IOException: " + "x".repeat(7979)}
        };
        for (boolean refresh : new boolean[] {false, true}) {
            for (int index = 0; index < cases.length; index++) {
                var fixture = fixture(root, "diagnostic-" + refresh + "-" + index, refresh);
                var failure = new IOException(cases[index][0]);
                var result = AttachmentTransaction.commit(fixture.request(), HOST, () -> false, point -> {
                    if (point == AttachmentTransaction.Boundary.TARGET_REPLACED) throw failure;
                }, AttachmentTransaction.RECEIPTS);
                String expected = cases[index][1];
                equal(AttachmentReceipt.Phase.ROLLED_BACK, result.outcome());
                equal(expected, result.diagnostic());
                equal(expected, result.recoveryReceipt().receipt().diagnostic());
                equal(fixture.snapshots().get("targetBefore").digest(), result.observedTarget().digest());
                retained(fixture);
            }
        }
    }

    private static void rejectContaining(Checked action, String message) throws Exception {
        try { action.run(); throw new AssertionError("expected rejection containing: " + message); }
        catch (IOException expected) {
            equal(true, expected.getMessage().contains(message));
        }
    }

    private static void recoveryJournalFailure(Path root) throws Exception {
        var fixture = fixture(root, "recovery-journal-failure", false);
        var receipts = new ReceiptProxy() {
            @Override public AttachmentReceiptStore.State advance(AttachmentReceiptStore.State previous,
                    AttachmentReceipt.Phase next, String diagnostic, AttachmentReceiptStore.Host host,
                    BooleanSupplier cancelled) throws IOException {
                var state = super.advance(previous, next, diagnostic, host, cancelled);
                if (state.receipt().recovery() != null) throw new IOException("injected final recovery journal flush failure");
                return state;
            }
        };
        var result = AttachmentTransaction.commit(fixture.request(), HOST, () -> false,
            point -> { if (point == AttachmentTransaction.Boundary.TARGET_REPLACED) throw new IOException("post-replacement failure"); }, receipts);
        equal(AttachmentReceipt.Phase.RECOVERY_REQUIRED, result.outcome());
        equal(fixture.snapshots().get("targetBefore").digest(), result.observedTarget().digest());
        equal(AttachmentReceipt.Phase.ROLLED_BACK, result.recoveryReceipt().receipt().phase());
        equal(result.recoveryReceipt(), AttachmentReceiptStore.read(fixture.request().recoveryReceipt(), HOST, () -> false));
        retained(fixture);
    }

    private static void crashChild(String[] args) throws Exception {
        if (args.length != 4 || !args[0].equals("--crash")) throw new IllegalArgumentException("bad child");
        var claims = AttachmentReceipt.read(Path.of(args[1]), () -> false);
        Properties selected = new Properties();
        try (var input = Files.newInputStream(Path.of(args[2]))) { selected.load(input); }
        var files = new HashMap<String, Path>();
        for (String role : claims.files().keySet()) files.put(role, Path.of(selected.getProperty(role)));
        var request = new AttachmentTransaction.Request(claims, files,
            Path.of(selected.getProperty("receipt")), Path.of(selected.getProperty("recoveryReceipt")),
            Path.of(selected.getProperty("restoreImage")));
        var boundary = AttachmentTransaction.Boundary.valueOf(args[3]);
        AttachmentTransaction.commit(request, HOST, () -> false,
            point -> { if (point == boundary) Runtime.getRuntime().halt(89); }, AttachmentTransaction.RECEIPTS);
        throw new AssertionError("child did not halt");
    }

    private static void crashes(Path root, boolean refresh) throws Exception {
        for (var boundary : new AttachmentTransaction.Boundary[] {
                AttachmentTransaction.Boundary.PREPARED, AttachmentTransaction.Boundary.TARGET_REPLACED,
                AttachmentTransaction.Boundary.BEFORE_COMMIT, AttachmentTransaction.Boundary.COMMITTED }) {
            var fixture = fixture(root, "crash-" + refresh + "-" + boundary, refresh);
            Path intent = Files.writeString(fixture.root().resolve("test-intent.json"), fixture.request().prepared().toJson());
            Properties selected = new Properties();
            fixture.request().files().forEach((role, path) -> selected.setProperty(role, path.toString()));
            selected.setProperty("receipt", fixture.request().receipt().toString());
            selected.setProperty("recoveryReceipt", fixture.request().recoveryReceipt().toString());
            selected.setProperty("restoreImage", fixture.request().restoreImage().toString());
            Path selections = fixture.root().resolve("test-selections.properties");
            try (var output = Files.newOutputStream(selections)) { selected.store(output, "explicit test-owned paths"); }
            var child = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED", "-cp", System.getProperty("java.class.path"),
                AttachmentTransactionSmoke.class.getName(), "--crash", intent.toString(), selections.toString(),
                boundary.name()).redirectErrorStream(true).redirectOutput(fixture.root().resolve("child.log").toFile()).start();
            try {
                if (!child.waitFor(20, TimeUnit.SECONDS)) throw new AssertionError("owned crash child timed out");
                equal(89, child.exitValue());
                var receiptBefore = AttachmentReceiptStore.read(fixture.request().receipt(), HOST, () -> false);
                var recovered = AttachmentTransaction.recoverInterrupted(fixture.request(), HOST);
                rolledBack(fixture, recovered);
                equal(receiptBefore, AttachmentReceiptStore.read(fixture.request().receipt(), HOST, () -> false));
                retained(fixture);
            }
            finally {
                if (child.isAlive()) {
                    child.destroyForcibly();
                    if (!child.waitFor(5, TimeUnit.SECONDS)) throw new AssertionError("owned child could not be reaped");
                }
            }
        }
    }

    private static void refreshAfterRollback(Path root) throws Exception {
        var first = fixture(root, "refresh-after-rollback", false);
        var initial = AttachmentTransaction.commit(first.request(), HOST, () -> false);
        var original = first.snapshots().get("originalBackup");
        var second = generation(first.root(), "second", initial.observedTarget(), original, first);
        var failed = AttachmentTransaction.commit(second.request(), HOST, () -> false,
            point -> { if (point == AttachmentTransaction.Boundary.TARGET_REPLACED) throw new IOException("rollback second generation"); },
            AttachmentTransaction.RECEIPTS);
        rolledBack(second, failed);
        equal(false, failed.observedTarget().fingerprint().identity().equals(initial.observedTarget().fingerprint().identity()));
        var third = generation(first.root(), "third", failed.observedTarget(), original, first);
        var committed = AttachmentTransaction.commit(third.request(), HOST, () -> false);
        equal(AttachmentReceipt.Phase.COMMITTED, committed.outcome());
        retained(third);
        retained(second);
    }

    private static void sourceBundles(Path root) throws Exception {
        for (boolean refresh : new boolean[] { false, true }) {
            for (String role : refresh ? java.util.List.of("source", "previousSource") : java.util.List.of("source")) {
                for (int dependency : new int[] { 1, 2 }) {
                    String label = "bundle-" + refresh + "-" + role + "-" + dependency;
                    var missing = fixture(root, label + "-preflight", refresh, true);
                    Path part = SourceBundleFiles.open(missing.request().files().get(role), () -> false).orElseThrow().files().get(dependency);
                    Files.move(part, part.resolveSibling(part.getFileName() + ".hidden"));
                    reject(() -> AttachmentTransaction.commit(missing.request(), HOST, () -> false));
                    equal(false, Files.exists(missing.request().receipt()));
                    equal(missing.snapshots().get("targetBefore"), AttachmentFileStore.observe(missing.request().files().get("targetBefore"), HOST, () -> false));
                    for (var boundary : new AttachmentTransaction.Boundary[] {
                            AttachmentTransaction.Boundary.PREPARED, AttachmentTransaction.Boundary.TARGET_REPLACED }) {
                        var changed = fixture(root, label + "-" + boundary, refresh, true);
                        Path selected = SourceBundleFiles.open(changed.request().files().get(role), () -> false).orElseThrow().files().get(dependency);
                        var result = AttachmentTransaction.commit(changed.request(), HOST, () -> false, point -> {
                            if (point == boundary) Files.move(selected, selected.resolveSibling(selected.getFileName() + ".hidden"));
                        }, AttachmentTransaction.RECEIPTS);
                        equal(role.equals("previousSource") ? AttachmentReceipt.Phase.RECOVERY_REQUIRED :
                            AttachmentReceipt.Phase.ROLLED_BACK, result.outcome());
                    }
                    var interrupted = fixture(root, label + "-recover", refresh, true);
                    equal(AttachmentReceipt.Phase.COMMITTED, AttachmentTransaction.commit(interrupted.request(), HOST, () -> false).outcome());
                    Path absent = SourceBundleFiles.open(interrupted.request().files().get(role), () -> false).orElseThrow().files().get(dependency);
                    Path hidden = absent.resolveSibling(absent.getFileName() + ".hidden");
                    Files.move(absent, hidden);
                    if (role.equals("previousSource")) {
                        reject(() -> AttachmentTransaction.recoverInterrupted(interrupted.request(), HOST));
                        Files.move(hidden, absent);
                    }
                    // Damaged new-generation dependencies must not prevent restoring an intact prior image.
                    equal(AttachmentReceipt.Phase.ROLLED_BACK,
                        AttachmentTransaction.recoverInterrupted(interrupted.request(), HOST).outcome());
                }
            }
        }
    }

    private static Fixture fixture(Path root, String name, boolean refresh) throws Exception {
        return fixture(root, name, refresh, false);
    }

    private static Fixture fixture(Path root, String name, boolean refresh, boolean bundle) throws Exception {
        Path directory = Files.createDirectory(root.resolve(name));
        Path target = Files.writeString(directory.resolve("target"), "original executable bytes");
        var before = AttachmentFileStore.observe(target, HOST, () -> false);
        var original = AttachmentFileStore.backup(before, directory.resolve("original-backup"), HOST, () -> false);
        Fixture first = generation(directory, "first", before, original, null, bundle);
        if (!refresh) return first;
        var committed = AttachmentTransaction.commit(first.request(), HOST, () -> false);
        equal(AttachmentReceipt.Phase.COMMITTED, committed.outcome());
        return generation(directory, "second", committed.observedTarget(), original, first, bundle);
    }

    private static Fixture generation(Path directory, String prefix, AttachmentFileStore.Snapshot before,
            AttachmentFileStore.Snapshot original, Fixture previous) throws Exception {
        return generation(directory, prefix, before, original, previous, false);
    }

    private static Fixture generation(Path directory, String prefix, AttachmentFileStore.Snapshot before,
            AttachmentFileStore.Snapshot original, Fixture previous, boolean bundle) throws Exception {
        var files = new HashMap<String, Path>();
        files.put("targetBefore", before.path());
        files.put("originalBackup", original.path());
        for (String role : new String[] { "sidecar", "source", "exportReport", "validationEvidence" }) {
            files.put(role, Files.writeString(directory.resolve(prefix + "-" + role), prefix + ":filesystem-only:" + role));
        }
        if (bundle) {
            Path source = Files.createDirectory(directory.resolve(prefix + "-sources")).resolve("source.c");
            var plan = SourceBundle.prepare(original.digest().sha256(), "source.c", SourceBundleSmoke.fixture(), 3, () -> false);
            SourceBundleStore.install(source, plan, java.util.List.of(), () -> false);
            Files.write(source, plan.indexBytes(() -> false));
            files.put("source", source);
        }
        Path stage = directory.resolve(prefix + "-candidate");
        try (var output = FileChannel.open(stage, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer bytes = ByteBuffer.wrap((prefix + ":complete attached image").getBytes(StandardCharsets.UTF_8));
            while (bytes.hasRemaining()) output.write(bytes);
            HOST.preserveMetadata(before.path(), before.fingerprint(), stage);
            output.force(true);
        }
        files.put("targetAfter", stage);
        if (previous != null) {
            files.put("previousReceipt", previous.request().receipt());
            files.put("previousSidecar", previous.request().files().get("sidecar"));
            files.put("previousSource", previous.request().files().get("source"));
            var backup = AttachmentFileStore.backup(before, directory.resolve(prefix + "-prior-backup"), HOST, () -> false);
            files.put("priorTargetBackup", backup.path());
        }
        var snapshots = new HashMap<String, AttachmentFileStore.Snapshot>();
        var artifacts = new HashMap<String, AttachmentReceipt.Artifact>();
        for (var entry : files.entrySet()) {
            var observed = AttachmentFileStore.observe(entry.getValue(), HOST, () -> false);
            snapshots.put(entry.getKey(), observed);
            var artifact = observed.artifact();
            if (entry.getKey().equals("targetAfter")) {
                artifact = new AttachmentReceipt.Artifact(before.path().toString(), artifact.sha256(), artifact.bytes(),
                    artifact.identity(), artifact.metadataSha256());
            }
            artifacts.put(entry.getKey(), artifact);
        }
        Path receipt = directory.resolve(prefix + "-receipt.json");
        var prepared = new AttachmentReceipt(UUID.randomUUID().toString(),
            previous == null ? AttachmentReceipt.Mode.INITIAL : AttachmentReceipt.Mode.REFRESH,
            AttachmentReceipt.Phase.PREPARED, receipt.toString(), "filesystem-test-only", HOST.contract(), HOST.durability(),
            snapshots.get("sidecar").digest().gnuDebuglinkCrc32(), artifacts, null);
        return new Fixture(directory, new AttachmentTransaction.Request(prepared, files, receipt,
            directory.resolve(prefix + "-recovery.json"), directory.resolve(prefix + "-restore")), snapshots);
    }

    private static void success(Path root, boolean refresh) throws Exception {
        var fixture = fixture(root, "success-" + refresh, refresh);
        var result = AttachmentTransaction.commit(fixture.request(), HOST, () -> false);
        equal(AttachmentReceipt.Phase.COMMITTED, result.outcome());
        equal(fixture.snapshots().get("targetAfter").digest(), result.observedTarget().digest());
        equal(AttachmentReceipt.Phase.COMMITTED, result.receipt().receipt().phase());
        equal(null, result.recoveryReceipt());
        equal(false, Files.exists(fixture.request().recoveryReceipt()));
        retained(fixture);
    }

    private static void faults(Path root, boolean refresh) throws Exception {
        for (var boundary : AttachmentTransaction.Boundary.values()) {
            var fixture = fixture(root, "fault-" + refresh + "-" + boundary, refresh);
            if (boundary == AttachmentTransaction.Boundary.VERIFIED) {
                reject(() -> AttachmentTransaction.commit(fixture.request(), HOST, () -> false,
                    point -> { throw new IOException("before preparation"); }, AttachmentTransaction.RECEIPTS));
                equal(false, Files.exists(fixture.request().receipt()));
                equal(fixture.snapshots().get("targetBefore"),
                    AttachmentFileStore.observe(fixture.request().files().get("targetBefore"), HOST, () -> false));
                retained(fixture);
                continue;
            }
            var result = AttachmentTransaction.commit(fixture.request(), HOST, () -> false,
                point -> { if (point == boundary) throw new IOException("injected " + boundary); }, AttachmentTransaction.RECEIPTS);
            rolledBack(fixture, result);
            equal(boundary == AttachmentTransaction.Boundary.COMMITTED ? AttachmentReceipt.Phase.COMMITTED :
                AttachmentReceipt.Phase.PREPARED, result.receipt().receipt().phase());
            equal(result.receipt().sha256(), result.recoveryReceipt().receipt().recovery().priorReceipt().sha256());
            retained(fixture);
        }
    }

    private static void cancellations(Path root, boolean refresh) throws Exception {
        for (var boundary : new AttachmentTransaction.Boundary[] {
                AttachmentTransaction.Boundary.VERIFIED, AttachmentTransaction.Boundary.PREPARED,
                AttachmentTransaction.Boundary.TARGET_REPLACED, AttachmentTransaction.Boundary.BEFORE_COMMIT }) {
            var fixture = fixture(root, "cancel-" + refresh + "-" + boundary, refresh);
            AtomicBoolean cancelled = new AtomicBoolean();
            try {
                var result = AttachmentTransaction.commit(fixture.request(), HOST, cancelled::get,
                    point -> { if (point == boundary) cancelled.set(true); }, AttachmentTransaction.RECEIPTS);
                equal(false, boundary == AttachmentTransaction.Boundary.VERIFIED);
                rolledBack(fixture, result);
                equal(true, result.cancelled());
            }
            catch (CancellationException expected) {
                equal(AttachmentTransaction.Boundary.VERIFIED, boundary);
                equal(false, Files.exists(fixture.request().receipt()));
            }
            retained(fixture);
        }
    }

    private static void commitPublicationFailure(Path root, boolean refresh) throws Exception {
        var fixture = fixture(root, "commit-publication-" + refresh, refresh);
        final AttachmentReceiptStore.State[] committed = new AttachmentReceiptStore.State[1];
        var receipts = new ReceiptProxy() {
            @Override public AttachmentReceiptStore.State advance(AttachmentReceiptStore.State previous,
                    AttachmentReceipt.Phase next, String diagnostic, AttachmentReceiptStore.Host host,
                    BooleanSupplier cancelled) throws IOException {
                var state = super.advance(previous, next, diagnostic, host, cancelled);
                if (next == AttachmentReceipt.Phase.COMMITTED) {
                    committed[0] = state;
                    throw new IOException("injected failure after COMMITTED became visible");
                }
                return state;
            }
        };
        var result = AttachmentTransaction.commit(fixture.request(), HOST, () -> false, point -> { }, receipts);
        rolledBack(fixture, result);
        equal(committed[0], AttachmentReceiptStore.read(fixture.request().receipt(), HOST, () -> false));
        equal(committed[0].sha256(), result.recoveryReceipt().receipt().recovery().priorReceipt().sha256());
        equal(AttachmentReceipt.Phase.COMMITTED, result.receipt().receipt().phase());
        retained(fixture);
    }

    private static void conflicts(Path root, boolean refresh) throws Exception {
        var fixture = fixture(root, "foreign-target-" + refresh, refresh);
        var result = AttachmentTransaction.commit(fixture.request(), HOST, () -> false,
            point -> {
                if (point == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                    Path target = fixture.request().files().get("targetBefore");
                    Files.move(target, target.resolveSibling("retained-attached"));
                    Files.writeString(target, "foreign target");
                    throw new IOException("concurrent target change");
                }
            }, AttachmentTransaction.RECEIPTS);
        equal(AttachmentReceipt.Phase.RECOVERY_REQUIRED, result.outcome());
        equal("foreign target", Files.readString(fixture.request().files().get("targetBefore")));
        equal(AttachmentReceipt.Phase.RECOVERY_REQUIRED, result.recoveryReceipt().receipt().phase());
        retained(fixture);

        var journal = fixture(root, "foreign-journal-" + refresh, refresh);
        var blocked = AttachmentTransaction.commit(journal.request(), HOST, () -> false,
            point -> {
                if (point == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                    Files.writeString(journal.request().recoveryReceipt(), "foreign recovery record", StandardOpenOption.CREATE_NEW);
                    throw new IOException("post-target failure");
                }
            }, AttachmentTransaction.RECEIPTS);
        equal(AttachmentReceipt.Phase.RECOVERY_REQUIRED, blocked.outcome());
        equal(journal.snapshots().get("targetBefore").digest(), blocked.observedTarget().digest());
        equal("foreign recovery record", Files.readString(journal.request().recoveryReceipt()));
        retained(journal);

        if (refresh) {
            var previous = fixture(root, "damaged-previous", true);
            var rejected = AttachmentTransaction.commit(previous.request(), HOST, () -> false,
                point -> {
                    if (point == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                        Files.writeString(previous.request().files().get("previousSidecar"), "overwritten prior pair");
                        throw new IOException("prior association disappeared");
                    }
                }, AttachmentTransaction.RECEIPTS);
            equal(AttachmentReceipt.Phase.RECOVERY_REQUIRED, rejected.outcome());
            equal(previous.snapshots().get("targetAfter").digest(), rejected.observedTarget().digest());
            equal(previous.snapshots().get("originalBackup"),
                AttachmentFileStore.observe(previous.request().files().get("originalBackup"), HOST, () -> false));
            equal(previous.snapshots().get("priorTargetBackup"),
                AttachmentFileStore.observe(previous.request().files().get("priorTargetBackup"), HOST, () -> false));
        }
    }

    private static void preflight(Path root) throws Exception {
        var fixture = fixture(root, "preflight", false);
        var request = fixture.request();
        var alias = new AttachmentTransaction.Request(request.prepared(), request.files(), request.receipt(),
            request.files().get("sidecar"), request.restoreImage());
        reject(() -> AttachmentTransaction.commit(alias, HOST, () -> false));
        equal(false, Files.exists(request.receipt()));
        equal(false, Files.exists(request.restoreImage()));
        retained(fixture);
        Files.writeString(request.files().get("sidecar"), "changed before commit");
        reject(() -> AttachmentTransaction.commit(request, HOST, () -> false));
        equal(false, Files.exists(request.receipt()));
        equal(fixture.snapshots().get("targetBefore"), AttachmentFileStore.observe(request.files().get("targetBefore"), HOST, () -> false));
    }

    private static void failedPreparation(Path root) throws Exception {
        var fixture = fixture(root, "prepare-failure", false);
        var receipts = new ReceiptProxy() {
            @Override public AttachmentReceiptStore.State prepare(Path path, AttachmentReceipt receipt,
                    AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException {
                throw new IOException("injected prepare failure before publication");
            }
        };
        var result = AttachmentTransaction.commit(fixture.request(), HOST, () -> false, point -> { }, receipts);
        equal(AttachmentReceipt.Phase.ROLLED_BACK, result.outcome());
        equal(false, Files.exists(fixture.request().receipt()));
        equal(fixture.snapshots().get("targetBefore"), result.observedTarget());
        retained(fixture);
    }

    private static void missingTarget(Path root) throws Exception {
        var fixture = fixture(root, "missing-target", false);
        var host = new Host() {
            @Override public void replaceAtomic(Path stage, Path target) throws IOException {
                if (!target.equals(fixture.snapshots().get("targetBefore").path())) {
                    super.replaceAtomic(stage, target);
                    return;
                }
                Files.move(target, target.resolveSibling("retained-native-original"));
                throw new IOException("injected native failure after removal of original name");
            }
        };
        var result = AttachmentTransaction.commit(fixture.request(), host, () -> false);
        rolledBack(fixture, result);
        retained(fixture);

        var repeated = fixture(root, "missing-target-and-receipt-failure", false);
        var persistentFailure = new Host() {
            @Override public void replaceAtomic(Path stage, Path target) throws IOException {
                Files.move(target, target.resolveSibling("retained-native-original"));
                throw new IOException("injected native failure also affects recovery receipt");
            }
        };
        var incomplete = AttachmentTransaction.commit(repeated.request(), persistentFailure, () -> false);
        equal(AttachmentReceipt.Phase.RECOVERY_REQUIRED, incomplete.outcome());
        equal(repeated.snapshots().get("targetBefore").digest(), incomplete.observedTarget().digest());
        retained(repeated);
    }

    private static void rolledBack(Fixture fixture, AttachmentTransaction.Result result) throws Exception {
        equal(AttachmentReceipt.Phase.ROLLED_BACK, result.outcome());
        equal(fixture.snapshots().get("targetBefore").digest(), result.observedTarget().digest());
        equal(result.observedTarget(), AttachmentFileStore.observe(result.observedTarget().path(), HOST, () -> false));
        equal(AttachmentReceipt.Phase.ROLLED_BACK, result.recoveryReceipt().receipt().phase());
        equal(result.observedTarget().artifact(), result.recoveryReceipt().receipt().recovery().observedTarget());
    }

    private static void retained(Fixture fixture) throws Exception {
        for (var entry : fixture.snapshots().entrySet()) {
            if (!entry.getKey().equals("targetBefore") && !entry.getKey().equals("targetAfter")) {
                equal(entry.getValue(), AttachmentFileStore.observe(entry.getValue().path(), HOST, () -> false));
            }
        }
    }

    private static class Host extends AttachmentReceiptStoreSmoke.Host implements AttachmentTargetStore.Host {
        public void replaceAtomic(Path stage, Path target) throws IOException {
            new LinuxAtomicRename().replaceAtomic(stage, target);
        }
    }

    private static class ReceiptProxy implements AttachmentTransaction.Receipts {
        public AttachmentReceiptStore.State prepare(Path path, AttachmentReceipt receipt,
                AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException {
            return AttachmentTransaction.RECEIPTS.prepare(path, receipt, host, cancelled);
        }
        public AttachmentReceiptStore.State advance(AttachmentReceiptStore.State previous, AttachmentReceipt.Phase next,
                String diagnostic, AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException {
            return AttachmentTransaction.RECEIPTS.advance(previous, next, diagnostic, host, cancelled);
        }
    }

    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void reject(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("expected rejection"); }
        catch (IOException expected) { checks++; }
    }
    private static void equal(Object expected, Object actual) {
        if (!java.util.Objects.equals(expected, actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }
}
