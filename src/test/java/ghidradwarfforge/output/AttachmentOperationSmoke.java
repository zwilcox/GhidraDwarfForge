package ghidradwarfforge.output;

import ghidradwarfforge.elf.MatchedElfSidecarWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Preparation ordering/failure controls; validator is deliberately a test seam. */
public final class AttachmentOperationSmoke {
    private static int checks;
    private static final Host HOST = new Host();
    private static final AttachmentOperation.Validator VALIDATOR = (binding, evidence, host, cancelled) ->
        Files.writeString(evidence, "test seam only; no DWARF validation claim\n", StandardOpenOption.CREATE_NEW);

    static class Host extends AttachmentReceiptStoreSmoke.Host implements AttachmentOperation.Host {
        public byte[] debuglinkBasename(Path sidecar) {
            return sidecar.getFileName().toString().getBytes(StandardCharsets.UTF_8);
        }
        public void replaceAtomic(Path stage, Path target) throws IOException {
            Files.move(stage, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-operation-");
        try {
            Path c = root.resolve("fixture.c");
            Path seed = root.resolve("seed.elf");
            Files.writeString(c, "int main(void) { return 0; }\n");
            var compiler = new ProcessBuilder("cc", "-g0", "-no-pie", "-o", seed.toString(), c.toString()).inheritIO().start();
            if (!compiler.waitFor(20, TimeUnit.SECONDS)) {
                compiler.destroyForcibly().waitFor();
                throw new AssertionError("fixture compiler timeout");
            }
            equal(0, compiler.exitValue());
            initialAndRefresh(root, seed, false);
            initialAndRefresh(root, seed, true);
            validationFailures(root, seed);
            preflight(root, seed);
            metadataFailure(root, seed);
            handoffFailure(root, seed);
            System.out.println("attachment-operation-smoke=PASS checks=" + checks +
                " initial-refresh-ordering=true production-host=false validator=test-seam");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (var path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static AttachmentOperation.Request fixture(Path root, Path seed, String name) throws Exception {
        Path directory = Files.createDirectory(root.resolve(name));
        Path target = directory.resolve("target.elf");
        Files.copy(seed, target, StandardCopyOption.COPY_ATTRIBUTES);
        return exported(directory, target, target, "first", null);
    }

    private static AttachmentOperation.Request exported(Path directory, Path target, Path original,
            String generation, AttachmentOperation.Refresh refresh) throws Exception {
        Path sidecar = directory.resolve(generation + ".dbg");
        Path source = directory.resolve(generation + ".dbg.c");
        Path report = directory.resolve(generation + ".report.json");
        new MatchedElfSidecarWriter().write(original, sidecar,
            Map.of(".debug_info", generation.getBytes(StandardCharsets.UTF_8)));
        Files.writeString(source, "/* synthetic unit fixture " + generation + " */\n");
        ExportArtifactHashBindingFixtures.write(new ExportArtifactHashBindingFixtures.Pair(directory,
            report, original, sidecar, source), true);
        return new AttachmentOperation.Request(target, sidecar, source, report, directory.resolve("original.backup"),
            directory.resolve(generation + ".validation.json"), directory.resolve(generation + ".receipt.json"),
            directory.resolve(generation + ".recovery.json"), directory.resolve(generation + ".restore.elf"), refresh);
    }

    private static void initialAndRefresh(Path root, Path seed, boolean rollback) throws Exception {
        var first = fixture(root, seed, "initial-refresh-" + rollback);
        var original = AttachmentFileStore.observe(first.target(), HOST, () -> false);
        var initial = AttachmentOperation.execute(first, HOST, VALIDATOR, () -> false);
        equal(AttachmentReceipt.Phase.COMMITTED, initial.transaction().outcome());
        var current = AttachmentFileStore.observe(first.target(), HOST, () -> false);
        var previousReceipt = AttachmentFileStore.observe(first.receipt(), HOST, () -> false);
        var previousSource = AttachmentFileStore.observe(first.source(), HOST, () -> false);
        var previousSidecar = AttachmentFileStore.observe(first.sidecar(), HOST, () -> false);
        var backup = AttachmentFileStore.observe(first.originalBackup(), HOST, () -> false);
        equal(original.digest(), backup.digest());
        var refresh = new AttachmentOperation.Refresh(first.receipt(), first.sidecar(), first.source(),
            first.target().resolveSibling("prior-target.backup"));
        var second = exported(first.target().getParent(), first.target(), first.originalBackup(), "second", refresh);
        var result = AttachmentOperation.execute(second, HOST, VALIDATOR, () -> false, boundary -> {
            if (rollback && boundary == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                throw new IOException("injected refresh post-replacement failure");
            }
        });
        equal(rollback ? AttachmentReceipt.Phase.ROLLED_BACK : AttachmentReceipt.Phase.COMMITTED,
            result.transaction().outcome());
        equal(current.digest(), AttachmentFileStore.observe(refresh.priorTargetBackup(), HOST, () -> false).digest());
        for (var retained : new AttachmentFileStore.Snapshot[] {previousReceipt, previousSource, previousSidecar, backup}) {
            AttachmentFileStore.unchanged(retained, HOST, () -> false);
            checks++;
        }
        if (rollback) {
            equal(current.digest(), AttachmentFileStore.observe(first.target(), HOST, () -> false).digest());
            // A rollback changes the target inode; the previous immutable receipt
            // must still allow a subsequent explicitly selected fresh generation.
            var third = exported(first.target().getParent(), first.target(), first.originalBackup(), "third",
                new AttachmentOperation.Refresh(first.receipt(), first.sidecar(), first.source(),
                    first.target().resolveSibling("third-prior.backup")));
            equal(AttachmentReceipt.Phase.COMMITTED,
                AttachmentOperation.execute(third, HOST, VALIDATOR, () -> false).transaction().outcome());
        }
    }

    private static void validationFailures(Path root, Path seed) throws Exception {
        for (String action : new String[] {"reject", "cancel", "missing-evidence", "change-input", "after-publication"}) {
            var request = fixture(root, seed, "validation-" + action);
            var before = AttachmentFileStore.observe(request.target(), HOST, () -> false);
            AtomicInteger calls = new AtomicInteger();
            var failure = reject(() -> AttachmentOperation.execute(request, HOST, (binding, evidence, host, cancelled) -> {
                calls.incrementAndGet();
                equal(false, Files.exists(request.originalBackup()));
                if (action.equals("reject")) throw new IOException("validation rejected");
                if (action.equals("cancel")) throw new CancellationException("validation cancelled");
                if (action.equals("missing-evidence")) return;
                VALIDATOR.validate(binding, evidence, host, cancelled);
                if (action.equals("after-publication")) throw new IOException("validator completion failed");
                Files.writeString(request.target(), "concurrent target bytes");
            }, () -> false));
            equal(1, calls.get());
            equal(true, failure instanceof AttachmentOperation.PreparationFailure);
            equal(action.equals("cancel"), ((AttachmentOperation.PreparationFailure) failure).cancelled());
            equal(false, Files.exists(request.originalBackup()));
            equal(false, Files.exists(request.receipt()));
            if (action.equals("change-input")) equal("concurrent target bytes", Files.readString(request.target()));
            else AttachmentFileStore.unchanged(before, HOST, () -> false);
        }
    }

    private static void preflight(Path root, Path seed) throws Exception {
        var request = fixture(root, seed, "preflight");
        var before = AttachmentFileStore.observe(request.target(), HOST, () -> false);
        AttachmentOperation.Validator never = (binding, evidence, host, cancelled) -> {
            throw new AssertionError("unsafe selection reached validator");
        };
        var alias = new AttachmentOperation.Request(request.target(), request.sidecar(), request.source(), request.exportReport(),
            request.originalBackup(), request.source(), request.receipt(), request.recoveryReceipt(), request.restoreImage(), null);
        reject(() -> AttachmentOperation.execute(alias, HOST, never, () -> false));
        Files.writeString(request.originalBackup(), "existing backup");
        reject(() -> AttachmentOperation.execute(request, HOST, never, () -> false));
        equal("existing backup", Files.readString(request.originalBackup()));
        Files.delete(request.originalBackup());
        Path movedSource = request.source().resolveSibling("moved-source.c");
        Files.copy(request.source(), movedSource);
        var moved = new AttachmentOperation.Request(request.target(), request.sidecar(), movedSource, request.exportReport(),
            request.originalBackup(), request.validationEvidence(), request.receipt(), request.recoveryReceipt(), request.restoreImage(), null);
        reject(() -> AttachmentOperation.execute(moved, HOST, never, () -> false));
        Path debug = Files.createDirectory(request.target().getParent().resolve(".debug"));
        Path relocated = debug.resolve(request.sidecar().getFileName());
        Files.copy(request.sidecar(), relocated);
        var shadowed = new AttachmentOperation.Request(request.target(), relocated, request.source(), request.exportReport(),
            request.originalBackup(), request.validationEvidence(), request.receipt(), request.recoveryReceipt(), request.restoreImage(), null);
        reject(() -> AttachmentOperation.execute(shadowed, HOST, never, () -> false));
        AttachmentFileStore.unchanged(before, HOST, () -> false);
        equal(false, Files.exists(request.validationEvidence()));
        equal(false, Files.exists(request.receipt()));
    }

    private static void metadataFailure(Path root, Path seed) throws Exception {
        var request = fixture(root, seed, "metadata-failure");
        var before = AttachmentFileStore.observe(request.target(), HOST, () -> false);
        var host = new Host() {
            @Override public void preserveMetadata(Path source, AttachmentReceiptStore.Fingerprint expected, Path stage)
                    throws IOException {
                if (stage.getFileName().toString().equals("candidate.elf")) throw new IOException("unsupported candidate metadata");
                super.preserveMetadata(source, expected, stage);
            }
        };
        var failure = reject(() -> AttachmentOperation.execute(request, host, VALIDATOR, () -> false));
        equal(true, failure instanceof AttachmentOperation.PreparationFailure);
        var selected = ((AttachmentOperation.PreparationFailure) failure).selected();
        equal(true, Files.isRegularFile(selected.get("targetAfter")));
        equal(before.digest(), AttachmentFileStore.observe(request.originalBackup(), HOST, () -> false).digest());
        AttachmentFileStore.unchanged(before, HOST, () -> false);
        equal(false, Files.exists(request.receipt()));
    }

    private static void handoffFailure(Path root, Path seed) throws Exception {
        var request = fixture(root, seed, "handoff-failure");
        var before = AttachmentFileStore.observe(request.target(), HOST, () -> false);
        var failure = reject(() -> AttachmentOperation.execute(request, HOST, VALIDATOR, () -> false,
            boundary -> {
                if (boundary == AttachmentTransaction.Boundary.VERIFIED) throw new IOException("pre-publication handoff failure");
            }));
        equal(true, failure instanceof AttachmentOperation.PreparationFailure);
        equal(true, Files.exists(((AttachmentOperation.PreparationFailure) failure).selected().get("targetAfter")));
        equal(before.digest(), AttachmentFileStore.observe(request.originalBackup(), HOST, () -> false).digest());
        AttachmentFileStore.unchanged(before, HOST, () -> false);
        equal(false, Files.exists(request.receipt()));
    }

    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static IOException reject(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("expected rejection"); }
        catch (IOException expected) { checks++; return expected; }
    }
    private static void equal(Object expected, Object actual) {
        if (!java.util.Objects.equals(expected, actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }
}
