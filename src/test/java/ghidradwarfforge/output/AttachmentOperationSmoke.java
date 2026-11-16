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
import java.util.List;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
        public byte[] debuglinkBasename(Path sidecar) throws IOException {
            return DebuglinkBasename.linuxUtf8(sidecar);
        }
        public void replaceAtomic(Path stage, Path target) throws IOException {
            new LinuxAtomicRename().replaceAtomic(stage, target);
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
            savedSelectionFailure(root, seed);
            validationFailures(root, seed);
            preflight(root, seed);
            basenameRefusal(root, seed);
            metadataFailure(root, seed);
            handoffFailure(root, seed);
            refreshRefusals(root, seed);
            reusedBasenames(root, seed);
            discoveryAndParentChanges(root, seed);
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
        var initial = executeWithRecoverySelection(first, boundary -> { });
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
        var result = executeWithRecoverySelection(second, boundary -> {
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

    private static AttachmentOperation.Result executeWithRecoverySelection(AttachmentOperation.Request request,
            AttachmentTransaction.Hook hook) throws IOException {
        Path saved = request.receipt().resolveSibling(request.receipt().getFileName() + ".recovery-request.json");
        var original = AttachmentFileStore.observe(request.target(), HOST, () -> false);
        var result = AttachmentOperation.execute(request, HOST, VALIDATOR, () -> false, hook, prepared -> {
            AttachmentFileStore.unchanged(original, HOST, () -> false);
            equal(false, Files.exists(request.receipt()));
            AttachmentRecoveryFile.publish(saved, prepared, HOST, () -> false);
            equal(false, Files.exists(request.receipt()));
            AttachmentFileStore.unchanged(original, HOST, () -> false);
        });
        var selected = AttachmentRecoveryInvocation.read(Files.newInputStream(saved), () -> false);
        equal(result.recoveryRequest(), selected.transaction(() -> false));
        equal(true, selected.acceptsReceiptSha256(AttachmentReceiptStore.read(request.receipt(), HOST, () -> false).sha256()));
        var retained = AttachmentFileStore.observe(saved, HOST, () -> false);
        try {
            AttachmentRecoveryFile.publish(saved, result.recoveryRequest(), HOST, () -> false);
            throw new AssertionError("recovery selection overwritten");
        }
        catch (IOException expected) { checks++; }
        AttachmentFileStore.unchanged(retained, HOST, () -> false);
        return result;
    }

    private static void savedSelectionFailure(Path root, Path seed) throws Exception {
        var request = fixture(root, seed, "recovery-selection-refusal");
        var original = AttachmentFileStore.observe(request.target(), HOST, () -> false);
        Path saved = Files.writeString(request.target().resolveSibling("existing-recovery.json"), "owned prior document");
        var previous = AttachmentFileStore.observe(saved, HOST, () -> false);
        try {
            AttachmentOperation.execute(request, HOST, VALIDATOR, () -> false, boundary -> { },
                prepared -> AttachmentRecoveryFile.publish(saved, prepared, HOST, () -> false));
            throw new AssertionError("transaction proceeded without a durable recovery selection");
        }
        catch (AttachmentOperation.PreparationFailure expected) { checks++; }
        AttachmentFileStore.unchanged(original, HOST, () -> false);
        AttachmentFileStore.unchanged(previous, HOST, () -> false);
        equal(false, Files.exists(request.receipt()));
        equal(original.digest(), AttachmentFileStore.observe(request.originalBackup(), HOST, () -> false).digest());
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

    private static void basenameRefusal(Path root, Path seed) throws Exception {
        for (boolean portable : new boolean[]{false, true}) {
            Path directory = Files.createDirectory(root.resolve("basename-" + portable));
            Path target = directory.resolve("target.elf");
            Files.copy(seed, target, StandardCopyOption.COPY_ATTRIBUTES);
            var request = exported(directory, target, target, portable ? "literal λ" : "bad\nname", null);
            var calls = new AtomicInteger();
            var host = new Host() {
                @Override public byte[] debuglinkBasename(Path sidecar) throws IOException {
                    calls.incrementAndGet();
                    return portable ? DebuglinkBasename.portableAscii(sidecar) : DebuglinkBasename.linuxUtf8(sidecar);
                }
            };
            java.util.List<AttachmentFileStore.Snapshot> before;
            try (var paths = Files.list(directory)) {
                before = paths.sorted().map(path -> {
                    try { return AttachmentFileStore.observe(path, HOST, () -> false); }
                    catch (IOException failure) { throw new java.io.UncheckedIOException(failure); }
                }).toList();
            }
            var failure = reject(() -> AttachmentOperation.execute(request, host,
                (binding, evidence, selectedHost, cancelled) -> { throw new AssertionError("unsupported basename reached validator"); },
                () -> false));
            equal(true, failure.getMessage().contains(portable ? "portable ASCII" : "control character"));
            equal(1, calls.get());
            for (var snapshot : before) AttachmentFileStore.unchanged(snapshot, HOST, () -> false);
            try (var paths = Files.list(directory)) {
                equal(before.stream().map(AttachmentFileStore.Snapshot::path).toList(), paths.sorted().toList());
            }
        }
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

    private static void refreshRefusals(Path root, Path seed) throws Exception {
        for (String fault : List.of("phase", "target-path", "target-sha", "target-bytes", "target-metadata",
                "originalBackup", "sidecar", "source", "crc", "program-bytes", "debuglink", "allocation",
                "bundle-input", "valid-bundle")) {
            var first = fixture(root, seed, "refresh-refusal-" + fault);
            equal(AttachmentReceipt.Phase.COMMITTED, AttachmentOperation.execute(first, HOST, VALIDATOR, () -> false).transaction().outcome());
            JsonObject receipt = JsonParser.parseString(Files.readString(first.receipt())).getAsJsonObject();
            var files = receipt.getAsJsonObject("files");
            String expected;
            switch (fault) {
                case "phase" -> {
                    receipt.addProperty("phase", "PREPARED");
                    expected = "requires a committed receipt";
                }
                case "target-path" -> {
                    files.getAsJsonObject("targetBefore").addProperty("path", root.resolve("different-target").toString());
                    files.getAsJsonObject("targetAfter").addProperty("path", root.resolve("different-target").toString());
                    expected = "current target differs";
                }
                case "target-sha", "target-bytes" -> {
                    files.getAsJsonObject("targetAfter").addProperty(fault.equals("target-sha") ? "sha256" : "bytes",
                        fault.equals("target-sha") ? "9".repeat(64) : "1");
                    expected = "current target differs";
                }
                case "target-metadata" -> {
                    for (String role : List.of("targetBefore", "targetAfter", "originalBackup")) {
                        files.getAsJsonObject(role).addProperty("metadataSha256", "9".repeat(64));
                    }
                    expected = "current target differs";
                }
                case "originalBackup", "sidecar", "source" -> {
                    files.getAsJsonObject(fault).addProperty("identity", "different-retained-file");
                    expected = "retained artifact differs";
                }
                case "crc" -> {
                    receipt.addProperty("debuglinkCrc32", receipt.get("debuglinkCrc32").getAsLong() ^ 1);
                    expected = "previous ELF/debuglink association differs";
                }
                case "program-bytes", "debuglink", "allocation" -> {
                    alterAttachedElf(first.target(), fault);
                    files.add("targetAfter", artifactJson(AttachmentFileStore.observe(first.target(), HOST, () -> false).artifact()));
                    expected = "previous ELF/debuglink association differs";
                }
                case "bundle-input", "valid-bundle" -> {
                    String input = fault.equals("bundle-input") ? "9".repeat(64) : ExportArtifactHashBindingFixtures.hash(first.originalBackup());
                    Files.delete(first.source());
                    var bundle = SourceBundle.prepare(input, first.source().getFileName().toString(), SourceBundleSmoke.fixture(), 3, () -> false);
                    SourceBundleStore.install(first.source(), bundle, List.of(), () -> false);
                    Files.write(first.source(), bundle.indexBytes(() -> false), StandardOpenOption.CREATE_NEW);
                    files.add("source", artifactJson(AttachmentFileStore.observe(first.source(), HOST, () -> false).artifact()));
                    expected = "previous source bundle differs from the original backup";
                }
                default -> throw new AssertionError(fault);
            }
            // These are deliberately supplied previous-record claims, not a
            // claim that a real validator approved the altered first generation.
            Files.writeString(first.receipt(), receipt.toString());
            AttachmentReceipt.read(first.receipt(), () -> false);
            var refresh = new AttachmentOperation.Refresh(first.receipt(), first.sidecar(), first.source(),
                first.target().resolveSibling("prior-target.backup"));
            var second = exported(first.target().getParent(), first.target(), first.originalBackup(), "second", refresh);
            var before = snapshots(first.target().getParent());
            if (fault.equals("valid-bundle")) {
                equal(AttachmentReceipt.Phase.COMMITTED, AttachmentOperation.execute(second, HOST, VALIDATOR, () -> false).transaction().outcome());
                for (var item : before) {
                    if (!item.path().equals(first.target())) AttachmentFileStore.unchanged(item, HOST, () -> false);
                }
            }
            else {
                var failure = reject(() -> AttachmentOperation.execute(second, HOST,
                    (binding, evidence, host, cancelled) -> { throw new AssertionError("unsafe refresh reached validator: " + fault); }, () -> false));
                equal(true, failure.getMessage().contains(expected));
                for (var item : before) AttachmentFileStore.unchanged(item, HOST, () -> false);
                equal(before.stream().map(AttachmentFileStore.Snapshot::path).toList(), snapshots(first.target().getParent()).stream()
                    .map(AttachmentFileStore.Snapshot::path).toList());
                equal(false, Files.exists(second.receipt()));
                equal(false, Files.exists(refresh.priorTargetBackup()));
                equal(false, Files.exists(second.validationEvidence()));
            }
        }
    }

    private static JsonObject artifactJson(AttachmentReceipt.Artifact artifact) {
        JsonObject json = new JsonObject();
        json.addProperty("path", artifact.path());
        json.addProperty("sha256", artifact.sha256());
        json.addProperty("bytes", Long.toString(artifact.bytes()));
        json.addProperty("identity", artifact.identity());
        json.addProperty("metadataSha256", artifact.metadataSha256());
        return json;
    }

    private static List<AttachmentFileStore.Snapshot> snapshots(Path directory) throws IOException {
        try (var children = Files.walk(directory)) {
            var result = new java.util.ArrayList<AttachmentFileStore.Snapshot>();
            for (Path child : children.filter(Files::isRegularFile).sorted().toList()) {
                result.add(AttachmentFileStore.observe(child, HOST, () -> false));
            }
            return List.copyOf(result);
        }
    }

    private static void alterAttachedElf(Path path, String fault) throws Exception {
        byte[] bytes = Files.readAllBytes(path);
        // This fixture is explicitly compiled as x86-64 ELF64 little-endian.
        // The mutation uses independently decoded section headers, not a writer.
        equal((byte) 2, bytes[4]);
        equal((byte) 1, bytes[5]);
        ByteBuffer header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        int table = Math.toIntExact(header.getLong(40)), stride = Short.toUnsignedInt(header.getShort(58));
        int names = Math.toIntExact(header.getLong(table + stride * Short.toUnsignedInt(header.getShort(62)) + 24));
        String wanted = fault.equals("debuglink") ? ".gnu_debuglink" : ".text";
        int selected = -1;
        for (int index = 1; index < Short.toUnsignedInt(header.getShort(60)); index++) {
            int entry = table + index * stride, start = names + header.getInt(entry), end = start;
            while (bytes[end] != 0) end++;
            if (new String(bytes, start, end - start, StandardCharsets.UTF_8).equals(wanted)) selected = entry;
        }
        if (selected < 0) throw new AssertionError("fixture lacks " + wanted);
        if (fault.equals("allocation")) header.putLong(selected + 16, header.getLong(selected + 16) + 1);
        else bytes[Math.toIntExact(header.getLong(selected + 24))] ^= 1;
        var timestamp = Files.getLastModifiedTime(path);
        Files.write(path, bytes);
        Files.setLastModifiedTime(path, timestamp);
    }

    private static void discoveryAndParentChanges(Path root, Path seed) throws Exception {
        var first = fixture(root, seed, "existing-association");
        AttachmentOperation.execute(first, HOST, VALIDATOR, () -> false);
        var initialAgain = exported(first.target().getParent(), first.target(), first.target(), "again", null);
        initialAgain = new AttachmentOperation.Request(initialAgain.target(), initialAgain.sidecar(), initialAgain.source(), initialAgain.exportReport(),
            first.target().resolveSibling("new.backup"), initialAgain.validationEvidence(), initialAgain.receipt(),
            initialAgain.recoveryReceipt(), initialAgain.restoreImage(), null);
        var selected = initialAgain;
        var before = snapshots(first.target().getParent());
        var failure = reject(() -> AttachmentOperation.execute(selected, HOST,
            (binding, evidence, host, cancelled) -> { throw new AssertionError("implicit refresh reached validation"); }, () -> false));
        equal(true, failure.getMessage().contains("initial attachment cannot replace an existing association"));
        for (var item : before) AttachmentFileStore.unchanged(item, HOST, () -> false);

        var request = fixture(root, seed, "parent-identity");
        var original = AttachmentFileStore.observe(request.target(), HOST, () -> false);
        try {
            AttachmentOperation.execute(request, HOST,
                (binding, evidence, host, cancelled) -> { throw new AssertionError("cancelled operation reached validation"); }, () -> true);
            throw new AssertionError("initial cancellation ignored");
        }
        catch (CancellationException expected) { checks++; }
        AttachmentFileStore.unchanged(original, HOST, () -> false);
        equal(false, Files.exists(request.validationEvidence()));
        Path parent = request.target().getParent(), retained = parent.resolveSibling("retained-parent");
        failure = reject(() -> AttachmentOperation.execute(request, HOST, (binding, evidence, host, cancelled) -> {
            VALIDATOR.validate(binding, evidence, host, cancelled);
            Files.move(parent, retained);
            Files.createDirectory(parent);
            try (var children = Files.list(retained)) {
                for (Path child : children.toList()) Files.move(child, parent.resolve(child.getFileName()));
            }
            Files.writeString(retained.resolve("sentinel"), "retained original directory");
        }, () -> false));
        equal(true, failure instanceof AttachmentOperation.PreparationFailure);
        equal(true, failure.getCause().getMessage().contains("output parent identity changed"));
        AttachmentFileStore.unchanged(original, HOST, () -> false);
        equal("retained original directory", Files.readString(retained.resolve("sentinel")));
        equal(false, Files.exists(request.receipt()));
        equal(false, Files.exists(request.originalBackup()));

        var location = fixture(root, seed, "sidecar-location");
        Path elsewhere = Files.createDirectory(location.target().getParent().resolve("elsewhere"));
        Path sidecar = Files.move(location.sidecar(), elsewhere.resolve(location.sidecar().getFileName()));
        var moved = new AttachmentOperation.Request(location.target(), sidecar, location.source(), location.exportReport(),
            location.originalBackup(), location.validationEvidence(), location.receipt(), location.recoveryReceipt(), location.restoreImage(), null);
        failure = reject(() -> AttachmentOperation.preflightPaths(moved));
        equal(true, failure.getMessage().contains("beside the target or in its .debug directory"));
        Path debug = Files.createDirectory(location.target().getParent().resolve(".debug"));
        sidecar = Files.move(sidecar, debug.resolve(sidecar.getFileName()));
        var allowed = new AttachmentOperation.Request(location.target(), sidecar, location.source(), location.exportReport(),
            location.originalBackup(), location.validationEvidence(), location.receipt(), location.recoveryReceipt(), location.restoreImage(), null);
        var plan = AttachmentOperation.preflightPaths(allowed);
        equal(location.sidecar(), plan.paths().get("discoveryShadow"));
        plan.recheck();
    }

    private static void reusedBasenames(Path root, Path seed) throws Exception {
        for (boolean sidecar : List.of(false, true)) {
            var first = fixture(root, seed, "reused-basename-" + sidecar);
            Path directory = first.target().getParent();
            if (sidecar) {
                Path debug = Files.createDirectory(directory.resolve(".debug"));
                first = selectPair(first, Files.move(first.sidecar(), debug.resolve(first.sidecar().getFileName())), first.source());
            }
            equal(AttachmentReceipt.Phase.COMMITTED, AttachmentOperation.execute(first, HOST, VALIDATOR, () -> false).transaction().outcome());
            var refresh = new AttachmentOperation.Refresh(first.receipt(), first.sidecar(), first.source(), directory.resolve("prior-target.backup"));
            var second = exported(directory, first.target(), first.originalBackup(), "second", refresh);
            if (sidecar) {
                second = selectPair(second, Files.move(second.sidecar(), directory.resolve(first.sidecar().getFileName())), second.source());
            }
            else {
                Path sources = Files.createDirectory(directory.resolve("new-sources"));
                second = selectPair(second, second.sidecar(), Files.move(second.source(), sources.resolve(first.source().getFileName())));
            }
            var before = snapshots(directory);
            var selected = second;
            var failure = reject(() -> AttachmentOperation.execute(selected, HOST,
                (binding, evidence, host, cancelled) -> { throw new AssertionError("reused basename reached validator"); }, () -> false));
            equal(true, failure.getMessage().contains("fresh source and sidecar basename"));
            for (var item : before) AttachmentFileStore.unchanged(item, HOST, () -> false);
            equal(before.stream().map(AttachmentFileStore.Snapshot::path).toList(), snapshots(directory).stream()
                .map(AttachmentFileStore.Snapshot::path).toList());
        }
    }

    private static AttachmentOperation.Request selectPair(AttachmentOperation.Request request, Path sidecar, Path source) throws Exception {
        ExportArtifactHashBindingFixtures.write(new ExportArtifactHashBindingFixtures.Pair(request.target().getParent(),
            request.exportReport(), request.refresh() == null ? request.target() : request.originalBackup(), sidecar, source), true);
        return new AttachmentOperation.Request(request.target(), sidecar, source, request.exportReport(), request.originalBackup(),
            request.validationEvidence(), request.receipt(), request.recoveryReceipt(), request.restoreImage(), request.refresh());
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
