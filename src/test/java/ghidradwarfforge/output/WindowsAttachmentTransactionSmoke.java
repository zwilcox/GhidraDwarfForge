package ghidradwarfforge.output;

import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Native coordinator/recovery fixtures. Sentinel files are not ELF export approvals. */
public final class WindowsAttachmentTransactionSmoke {
    private static int checks;
    private record Fixture(Path root, AttachmentTransaction.Request request,
            Map<String, AttachmentFileStore.Snapshot> snapshots) { }

    public static void main(String[] args) throws Exception {
        if (!System.getProperty("os.name").startsWith("Windows")) throw new IllegalStateException("requires Windows");
        try (var privilege = new WindowsFileSecurityProbe.OwnPrivilege(true)) {
            var host = new WindowsAttachmentHost();
            if (args.length == 3 && args[0].equals("--crash")) {
                child(Path.of(args[1]), AttachmentTransaction.Boundary.valueOf(args[2]), host);
                return;
            }
            if (args.length != 1) throw new IllegalArgumentException("fresh owned result directory required");
            Path root = Files.createDirectory(Path.of(args[0]).toAbsolutePath());
            var outcomes = new ArrayList<Object>();
            var success = fixture(root, "commit", host);
            var committed = AttachmentTransaction.commit(success.request(), host, () -> false);
            require(committed.outcome() == AttachmentReceipt.Phase.COMMITTED, "native commit failed: " + committed.diagnostic());
            require(committed.observedTarget().digest().equals(success.snapshots().get("targetAfter").digest()), "candidate differs");
            retained(success, host);
            outcomes.add(Map.of("case", "commit", "result", committed));

            for (boolean cancel : new boolean[] { false, true }) {
                var failure = fixture(root, cancel ? "cancel" : "rollback", host);
                var cancelled = new AtomicBoolean();
                var reached = new AtomicBoolean();
                var result = AttachmentTransaction.commit(failure.request(), host, cancelled::get, point -> {
                    if (point == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                        reached.set(true);
                        if (cancel) cancelled.set(true);
                        else throw new IOException("owned failure after target replacement");
                    }
                }, AttachmentTransaction.RECEIPTS);
                require(reached.get(), "failure did not reach replacement");
                restored(failure, result, host);
                require(result.cancelled() == cancel, "cancellation status differs");
                outcomes.add(Map.of("case", cancel ? "cancel" : "rollback", "result", result));
            }

            var conflict = fixture(root, "concurrent-target", host);
            var conflicted = AttachmentTransaction.commit(conflict.request(), host, () -> false, point -> {
                if (point == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                    Path target = conflict.request().files().get("targetBefore");
                    Files.move(target, conflict.root().resolve("retained candidate"));
                    Files.writeString(target, "concurrent target sentinel", StandardOpenOption.CREATE_NEW);
                    throw new IOException("owned concurrent-target control");
                }
            }, AttachmentTransaction.RECEIPTS);
            require(conflicted.outcome() == AttachmentReceipt.Phase.RECOVERY_REQUIRED, "concurrent target was not protected");
            require(Files.readString(conflict.request().files().get("targetBefore")).equals("concurrent target sentinel"),
                "rollback changed concurrent target");
            retained(conflict, host);
            outcomes.add(Map.of("case", "concurrent-target", "result", conflicted));

            for (var boundary : new AttachmentTransaction.Boundary[] { AttachmentTransaction.Boundary.PREPARED,
                    AttachmentTransaction.Boundary.TARGET_REPLACED, AttachmentTransaction.Boundary.BEFORE_COMMIT,
                    AttachmentTransaction.Boundary.COMMITTED }) {
                var crash = fixture(root, "crash-" + boundary, host);
                writeSelection(crash);
                Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java.exe").toString(),
                    "--enable-native-access=ALL-UNNAMED", "-cp", System.getProperty("java.class.path"),
                    WindowsAttachmentTransactionSmoke.class.getName(), "--crash", crash.root().toString(), boundary.name())
                    .redirectErrorStream(true).redirectOutput(crash.root().resolve("child.log").toFile()).start();
                try {
                    require(process.waitFor(60, TimeUnit.SECONDS), "owned crash child timed out");
                    require(process.exitValue() == 89, "owned crash child failed: " + Files.readString(crash.root().resolve("child.log")));
                    var receiptBefore = AttachmentReceiptStore.read(crash.request().receipt(), host, () -> false);
                    var recovered = AttachmentTransaction.recoverInterrupted(crash.request(), host);
                    restored(crash, recovered, host);
                    require(receiptBefore.equals(AttachmentReceiptStore.read(crash.request().receipt(), host, () -> false)),
                        "recovery rewrote the original receipt");
                    outcomes.add(Map.of("case", "crash-" + boundary, "originalReceipt", receiptBefore, "result", recovered));
                }
                finally {
                    if (process.isAlive()) {
                        process.destroyForcibly();
                        require(process.waitFor(5, TimeUnit.SECONDS), "owned crash child could not be reaped");
                    }
                }
            }
            var json = new GsonBuilder().registerTypeHierarchyAdapter(Path.class,
                (com.google.gson.JsonSerializer<Path>) (value, type, context) -> new com.google.gson.JsonPrimitive(value.toString()))
                .setPrettyPrinting().create();
            Files.writeString(root.resolve("result.json"), json.toJson(Map.of("checks", checks, "outcomes", outcomes,
                "scope", "Native Windows initial coordinator and process-interruption recovery; no ELF, refresh, public controls or power-loss acceptance")),
                StandardOpenOption.CREATE_NEW);
            System.out.println("windows-attachment-transaction=PASS checks=" + checks + " abrupt-process-exits=4");
        }
    }

    private static Fixture fixture(Path root, String name, WindowsAttachmentHost host) throws IOException {
        Path directory = Files.createDirectory(root.resolve(name));
        Path target = Files.writeString(directory.resolve("target"), "original " + name, StandardOpenOption.CREATE_NEW);
        var snapshots = new LinkedHashMap<String, AttachmentFileStore.Snapshot>();
        var original = AttachmentFileStore.observe(target, host, () -> false);
        snapshots.put("targetBefore", original);
        snapshots.put("originalBackup", AttachmentFileStore.backup(original, directory.resolve("backup"), host, () -> false));
        Path stageParent = Files.createDirectory(directory.resolve("private candidate"));
        Path stage = Files.writeString(stageParent.resolve("image"), "candidate with different bytes " + name, StandardOpenOption.CREATE_NEW);
        try (var output = FileChannel.open(stage, StandardOpenOption.WRITE)) {
            host.preserveMetadata(target, original.fingerprint(), stage);
            output.force(true);
        }
        host.syncDirectory(stageParent);
        snapshots.put("targetAfter", AttachmentFileStore.observe(stage, host, () -> false));
        for (String role : new String[] { "sidecar", "source", "exportReport", "validationEvidence" }) {
            Path file = Files.writeString(directory.resolve(role), "transaction fixture " + role, StandardOpenOption.CREATE_NEW);
            snapshots.put(role, AttachmentFileStore.observe(file, host, () -> false));
        }
        var claims = new LinkedHashMap<String, AttachmentReceipt.Artifact>();
        var paths = new LinkedHashMap<String, Path>();
        for (var entry : snapshots.entrySet()) {
            var artifact = entry.getValue().artifact();
            if (entry.getKey().equals("targetAfter")) artifact = new AttachmentReceipt.Artifact(target.toString(),
                artifact.sha256(), artifact.bytes(), artifact.identity(), artifact.metadataSha256());
            claims.put(entry.getKey(), artifact);
            paths.put(entry.getKey(), entry.getValue().path());
        }
        Path receipt = directory.resolve("transaction.json");
        var prepared = new AttachmentReceipt(UUID.randomUUID().toString(), AttachmentReceipt.Mode.INITIAL,
            AttachmentReceipt.Phase.PREPARED, receipt.toString(), "owned-append-v1", host.contract(), host.durability(),
            snapshots.get("sidecar").digest().gnuDebuglinkCrc32(), claims, null);
        return new Fixture(directory, new AttachmentTransaction.Request(prepared, paths, receipt,
            directory.resolve("recovery.json"), directory.resolve("restore image")), Map.copyOf(snapshots));
    }

    private static void writeSelection(Fixture fixture) throws IOException {
        Files.writeString(fixture.root().resolve("intent.json"), fixture.request().prepared().toJson(), StandardOpenOption.CREATE_NEW);
        var properties = new Properties();
        fixture.request().files().forEach((role, path) -> properties.setProperty(role, path.toString()));
        properties.setProperty("receipt", fixture.request().receipt().toString());
        properties.setProperty("recovery", fixture.request().recoveryReceipt().toString());
        properties.setProperty("restore", fixture.request().restoreImage().toString());
        try (var output = Files.newOutputStream(fixture.root().resolve("selected.properties"), StandardOpenOption.CREATE_NEW)) {
            properties.store(output, "Explicit test-owned paths; not production receipt-selected paths");
        }
    }

    private static void child(Path root, AttachmentTransaction.Boundary boundary, WindowsAttachmentHost host) throws IOException {
        AttachmentReceipt receipt;
        try (var input = Files.newInputStream(root.resolve("intent.json"))) {
            receipt = AttachmentReceipt.read(input, () -> false);
        }
        var selected = new Properties();
        try (var input = Files.newInputStream(root.resolve("selected.properties"))) { selected.load(input); }
        var files = new LinkedHashMap<String, Path>();
        for (String role : receipt.files().keySet()) files.put(role, Path.of(selected.getProperty(role)));
        var request = new AttachmentTransaction.Request(receipt, files, Path.of(selected.getProperty("receipt")),
            Path.of(selected.getProperty("recovery")), Path.of(selected.getProperty("restore")));
        AttachmentTransaction.commit(request, host, () -> false, point -> {
            if (point == boundary) Runtime.getRuntime().halt(89);
        }, AttachmentTransaction.RECEIPTS);
        throw new AssertionError("selected process-exit boundary was not reached");
    }

    private static void restored(Fixture fixture, AttachmentTransaction.Result result, WindowsAttachmentHost host) throws IOException {
        require(result.outcome() == AttachmentReceipt.Phase.ROLLED_BACK, "rollback failed: " + result.diagnostic());
        require(result.observedTarget().digest().equals(fixture.snapshots().get("targetBefore").digest()), "restored bytes differ");
        require(result.observedTarget().fingerprint().metadataSha256().equals(
            fixture.snapshots().get("targetBefore").fingerprint().metadataSha256()), "restored metadata differs");
        require(result.recoveryReceipt().receipt().phase() == AttachmentReceipt.Phase.ROLLED_BACK, "missing recovery outcome");
        retained(fixture, host);
    }

    private static void retained(Fixture fixture, WindowsAttachmentHost host) throws IOException {
        for (String role : new String[] { "originalBackup", "sidecar", "source", "exportReport", "validationEvidence" }) {
            AttachmentFileStore.unchanged(fixture.snapshots().get(role), host, () -> false);
            checks++;
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
