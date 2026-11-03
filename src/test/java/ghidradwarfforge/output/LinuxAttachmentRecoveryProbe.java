package ghidradwarfforge.output;

import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/** Owned sentinel coordinator fixtures; no ELF/validator approval is inferred. */
public final class LinuxAttachmentRecoveryProbe {
    private record Fixture(Path root, AttachmentTransaction.Request request,
            Map<String, AttachmentFileStore.Snapshot> snapshots) { }

    public static void main(String[] args) throws Exception {
        if (args.length == 3 && args[0].equals("--crash")) {
            var request = selected(Path.of(args[1]));
            var boundary = AttachmentTransaction.Boundary.valueOf(args[2]);
            try (var host = LinuxAttachmentHost.openPrepared(request, () -> false)) {
                AttachmentTransaction.commit(request, host, () -> false, point -> {
                    if (point == boundary) Runtime.getRuntime().halt(89);
                }, AttachmentTransaction.RECEIPTS);
            }
            throw new AssertionError("crash boundary was not reached");
        }
        if (args.length != 1) throw new IllegalArgumentException("new owned result directory required");
        Path root = Files.createDirectory(Path.of(args[0]).toAbsolutePath());
        Path scope = Files.createDirectory(root.resolve("scope"));
        // Explicit disposable selections establish the shared fixture-building
        // session. Each prepared commit/recovery gets its own full preflight.
        for (String name : new String[] { "target", "sidecar", "source", "report" }) Files.writeString(scope.resolve(name), name);
        var initial = new AttachmentOperation.Request(scope.resolve("target"), scope.resolve("sidecar"),
            scope.resolve("source"), scope.resolve("report"), scope.resolve("backup"), scope.resolve("validation"),
            scope.resolve("receipt"), scope.resolve("recovery"), scope.resolve("restore"), null);
        var outcomes = new ArrayList<Object>();
        try (var host = LinuxAttachmentHost.open(initial, () -> false)) {
            for (boolean refresh : new boolean[] { false, true }) {
                for (var boundary : new AttachmentTransaction.Boundary[] { AttachmentTransaction.Boundary.PREPARED,
                        AttachmentTransaction.Boundary.TARGET_REPLACED, AttachmentTransaction.Boundary.BEFORE_COMMIT,
                        AttachmentTransaction.Boundary.COMMITTED }) {
                    Path directory = Files.createDirectory(root.resolve((refresh ? "refresh-" : "initial-") + boundary));
                    Fixture fixture = fixture(directory, host, refresh);
                    writeSelection(fixture);
                    var child = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                        "--enable-native-access=ALL-UNNAMED", "-cp", System.getProperty("java.class.path"),
                        LinuxAttachmentRecoveryProbe.class.getName(), "--crash", fixture.root().toString(), boundary.name())
                        .redirectErrorStream(true).redirectOutput(fixture.root().resolve("child.log").toFile()).start();
                    try {
                        require(child.waitFor(60, TimeUnit.SECONDS), "crash child timed out");
                        require(child.exitValue() == 89, "crash child failed: " + Files.readString(fixture.root().resolve("child.log")));
                    }
                    finally {
                        if (child.isAlive()) {
                            child.destroyForcibly();
                            require(child.waitFor(5, TimeUnit.SECONDS), "crash child could not be reaped");
                        }
                    }
                    try (var recoveryHost = LinuxAttachmentHost.openRecovery(fixture.request())) {
                        var before = AttachmentReceiptStore.read(fixture.request().receipt(), recoveryHost, () -> false);
                        var selectedPaths = new java.util.TreeMap<>(fixture.request().files());
                        selectedPaths.put("receipt", fixture.request().receipt());
                        selectedPaths.put("recoveryReceipt", fixture.request().recoveryReceipt());
                        selectedPaths.put("restoreImage", fixture.request().restoreImage());
                        var invocation = new AttachmentRecoveryInvocation(selectedPaths, before.sha256());
                        Path requestFile = Files.writeString(directory.resolve("helper-recovery-request.json"), invocation.toJson(),
                            StandardOpenOption.CREATE_NEW);
                        Path helperOutput = directory.resolve("helper-recovery.stdout");
                        var recoveryChild = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                            "--enable-native-access=ALL-UNNAMED", "-cp", System.getProperty("java.class.path"),
                            AttachmentHelper.class.getName(), "--recover", "--request", requestFile.toString(),
                            "--request-sha256", FileDigests.read(requestFile, () -> false).sha256(), "--confirm-target-change")
                            .redirectOutput(helperOutput.toFile()).redirectError(directory.resolve("helper-recovery.stderr").toFile()).start();
                        try {
                            require(recoveryChild.waitFor(60, TimeUnit.SECONDS), "recovery helper timeout");
                            require(recoveryChild.exitValue() == 0, "recovery helper failed: " + Files.readString(helperOutput));
                        }
                        finally {
                            if (recoveryChild.isAlive()) {
                                recoveryChild.destroyForcibly();
                                require(recoveryChild.waitFor(5, TimeUnit.SECONDS), "recovery helper could not be reaped");
                            }
                        }
                        require(Files.size(directory.resolve("helper-recovery.stderr")) == 0, "unexplained helper stderr");
                        var response = com.google.gson.JsonParser.parseString(Files.readString(helperOutput)).getAsJsonObject();
                        require(response.get("outcome").getAsString().equals("ROLLED_BACK") &&
                            response.get("exitCode").getAsInt() == 0, "recovery helper did not report restoration");
                        var recoveryRecord = AttachmentReceiptStore.read(fixture.request().recoveryReceipt(), recoveryHost, () -> false);
                        require(response.get("recoveryReceipt").equals(com.google.gson.JsonParser.parseString(recoveryRecord.receipt().toJson())),
                            "reported recovery record differs from actual durable receipt");
                        var recovered = new AttachmentTransaction.Result(recoveryRecord.receipt().phase(), before, recoveryRecord,
                            AttachmentFileStore.observe(fixture.request().files().get("targetBefore"), recoveryHost, () -> false),
                            false, recoveryRecord.receipt().diagnostic());
                        require(recovered.outcome() == AttachmentReceipt.Phase.ROLLED_BACK, "recovery failed: " + recovered.diagnostic());
                        var prior = fixture.snapshots().get("targetBefore");
                        require(recovered.observedTarget().digest().equals(prior.digest()), "recovered bytes differ");
                        require(recovered.observedTarget().fingerprint().metadataSha256().equals(prior.fingerprint().metadataSha256()),
                            "recovered metadata differs");
                        require(before.equals(AttachmentReceiptStore.read(fixture.request().receipt(), recoveryHost, () -> false)),
                            "interrupted receipt changed");
                        for (var entry : fixture.snapshots().entrySet()) {
                            if (!entry.getKey().equals("targetBefore") && !entry.getKey().equals("targetAfter")) {
                                AttachmentFileStore.unchanged(entry.getValue(), recoveryHost, () -> false);
                            }
                        }
                        outcomes.add(Map.of("case", directory.getFileName().toString(), "childExit", 89,
                            "prior", prior, "interruptedReceipt", before, "result", recovered));
                        Files.writeString(root.resolve("progress.json"), json(outcomes));
                    }
                }
            }
        }
        // Abrupt children deliberately leave their own canaries. Retain them
        // as crash evidence; successful parent/recovery sessions must close.
        long canaries;
        try (var paths = Files.walk(root)) {
            canaries = paths.filter(path -> path.getFileName().toString().startsWith(".forge-visibility-")).count();
        }
        require(canaries == 8, "unexpected visibility workspace lifecycle after eight crashes");
        Files.writeString(root.resolve("result.json"), json(Map.of("outcomes", outcomes,
            "retainedCrashCanaries", canaries, "host", "production-linux", "elfValidation", false)), StandardOpenOption.CREATE_NEW);
        System.out.println("linux-attachment-recovery=PASS cases=8 abrupt-exits=8");
    }

    private static Fixture fixture(Path directory, LinuxAttachmentHost host, boolean refresh) throws IOException {
        var snapshots = new LinkedHashMap<String, AttachmentFileStore.Snapshot>();
        if (refresh) {
            var previous = fixture(Files.createDirectory(directory.resolve("first")), host, false);
            var committed = AttachmentTransaction.commit(previous.request(), host, () -> false);
            require(committed.outcome() == AttachmentReceipt.Phase.COMMITTED, "refresh prerequisite failed");
            snapshots.put("targetBefore", committed.observedTarget());
            snapshots.put("originalBackup", previous.snapshots().get("originalBackup"));
            snapshots.put("priorTargetBackup", AttachmentFileStore.backup(committed.observedTarget(), directory.resolve("prior.backup"), host, () -> false));
            snapshots.put("previousReceipt", AttachmentFileStore.observe(previous.request().receipt(), host, () -> false));
            snapshots.put("previousSidecar", previous.snapshots().get("sidecar"));
            snapshots.put("previousSource", previous.snapshots().get("source"));
        }
        else {
            Path target = Files.writeString(directory.resolve("target"), "original fixture " + directory.getFileName());
            var before = AttachmentFileStore.observe(target, host, () -> false);
            snapshots.put("targetBefore", before);
            snapshots.put("originalBackup", AttachmentFileStore.backup(before, directory.resolve("backup"), host, () -> false));
        }
        var before = snapshots.get("targetBefore");
        Path candidate = Files.writeString(directory.resolve("candidate"), "candidate " + directory.getFileName());
        host.preserveMetadata(before.path(), before.fingerprint(), candidate);
        try (var file = java.nio.channels.FileChannel.open(candidate, StandardOpenOption.WRITE)) { file.force(true); }
        host.syncDirectory(directory);
        snapshots.put("targetAfter", AttachmentFileStore.observe(candidate, host, () -> false));
        for (String role : new String[] { "sidecar", "source", "exportReport", "validationEvidence" }) {
            Path file = Files.writeString(directory.resolve(role), directory.getFileName() + " " + role);
            snapshots.put(role, AttachmentFileStore.observe(file, host, () -> false));
        }
        if (refresh) require(snapshots.get("sidecar").digest().gnuDebuglinkCrc32() !=
            snapshots.get("previousSidecar").digest().gnuDebuglinkCrc32(), "refresh did not change CRC");
        var claims = new LinkedHashMap<String, AttachmentReceipt.Artifact>();
        var files = new LinkedHashMap<String, Path>();
        for (var entry : snapshots.entrySet()) {
            var artifact = entry.getValue().artifact();
            if (entry.getKey().equals("targetAfter")) artifact = new AttachmentReceipt.Artifact(before.path().toString(),
                artifact.sha256(), artifact.bytes(), artifact.identity(), artifact.metadataSha256());
            claims.put(entry.getKey(), artifact); files.put(entry.getKey(), entry.getValue().path());
        }
        Path receipt = directory.resolve("transaction.json");
        var prepared = new AttachmentReceipt(UUID.randomUUID().toString(), refresh ? AttachmentReceipt.Mode.REFRESH : AttachmentReceipt.Mode.INITIAL,
            AttachmentReceipt.Phase.PREPARED, receipt.toString(), "owned-append-v1", host.contract(), host.durability(),
            snapshots.get("sidecar").digest().gnuDebuglinkCrc32(), claims, null);
        return new Fixture(directory, new AttachmentTransaction.Request(prepared, files, receipt,
            directory.resolve("recovery.json"), directory.resolve("restore")), Map.copyOf(snapshots));
    }

    private static void writeSelection(Fixture fixture) throws IOException {
        Files.writeString(fixture.root().resolve("intent.json"), fixture.request().prepared().toJson());
        var paths = new Properties();
        fixture.request().files().forEach((role, path) -> paths.setProperty(role, path.toString()));
        paths.setProperty("receipt", fixture.request().receipt().toString());
        paths.setProperty("recovery", fixture.request().recoveryReceipt().toString());
        paths.setProperty("restore", fixture.request().restoreImage().toString());
        try (var output = Files.newOutputStream(fixture.root().resolve("selected.properties"))) { paths.store(output, "owned test selections"); }
    }

    private static AttachmentTransaction.Request selected(Path directory) throws IOException {
        var receipt = AttachmentReceipt.read(directory.resolve("intent.json"), () -> false);
        var paths = new Properties();
        try (var input = Files.newInputStream(directory.resolve("selected.properties"))) { paths.load(input); }
        var files = new LinkedHashMap<String, Path>();
        for (String role : receipt.files().keySet()) files.put(role, Path.of(paths.getProperty(role)));
        return new AttachmentTransaction.Request(receipt, files, Path.of(paths.getProperty("receipt")),
            Path.of(paths.getProperty("recovery")), Path.of(paths.getProperty("restore")));
    }

    private static String json(Object value) {
        return new GsonBuilder().registerTypeHierarchyAdapter(Path.class,
            (com.google.gson.JsonSerializer<Path>) (path, type, context) -> new com.google.gson.JsonPrimitive(path.toString()))
            .setPrettyPrinting().create().toJson(value);
    }
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
