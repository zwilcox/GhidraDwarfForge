package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AttachmentProtocolSmoke {
    private static final String BEFORE = "a".repeat(64);
    private static final String AFTER = "b".repeat(64);
    private static final String METADATA = "c".repeat(64);
    private static int checks;

    public static void main(String[] args) throws Exception {
        receipts();
        Path root = Files.createTempDirectory("forge-attachment-protocol-");
        try {
            paths(root);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
        System.out.println("attachment-protocol-smoke=PASS checks=" + checks);
    }

    static AttachmentReceipt fixture(AttachmentReceipt.Mode mode) {
        Map<String, AttachmentReceipt.Artifact> files = new HashMap<>();
        for (String role : List.of("targetBefore", "targetAfter", "originalBackup", "sidecar",
                "source", "exportReport", "validationEvidence")) {
            files.put(role, artifact(role.equals("targetAfter") ? "targetBefore" : role,
                role.equals("targetAfter") ? AFTER : BEFORE, role));
        }
        if (mode == AttachmentReceipt.Mode.REFRESH) {
            for (String role : List.of("previousReceipt", "previousSidecar", "previousSource", "priorTargetBackup")) {
                files.put(role, artifact(role, BEFORE, role));
            }
        }
        return new AttachmentReceipt("12345678-1234-4234-8234-123456789abc", mode,
            AttachmentReceipt.Phase.PREPARED, "/owned/receipt.json", "forge-owned-append-v1",
            "test-host-v1", "test-only-no-durability", 0xffff_ffffL, files, null);
    }

    private static AttachmentReceipt.Artifact artifact(String name, String hash, String identity) {
        return new AttachmentReceipt.Artifact("/owned/" + name, hash, Long.MAX_VALUE, identity, METADATA);
    }

    private static AttachmentReceipt read(String value) throws IOException {
        return AttachmentReceipt.read(new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8)), () -> false);
    }

    private static void receipts() throws Exception {
        for (var mode : AttachmentReceipt.Mode.values()) {
            AttachmentReceipt prepared = fixture(mode);
            equal(prepared, read(prepared.toJson()));
            equal(prepared.toJson(), read(prepared.toJson()).toJson());
            equal(prepared, read(prepared.toJson().replace("\"schemaVersion\":2", "\"schemaVersion\":1")
                .replace(",\"recovery\":null", "")));
            var recovery = prepared.forRecovery("/owned/recovery.json", artifact("receipt.json", BEFORE, "receipt-id"),
                prepared.files().get("targetBefore"));
            equal(recovery, read(recovery.toJson()));
            equal(recovery.advance(AttachmentReceipt.Phase.ROLLED_BACK, "verified prior image"),
                read(recovery.advance(AttachmentReceipt.Phase.ROLLED_BACK, "verified prior image").toJson()));
            rejectState(() -> recovery.advance(AttachmentReceipt.Phase.COMMITTED, null));
            var unknown = prepared.forRecovery("/owned/recovery.json", artifact("receipt.json", BEFORE, "receipt-id"), null);
            rejectArgument(() -> unknown.advance(AttachmentReceipt.Phase.ROLLED_BACK, "no observation"));
            equal(unknown.advance(AttachmentReceipt.Phase.RECOVERY_REQUIRED, "target unreadable"),
                read(unknown.advance(AttachmentReceipt.Phase.RECOVERY_REQUIRED, "target unreadable").toJson()));
            rejectArgument(() -> prepared.forRecovery("/owned/recovery.json", artifact("receipt.json", BEFORE, "receipt-id"),
                prepared.files().get("targetAfter")).advance(AttachmentReceipt.Phase.ROLLED_BACK, "wrong image"));
            for (String malformed : List.of(
                    recovery.toJson().replace("\"schemaVersion\":2", "\"schemaVersion\":1"),
                    recovery.toJson().replace("\"observedTarget\"", "\"unknownObservation\""),
                    recovery.toJson().replace("\"observedTarget\":", "\"priorReceipt\":"),
                    recovery.toJson().replace("/owned/receipt.json", "/owned/originalBackup"))) {
                rejectIO(() -> read(malformed));
            }
            for (var phase : List.of(AttachmentReceipt.Phase.COMMITTED,
                    AttachmentReceipt.Phase.ROLLED_BACK, AttachmentReceipt.Phase.RECOVERY_REQUIRED)) {
                var next = prepared.advance(phase, phase == AttachmentReceipt.Phase.COMMITTED ? null : "owned failure");
                equal(next, read(next.toJson()));
                if (phase != AttachmentReceipt.Phase.RECOVERY_REQUIRED) {
                    rejectState(() -> next.advance(AttachmentReceipt.Phase.ROLLED_BACK, "forbidden"));
                }
                else {
                    equal(AttachmentReceipt.Phase.ROLLED_BACK,
                        next.advance(AttachmentReceipt.Phase.ROLLED_BACK, "recovered").phase());
                    rejectState(() -> next.advance(AttachmentReceipt.Phase.COMMITTED, null));
                }
            }
            rejectState(() -> prepared.advance(AttachmentReceipt.Phase.PREPARED, null));
            String json = prepared.toJson();
            for (String malformed : List.of(
                    json.replace("\"schemaVersion\":2", "\"schemaVersion\":3"),
                    json.replace("\"schemaVersion\":2", "\"schemaVersion\":2,\"schemaVersion\":2"),
                    json.replace("\"bytes\":\"9223372036854775807\"", "\"bytes\":9223372036854775807"),
                    json.replace("9223372036854775807", "9223372036854775808"),
                    json.replace("9223372036854775807", "01"),
                    json.replace("\"diagnostic\":null", "\"diagnostic\":\"not allowed\""),
                    json.replace("\"diagnostic\":null", "\"other\":null"),
                    json.replace("\"debuglinkCrc32\":4294967295", "\"debuglinkCrc32\":4294967296"),
                    json.replace("\"debuglinkCrc32\":4294967295", "\"debuglinkCrc32\":1.5"),
                    json.replace("test-host-v1", "x".repeat(16385)),
                    json.replace("/owned/source", "/owned/sidecar"),
                    json.replace("\"targetAfter\"", "\"targetBefore\""),
                    json.replace(AFTER, BEFORE),
                    json.replace("/owned/source", "/owned/\\u0000source"),
                    json.replace("/owned/source", "/owned/\\ud800source"),
                    json + "{}", "\ufeff" + json, json.substring(0, json.length() - 2))) {
                rejectIO(() -> read(malformed));
            }
            var wrong = new HashMap<>(prepared.files());
            wrong.put(mode == AttachmentReceipt.Mode.INITIAL ? "originalBackup" : "priorTargetBackup",
                artifact("wrong-backup", AFTER, "separate-inode"));
            rejectArgument(() -> new AttachmentReceipt(prepared.operationId(), mode, prepared.phase(),
                prepared.receiptPath(), prepared.backend(), prepared.hostContract(), prepared.durability(),
                prepared.debuglinkCrc32(), wrong, null));
        }
        AtomicBoolean closed = new AtomicBoolean();
        var input = new ByteArrayInputStream(fixture(AttachmentReceipt.Mode.INITIAL).toJson()
                .getBytes(StandardCharsets.UTF_8)) {
            @Override public void close() throws IOException {
                closed.set(true);
                super.close();
            }
        };
        try {
            AttachmentReceipt.read(input, () -> true);
            throw new AssertionError("receipt cancellation ignored");
        }
        catch (CancellationException expected) {
            equal(true, closed.get());
        }
        rejectIO(() -> AttachmentReceipt.read(new ByteArrayInputStream(new byte[] {(byte) 0xff}), () -> false));
    }

    private static void paths(Path root) throws Exception {
        List<AttachmentPaths.Selection> selected = new ArrayList<>();
        for (String role : List.of("target", "sidecar", "source", "report", "validation", "previousReceipt")) {
            Path file = Files.writeString(root.resolve(role), "original:" + role);
            selected.add(new AttachmentPaths.Selection(role, file,
                role.equals("target") ? AttachmentPaths.Kind.TARGET : AttachmentPaths.Kind.INPUT));
        }
        for (String role : List.of("backup", "receipt", "log")) {
            selected.add(new AttachmentPaths.Selection(role, root.resolve(role), AttachmentPaths.Kind.NEW_FILE));
        }
        var plan = AttachmentPaths.preflight(selected);
        plan.recheck();
        equal(9, plan.paths().size());
        for (int first = 0; first < selected.size(); first++) {
            for (int second = first + 1; second < selected.size(); second++) {
                var alias = new ArrayList<>(selected);
                var original = alias.get(first);
                var replaced = alias.get(second);
                alias.set(second, new AttachmentPaths.Selection(replaced.role(), original.path(), replaced.kind()));
                rejectIO(() -> AttachmentPaths.preflight(alias));
            }
        }
        Path hardlink = Files.createLink(root.resolve("hardlink"), root.resolve("target"));
        Path symlink = Files.createSymbolicLink(root.resolve("symlink"), root.resolve("target"));
        Path dangling = Files.createSymbolicLink(root.resolve("dangling"), root.resolve("absent"));
        for (Path alias : List.of(hardlink, symlink)) {
            var changed = new ArrayList<>(selected);
            changed.set(1, new AttachmentPaths.Selection("sidecar", alias, AttachmentPaths.Kind.INPUT));
            rejectIO(() -> AttachmentPaths.preflight(changed));
        }
        for (Path invalid : List.of(symlink, dangling, root)) {
            var changed = new ArrayList<>(selected);
            changed.set(0, new AttachmentPaths.Selection("target", invalid, AttachmentPaths.Kind.TARGET));
            rejectIO(() -> AttachmentPaths.preflight(changed));
        }
        rejectIO(() -> AttachmentPaths.preflight(List.of(
            new AttachmentPaths.Selection("backup", dangling, AttachmentPaths.Kind.NEW_FILE))));
        Path actual = Files.createDirectories(root.resolve("actual/child"));
        Path traversed = Files.writeString(actual.getParent().resolve("input"), "traversal sentinel");
        Files.createSymbolicLink(root.resolve("parent-link"), actual);
        rejectIO(() -> AttachmentPaths.preflight(List.of(
            new AttachmentPaths.Selection("input", traversed, AttachmentPaths.Kind.INPUT),
            new AttachmentPaths.Selection("alias", root.resolve("parent-link/../input"), AttachmentPaths.Kind.INPUT))));
        for (var selection : selected) {
            if (selection.kind() == AttachmentPaths.Kind.NEW_FILE) {
                equal(false, Files.exists(selection.path(), java.nio.file.LinkOption.NOFOLLOW_LINKS));
            }
            else {
                equal("original:" + selection.role(), Files.readString(selection.path()));
            }
        }
        Files.writeString(root.resolve("sidecar"), "concurrently changed sidecar");
        rejectIO(plan::recheck);
        var newPlan = AttachmentPaths.preflight(selected);
        Files.writeString(root.resolve("log"), "concurrent log sentinel");
        rejectIO(newPlan::recheck);
        equal("concurrent log sentinel", Files.readString(root.resolve("log")));
    }

    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void rejectIO(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("invalid input accepted"); }
        catch (IOException expected) { checks++; }
    }
    private static void rejectState(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("invalid transition accepted"); }
        catch (IllegalStateException expected) { checks++; }
    }
    private static void rejectArgument(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("invalid claim accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }
}
